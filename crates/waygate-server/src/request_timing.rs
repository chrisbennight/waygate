//! HTTP timing around authentication, routing, and unbuffered response bodies.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{MatchedPath, Request};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Frame, SizeHint};
use waygate_telemetry::metrics::{record_http_request_phase, HttpRequestPhase};

struct Observation {
    route: String,
    method: String,
    status: Option<u16>,
    started: Instant,
    first_data: bool,
    finished: bool,
}

impl Observation {
    fn record(&self, phase: HttpRequestPhase) {
        record_http_request_phase(
            &self.route,
            &self.method,
            self.status,
            phase,
            self.started.elapsed().as_secs_f64(),
        );
    }

    fn finish(&mut self, phase: HttpRequestPhase) {
        if !self.finished {
            self.record(phase);
            self.finished = true;
        }
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        self.finish(HttpRequestPhase::Cancelled);
    }
}

pub async fn observe(request: Request, next: Next) -> Response {
    let mut observation = Observation {
        route: request
            .extensions()
            .get::<MatchedPath>()
            .map_or_else(|| "unmatched".to_owned(), |route| route.as_str().to_owned()),
        method: request.method().as_str().to_owned(),
        status: None,
        started: Instant::now(),
        first_data: false,
        finished: false,
    };
    let mut response = next.run(request).await;
    observation.status = Some(response.status().as_u16());
    observation.record(HttpRequestPhase::Headers);
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"text/html"))
    {
        let value = format!(
            "gateway;dur={:.3}",
            observation.started.elapsed().as_secs_f64() * 1000.0
        );
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().append("server-timing", value);
        }
    }
    let (parts, body) = response.into_parts();
    if body.is_end_stream() {
        observation.finish(HttpRequestPhase::Complete);
    }
    Response::from_parts(
        parts,
        Body::new(ObservedBody {
            inner: Box::pin(body),
            observation,
        }),
    )
}

struct ObservedBody {
    inner: Pin<Box<Body>>,
    observation: Observation,
}

impl HttpBody for ObservedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if !this.observation.first_data
                    && frame.data_ref().is_some_and(|data| !data.is_empty())
                {
                    this.observation.first_data = true;
                    this.observation.record(HttpRequestPhase::FirstData);
                }
                if this.inner.is_end_stream() {
                    this.observation.finish(HttpRequestPhase::Complete);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.observation.finish(HttpRequestPhase::Error);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.observation.finish(HttpRequestPhase::Complete);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use tower::ServiceExt;

    fn observation(route: &str) -> Observation {
        Observation {
            route: route.into(),
            method: "GET".into(),
            status: Some(200),
            started: Instant::now(),
            first_data: false,
            finished: false,
        }
    }

    #[tokio::test]
    async fn html_timing_uses_matched_routes_without_url_or_query_labels() {
        let app = axum::Router::new()
            .route(
                "/timing/{id}",
                get(|| async { axum::response::Html("hello") }),
            )
            .layer(axum::middleware::from_fn(observe));
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/timing/private-value?token=never-label")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.headers()["server-timing"]
            .to_str()
            .unwrap()
            .starts_with("gateway;dur="));
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
            "hello"
        );
        let metrics = waygate_telemetry::gather_text();
        assert!(metrics.contains("route=\"/timing/{id}\""));
        assert!(!metrics.contains("private-value"));
        assert!(!metrics.contains("never-label"));
    }

    struct Frames(std::collections::VecDeque<Frame<Bytes>>);
    impl HttpBody for Frames {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(Ok))
        }
        fn is_end_stream(&self) -> bool {
            self.0.is_empty()
        }
    }

    #[tokio::test]
    async fn observation_preserves_data_frames_and_trailers() {
        let trailers = axum::http::HeaderMap::from_iter([(
            header::HeaderName::from_static("x-check"),
            HeaderValue::from_static("present"),
        )]);
        let inner = Body::new(Frames(
            [
                Frame::data(Bytes::from_static(b"hello")),
                Frame::trailers(trailers),
            ]
            .into(),
        ));
        let mut body = ObservedBody {
            inner: Box::pin(inner),
            observation: observation("timing_trailers"),
        };
        let data = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data.data_ref().unwrap(), "hello");
        assert!(!body.observation.finished);
        let trailers = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(trailers.trailers_ref().unwrap()["x-check"], "present");
        assert!(body.observation.finished);
    }

    #[test]
    fn abandoning_an_unpolled_stream_records_cancellation() {
        let inner = Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>());
        drop(ObservedBody {
            inner: Box::pin(inner),
            observation: observation("timing_cancelled"),
        });
        assert!(waygate_telemetry::gather_text().lines().any(|line| line
            .starts_with("mcp_http_request_duration_seconds_count")
            && line.contains("route=\"timing_cancelled\"")
            && line.contains("phase=\"cancelled\"")));
    }
}
