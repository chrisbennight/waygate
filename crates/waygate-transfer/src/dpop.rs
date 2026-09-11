//! RFC 9449 proof verification isolated from semantic transfer authority.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::jwk::{AlgorithmParameters, ThumbprintHash};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use time::{Duration, OffsetDateTime};
use url::Url;

const MAX_JTI_BYTES: usize = 200;

#[derive(Debug, Clone, Deserialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UnclaimedDpopProof {
    pub jkt: String,
    pub jti: String,
    pub replay_expires_at: OffsetDateTime,
}

impl UnclaimedDpopProof {
    pub(crate) fn claimed(self) -> VerifiedDpopProof {
        VerifiedDpopProof {
            jkt: self.jkt,
            jti: self.jti,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedDpopProof {
    pub jkt: String,
    pub jti: String,
}

#[derive(Debug, Clone)]
pub struct DpopVerifier {
    max_age: Duration,
    future_skew: Duration,
}

impl DpopVerifier {
    pub fn new(max_age: Duration, future_skew: Duration) -> Result<Self, DpopError> {
        if max_age <= Duration::ZERO || future_skew < Duration::ZERO {
            return Err(DpopError::Configuration);
        }
        Ok(Self {
            max_age,
            future_skew,
        })
    }

    pub fn verify(
        &self,
        proof_jwt: &str,
        request_method: &str,
        request_uri: &str,
        access_token: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<UnclaimedDpopProof, DpopError> {
        let header = decode_header(proof_jwt).map_err(|_| DpopError::Malformed)?;
        if header.typ.as_deref() != Some("dpop+jwt") || !asymmetric_algorithm(header.alg) {
            return Err(DpopError::Header);
        }
        if header.jku.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.crit.is_some()
        {
            return Err(DpopError::Header);
        }
        let jwk = header.jwk.ok_or(DpopError::Header)?;
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            return Err(DpopError::Header);
        }
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| DpopError::Header)?;
        let mut validation = Validation::new(header.alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let claims = decode::<DpopClaims>(proof_jwt, &key, &validation)
            .map_err(|_| DpopError::Signature)?
            .claims;

        if claims.jti.is_empty() || claims.jti.len() > MAX_JTI_BYTES {
            return Err(DpopError::Claims);
        }
        if !claims.htm.eq_ignore_ascii_case(request_method) {
            return Err(DpopError::RequestBinding);
        }
        if canonical_htu(&claims.htu)? != canonical_htu(request_uri)? {
            return Err(DpopError::RequestBinding);
        }
        let issued_at =
            OffsetDateTime::from_unix_timestamp(claims.iat).map_err(|_| DpopError::Claims)?;
        if issued_at > now + self.future_skew || issued_at < now - self.max_age {
            return Err(DpopError::Stale);
        }
        match access_token {
            Some(token) => {
                let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
                let actual = claims.ath.ok_or(DpopError::AccessTokenBinding)?;
                if expected.as_bytes().ct_eq(actual.as_bytes()).unwrap_u8() != 1 {
                    return Err(DpopError::AccessTokenBinding);
                }
            }
            None if claims.ath.is_some() => return Err(DpopError::AccessTokenBinding),
            None => {}
        }

        Ok(UnclaimedDpopProof {
            jkt: jwk.thumbprint(ThumbprintHash::SHA256),
            jti: claims.jti,
            replay_expires_at: issued_at + self.max_age + self.future_skew,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DpopError {
    #[error("invalid verifier configuration")]
    Configuration,
    #[error("malformed proof JWT")]
    Malformed,
    #[error("unsupported or unsafe proof header")]
    Header,
    #[error("proof signature is invalid")]
    Signature,
    #[error("required proof claim is invalid")]
    Claims,
    #[error("proof does not match the HTTP request")]
    RequestBinding,
    #[error("proof is outside the accepted time window")]
    Stale,
    #[error("proof does not match the transfer credential")]
    AccessTokenBinding,
    #[error("proof was already used")]
    Replay,
}

fn asymmetric_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::EdDSA
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
    )
}

fn canonical_htu(value: &str) -> Result<String, DpopError> {
    let mut url = Url::parse(value).map_err(|_| DpopError::RequestBinding)?;
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback(&url)) {
        return Err(DpopError::RequestBinding);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DpopError::RequestBinding);
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn is_loopback(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    )
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, KeyAlgorithm,
        OctetKeyPairParameters, OctetKeyPairType,
    };
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    struct Claims<'a> {
        jti: &'a str,
        htm: &'a str,
        htu: &'a str,
        iat: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        ath: Option<String>,
    }

    fn key_pair() -> (Jwk, EncodingKey) {
        let signing = SigningKey::from_bytes(&[31_u8; 32]);
        let pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap();
        let encoding = EncodingKey::from_ed_pem(pem.as_bytes()).unwrap();
        let jwk = Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
            }),
        };
        (jwk, encoding)
    }

    fn proof(uri: &str, token: Option<&str>, now: OffsetDateTime) -> String {
        let (jwk, encoding) = key_pair();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(jwk);
        let claims = Claims {
            jti: "proof-1",
            htm: "POST",
            htu: uri,
            iat: now.unix_timestamp(),
            ath: token.map(|value| URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))),
        };
        encode(&header, &claims, &encoding).unwrap()
    }

    #[test]
    fn verifies_request_and_access_token_binding() {
        let now = OffsetDateTime::now_utc();
        let uri = "https://gateway.example/files/transfer";
        let verifier = DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).unwrap();
        let token = "ftc_example";
        let verified = verifier
            .verify(&proof(uri, Some(token), now), "POST", uri, Some(token), now)
            .unwrap();
        assert_eq!(
            verified.jkt,
            key_pair().0.thumbprint(ThumbprintHash::SHA256)
        );
    }

    #[test]
    fn refuses_wrong_target_and_wrong_token() {
        let now = OffsetDateTime::now_utc();
        let uri = "https://gateway.example/files/transfer";
        let verifier = DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).unwrap();
        let jwt = proof(uri, Some("right"), now);
        assert!(matches!(
            verifier.verify(
                &jwt,
                "POST",
                "https://gateway.example/files/other",
                Some("right"),
                now
            ),
            Err(DpopError::RequestBinding)
        ));
        assert!(matches!(
            verifier.verify(&jwt, "POST", uri, Some("wrong"), now),
            Err(DpopError::AccessTokenBinding)
        ));
    }
}
