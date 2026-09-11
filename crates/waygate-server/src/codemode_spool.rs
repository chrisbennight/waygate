//! Execution-private transport for completed connector results too large for
//! the parent/runner control frame.

use crate::codemode_limits::limits;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use serde_json::Value;

#[derive(Debug)]
pub(crate) enum WriteValueError {
    TooLarge,
    Failed(anyhow::Error),
}

pub(crate) fn write_value(file: &mut File, value: &Value) -> Result<u64, WriteValueError> {
    file.set_len(0)
        .map_err(|error| WriteValueError::Failed(error.into()))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| WriteValueError::Failed(error.into()))?;
    write_bounded(file, value, limits().connector_response_bytes)
}

/// Check serialized size without allocating a second response buffer.
pub(crate) fn check_value(value: &Value, limit: usize) -> Result<(), WriteValueError> {
    write_bounded(io::sink(), value, limit).map(|_| ())
}

fn write_bounded(writer: impl Write, value: &Value, limit: usize) -> Result<u64, WriteValueError> {
    let mut writer = BoundedWriter {
        inner: writer,
        written: 0,
        limit,
        exceeded: false,
    };
    let encoded = serde_json::to_writer(&mut writer, value);
    if writer.exceeded {
        return Err(WriteValueError::TooLarge);
    }
    encoded.map_err(|error| WriteValueError::Failed(error.into()))?;
    writer
        .flush()
        .map_err(|error| WriteValueError::Failed(error.into()))?;
    u64::try_from(writer.written).map_err(|error| WriteValueError::Failed(error.into()))
}

pub(crate) fn read_value(file: &mut File, bytes: u64) -> anyhow::Result<Value> {
    let bytes = usize::try_from(bytes)?;
    anyhow::ensure!(
        bytes <= limits().connector_response_bytes,
        "spooled connector result exceeds its materialization limit"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut encoded = vec![0; bytes];
    file.read_exact(&mut encoded)?;
    Ok(serde_json::from_slice(&encoded)?)
}

struct BoundedWriter<W> {
    inner: W,
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("connector result size overflow"));
        };
        if next > self.limit {
            self.exceeded = true;
            return Err(io::Error::other(
                "connector result exceeds its materialization limit",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.written += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_round_trips_a_completed_json_value() {
        let mut file = tempfile::tempfile().expect("temporary spool");
        let value = serde_json::json!({"data": "failure\n".repeat(200_000)});

        let bytes = write_value(&mut file, &value).expect("write value");

        assert_eq!(read_value(&mut file, bytes).expect("read value"), value);
    }

    #[test]
    fn spool_refuses_values_beyond_the_runner_derived_budget() {
        let mut file = tempfile::tempfile().expect("temporary spool");
        let value = Value::String("x".repeat(limits().connector_response_bytes));

        assert!(matches!(
            write_value(&mut file, &value),
            Err(WriteValueError::TooLarge)
        ));
    }
}
