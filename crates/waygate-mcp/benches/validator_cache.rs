use std::hint::black_box;
use std::time::Instant;

use serde_json::json;

fn percentile(mut samples: Vec<u128>, percentile: usize) -> u128 {
    samples.sort_unstable();
    let index = (samples.len() - 1) * percentile / 100;
    samples[index]
}

fn main() {
    const ITERATIONS: usize = 10_000;
    let schema = json!({
        "type": "object",
        "properties": {
            "ok": {"type": "boolean"},
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "score": {"type": "number", "minimum": 0, "maximum": 1},
                        "tags": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["id", "score"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["ok", "items"],
        "additionalProperties": false
    });
    let value = json!({
        "ok": true,
        "items": [
            {"id": "alpha", "score": 0.75, "tags": ["one", "two"]},
            {"id": "beta", "score": 0.25, "tags": []}
        ]
    });

    let cached = jsonschema::validator_for(&schema).expect("representative schema must compile");
    let mut compile_each = Vec::with_capacity(ITERATIONS);
    let mut cached_validate = Vec::with_capacity(ITERATIONS);
    let mut digest_and_cached_validate = Vec::with_capacity(ITERATIONS);

    for _ in 0..ITERATIONS {
        let started = Instant::now();
        let validator = jsonschema::validator_for(black_box(&schema)).unwrap();
        black_box(validator.validate(black_box(&value))).unwrap();
        compile_each.push(started.elapsed().as_nanos());

        let started = Instant::now();
        black_box(cached.validate(black_box(&value))).unwrap();
        cached_validate.push(started.elapsed().as_nanos());

        let started = Instant::now();
        black_box(waygate_catalog::validator_schema_hash(black_box(&schema)));
        black_box(cached.validate(black_box(&value))).unwrap();
        digest_and_cached_validate.push(started.elapsed().as_nanos());
    }

    println!("iterations={ITERATIONS}");
    println!(
        "compile_each_median_ns={}",
        percentile(compile_each.clone(), 50)
    );
    println!("compile_each_p95_ns={}", percentile(compile_each, 95));
    println!(
        "cached_validate_median_ns={}",
        percentile(cached_validate.clone(), 50)
    );
    println!("cached_validate_p95_ns={}", percentile(cached_validate, 95));
    println!(
        "digest_and_cached_validate_median_ns={}",
        percentile(digest_and_cached_validate.clone(), 50)
    );
    println!(
        "digest_and_cached_validate_p95_ns={}",
        percentile(digest_and_cached_validate, 95)
    );
}
