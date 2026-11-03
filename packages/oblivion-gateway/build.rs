use serde_json::Value;
use std::{env, fs, path::PathBuf};

fn main() {
    // The client embeds this same catalog. Keep only limits for admitted
    // providers in the gateway binary; no catalog requests happen at runtime.
    let source = "../core/src/models-dev/snapshot.txt";
    println!("cargo:rerun-if-changed={source}");
    let catalog: Value = serde_json::from_str(&fs::read_to_string(source).expect("model catalog"))
        .expect("valid model catalog");
    let mut rows = String::from("const MODEL_LIMITS: &[(&str, &str, u64, u64)] = &[\n");
    for provider in ["abliteration-ai", "refuseless", "openrouter"] {
        let models = catalog[provider]["models"]
            .as_object()
            .expect("supported provider model catalog");
        assert!(!models.is_empty(), "empty catalog for {provider}");
        for model in models.values() {
            let id = model["id"].as_str().expect("model ID");
            let context = model["limit"]["context"].as_u64().expect("context limit");
            let output = model["limit"]["output"].as_u64().expect("output limit");
            assert!(
                context > 0 && output > 0,
                "unknown limits for {provider}/{id}"
            );
            rows.push_str(&format!("({provider:?}, {id:?}, {context}, {output}),\n"));
        }
    }
    rows.push_str("];");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"))
            .join("model-limits.rs"),
        rows,
    )
    .expect("write model limits");
}
