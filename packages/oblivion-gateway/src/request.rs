use oblivion_transport::provider::Provider;
use serde_json::{Map, Value};

pub const ABLITERATION_MODELS: [&str; 3] = [
    "abliterated-model",
    "abliterated-model-large",
    "abliterated-model-large-v2",
];

pub const REFUSELESS_MODELS: [&str; 6] = [
    "glm-5.3-abliterated",
    "glm-5.3-flash-abliterated",
    "deepseek-v4.1-flash-abliterated",
    "deepseek-v4.1-flash-fast",
    "minimax-m3.1-flash",
    "deepseek-v4.1-flash-free",
];

// Closed request surface derived from OpenCode's openai-chat protocol. Serialize
// the validated value again: duplicate JSON keys cannot acquire different meaning
// in the provider's parser. Arbitrary provider settings are deliberately rejected.
pub fn validate(provider: Provider, bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let request = object(
        &value,
        &[
            "model",
            "messages",
            "tools",
            "tool_choice",
            "stream",
            "stream_options",
            "store",
            "prompt_cache_key",
            "reasoning_effort",
            "max_tokens",
            "max_completion_tokens",
            "temperature",
            "top_p",
            "frequency_penalty",
            "presence_penalty",
            "seed",
            "stop",
            "provider",
            "reasoning",
            "usage",
        ],
    )?;
    let model = string(required(request, "model")?)?;
    match provider {
        Provider::AbliterationAi => require(ABLITERATION_MODELS.contains(&model))?,
        Provider::Refuseless => require(REFUSELESS_MODELS.contains(&model))?,
        Provider::Openrouter => require(
            (1..=256).contains(&model.len())
                && model
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._:/~".contains(&byte)),
        )?,
    }
    require(request.get("stream") == Some(&Value::Bool(true)))?;
    let messages = required(request, "messages")?.as_array().ok_or(())?;
    require(!messages.is_empty() && messages.len() <= 4096)?;
    messages
        .iter()
        .try_for_each(|message| validate_message(provider, message))?;
    if let Some(tools) = request.get("tools") {
        let tools = tools.as_array().ok_or(())?;
        require(tools.len() <= 256)?;
        tools.iter().try_for_each(|tool| {
            let tool = function(tool)?;
            let function = object(tool, &["name", "description", "parameters", "strict"])?;
            name(required(function, "name")?)?;
            if let Some(description) = function.get("description") {
                string(description)?;
            }
            require(required(function, "parameters")?.is_object())?;
            local_schema(required(function, "parameters")?)?;
            optional_bool(function, "strict")
        })?;
    }
    if let Some(choice) = request.get("tool_choice") {
        if let Some(choice) = choice.as_str() {
            require(["auto", "none", "required"].contains(&choice))?;
        } else {
            let function = object(function(choice)?, &["name"])?;
            name(required(function, "name")?)?;
        }
    }
    if let Some(options) = request.get("stream_options") {
        let options = object(options, &["include_usage"])?;
        require(required(options, "include_usage")?.is_boolean())?;
    }
    if let Some(store) = request.get("store") {
        require(store == &Value::Bool(false))?;
    }
    if let Some(key) = request.get("prompt_cache_key") {
        require(string(key)?.len() <= 256)?;
    }
    if let Some(effort) = request.get("reasoning_effort") {
        require(
            ["none", "minimal", "low", "medium", "high", "xhigh", "max"].contains(&string(effort)?),
        )?;
    }
    for field in ["max_tokens", "max_completion_tokens"] {
        if let Some(value) = request.get(field) {
            require(value.as_u64().is_some_and(|n| (1..=131072).contains(&n)))?;
        }
    }
    for (field, minimum, maximum) in [
        ("temperature", 0.0, 2.0),
        ("top_p", 0.0, 1.0),
        ("frequency_penalty", -2.0, 2.0),
        ("presence_penalty", -2.0, 2.0),
    ] {
        if let Some(value) = request.get(field) {
            require(
                value
                    .as_f64()
                    .is_some_and(|n| (minimum..=maximum).contains(&n)),
            )?;
        }
    }
    if let Some(seed) = request.get("seed") {
        require(seed.as_i64().is_some())?;
    }
    if let Some(stop) = request.get("stop") {
        let stop = stop.as_array().ok_or(())?;
        require(stop.len() <= 16)?;
        stop.iter().try_for_each(|item| string(item).map(|_| ()))?;
    }
    if provider != Provider::Openrouter {
        require(
            request.get("provider").is_none()
                && request.get("reasoning").is_none()
                && request.get("usage").is_none(),
        )?;
    } else {
        if let Some(routing) = request.get("provider") {
            let routing = object(routing, &["zdr", "data_collection", "allow_fallbacks"])?;
            optional_bool(routing, "zdr")?;
            optional_bool(routing, "allow_fallbacks")?;
            if let Some(collection) = routing.get("data_collection") {
                require(collection == "deny")?;
            }
        }
        if let Some(reasoning) = request.get("reasoning") {
            let reasoning = object(reasoning, &["enabled", "exclude", "effort", "max_tokens"])?;
            optional_bool(reasoning, "enabled")?;
            optional_bool(reasoning, "exclude")?;
            if let Some(effort) = reasoning.get("effort") {
                require(
                    ["none", "minimal", "low", "medium", "high", "xhigh", "max"]
                        .contains(&string(effort)?),
                )?;
            }
            if let Some(tokens) = reasoning.get("max_tokens") {
                require(
                    tokens
                        .as_u64()
                        .is_some_and(|value| (1..=131072).contains(&value)),
                )?;
            }
        }
        if let Some(usage) = request.get("usage") {
            let usage = object(usage, &["include"])?;
            require(required(usage, "include")?.is_boolean())?;
        }
    }
    if provider == Provider::Openrouter {
        value.as_object_mut().ok_or(())?.insert(
            "provider".to_owned(),
            serde_json::json!({
                "zdr": true,
                "data_collection": "deny",
                "allow_fallbacks": false,
            }),
        );
    }
    serde_json::to_vec(&value).map_err(|_| ())
}

fn validate_message(provider: Provider, value: &Value) -> Result<(), ()> {
    let fields = value.as_object().ok_or(())?;
    let role = string(required(fields, "role")?)?;
    let allowed: &[&str] = match role {
        "system" | "user" => &["role", "content"],
        "assistant" => &[
            "role",
            "content",
            "tool_calls",
            "reasoning_content",
            "reasoning",
            "reasoning_text",
            "reasoning_details",
        ],
        "tool" => &["role", "content", "tool_call_id"],
        _ => return Err(()),
    };
    let fields = object(value, allowed)?;
    content(provider, required(fields, "content")?, role)?;
    if role == "tool" {
        require(!string(required(fields, "tool_call_id")?)?.is_empty())?;
    }
    if let Some(calls) = fields.get("tool_calls") {
        let calls = calls.as_array().ok_or(())?;
        require(calls.len() <= 256)?;
        calls.iter().try_for_each(|call| {
            let allowed = if provider == Provider::Openrouter {
                &["id", "type", "function", "extra_content"][..]
            } else {
                &["id", "type", "function"][..]
            };
            let call = object(call, allowed)?;
            require(!string(required(call, "id")?)?.is_empty())?;
            require(required(call, "type")? == "function")?;
            let function = object(required(call, "function")?, &["name", "arguments"])?;
            name(required(function, "name")?)?;
            string(required(function, "arguments")?)?;
            if let Some(extra) = call.get("extra_content") {
                let extra = object(extra, &["google"])?;
                let google = object(required(extra, "google")?, &["thought_signature"])?;
                string(required(google, "thought_signature")?)?;
            }
            Ok(())
        })?;
    }
    for key in ["reasoning_content", "reasoning", "reasoning_text"] {
        if let Some(value) = fields.get(key) {
            string(value)?;
        }
    }
    if let Some(details) = fields.get("reasoning_details") {
        require(provider == Provider::Openrouter)?;
        reasoning_details(details)?;
    }
    Ok(())
}

fn content(provider: Provider, value: &Value, role: &str) -> Result<(), ()> {
    if value.is_string() || (role == "assistant" && value.is_null()) {
        return Ok(());
    }
    let parts = value.as_array().ok_or(())?;
    require(parts.len() <= 1024)?;
    parts.iter().try_for_each(|part| {
        let fields = part.as_object().ok_or(())?;
        match string(required(fields, "type")?)? {
            "text" => {
                let allowed = if provider == Provider::Openrouter {
                    &["type", "text", "cache_control"][..]
                } else {
                    &["type", "text"][..]
                };
                let fields = object(part, allowed)?;
                string(required(fields, "text")?)?;
                if let Some(cache) = fields.get("cache_control") {
                    let cache = object(cache, &["type", "ttl"])?;
                    require(required(cache, "type")? == "ephemeral")?;
                    if let Some(ttl) = cache.get("ttl") {
                        require(ttl == "1h")?;
                    }
                }
                Ok(())
            }
            "image_url" if role == "user" || role == "system" => {
                let fields = object(part, &["type", "image_url"])?;
                let image = object(required(fields, "image_url")?, &["url"])?;
                inline_data(
                    required(image, "url")?,
                    &["image/png", "image/jpeg", "image/webp", "image/gif"],
                )
            }
            "file" if role == "user" || role == "system" => {
                let fields = object(part, &["type", "file"])?;
                let file = object(required(fields, "file")?, &["filename", "file_data"])?;
                require(string(required(file, "filename")?)?.len() <= 255)?;
                inline_data(required(file, "file_data")?, &["application/pdf"])
            }
            _ => Err(()),
        }
    })
}

fn reasoning_details(value: &Value) -> Result<(), ()> {
    let details = value.as_array().ok_or(())?;
    require(details.len() <= 128)?;
    details.iter().try_for_each(|detail| {
        let fields = detail.as_object().ok_or(())?;
        require(fields.len() <= 32)?;
        match string(required(fields, "type")?)? {
            "reasoning.text" => optional_string(fields, "text")?,
            "reasoning.summary" => optional_string(fields, "summary")?,
            "reasoning.encrypted" => string(required(fields, "data")?).map(|_| ())?,
            "summary" => string(required(fields, "summary")?).map(|_| ())?,
            "encrypted" => string(required(fields, "encrypted")?).map(|_| ())?,
            _ => return Err(()),
        }
        optional_string(fields, "format")?;
        optional_string_or_null(fields, "id")?;
        optional_string_or_null(fields, "signature")?;
        if let Some(index) = fields.get("index") {
            require(index.as_u64().is_some_and(|index| index <= 4096))?;
        }
        Ok(())
    })
}

fn inline_data(value: &Value, media: &[&str]) -> Result<(), ()> {
    let (header, data) = string(value)?.split_once(',').ok_or(())?;
    let mime = header
        .strip_prefix("data:")
        .and_then(|h| h.strip_suffix(";base64"))
        .ok_or(())?;
    require(media.contains(&mime) && !data.is_empty())?;
    require(
        data.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)),
    )
}

fn local_schema(value: &Value) -> Result<(), ()> {
    match value {
        Value::Object(fields) => fields.iter().try_for_each(|(key, value)| {
            if ["$ref", "$dynamicRef", "$recursiveRef"].contains(&key.as_str()) {
                require(string(value)?.starts_with('#'))?;
            }
            local_schema(value)
        }),
        Value::Array(values) => values.iter().try_for_each(local_schema),
        _ => Ok(()),
    }
}

fn function(value: &Value) -> Result<&Value, ()> {
    let fields = object(value, &["type", "function"])?;
    require(required(fields, "type")? == "function")?;
    required(fields, "function")
}

fn name(value: &Value) -> Result<(), ()> {
    let name = string(value)?;
    require(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
    )
}

fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>, ()> {
    let fields = value.as_object().ok_or(())?;
    require(fields.keys().all(|key| allowed.contains(&key.as_str())))?;
    Ok(fields)
}

fn required<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ()> {
    fields.get(key).ok_or(())
}

fn string(value: &Value) -> Result<&str, ()> {
    value.as_str().ok_or(())
}

fn optional_bool(fields: &Map<String, Value>, key: &str) -> Result<(), ()> {
    require(fields.get(key).is_none_or(Value::is_boolean))
}

fn optional_string(fields: &Map<String, Value>, key: &str) -> Result<(), ()> {
    require(fields.get(key).is_none_or(Value::is_string))
}

fn optional_string_or_null(fields: &Map<String, Value>, key: &str) -> Result<(), ()> {
    require(
        fields
            .get(key)
            .is_none_or(|value| value.is_string() || value.is_null()),
    )
}

fn require(valid: bool) -> Result<(), ()> {
    valid.then_some(()).ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chat(model: &str) -> Value {
        json!({
            "model": model,
            "messages": [{"role": "user", "content": "private prompt"}],
            "stream": true,
            "stream_options": {"include_usage": true}
        })
    }

    #[test]
    fn each_fixed_provider_accepts_only_its_own_catalog() {
        assert!(
            validate(
                Provider::AbliterationAi,
                &serde_json::to_vec(&chat(ABLITERATION_MODELS[0])).unwrap()
            )
            .is_ok()
        );
        assert!(
            validate(
                Provider::Refuseless,
                &serde_json::to_vec(&chat(REFUSELESS_MODELS[0])).unwrap()
            )
            .is_ok()
        );
        assert!(
            validate(
                Provider::AbliterationAi,
                &serde_json::to_vec(&chat(REFUSELESS_MODELS[0])).unwrap()
            )
            .is_err()
        );
        assert!(
            validate(
                Provider::Refuseless,
                &serde_json::to_vec(&chat(ABLITERATION_MODELS[0])).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn openrouter_always_emits_strict_zero_retention_routing() {
        let mut body = chat("~anthropic/claude-sonnet-latest");
        body["provider"] = json!({
            "zdr": false,
            "data_collection": "deny",
            "allow_fallbacks": true
        });
        let output: Value = serde_json::from_slice(
            &validate(Provider::Openrouter, &serde_json::to_vec(&body).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            output["provider"],
            json!({
                "zdr": true,
                "data_collection": "deny",
                "allow_fallbacks": false
            })
        );
    }

    #[test]
    fn openrouter_rejects_routing_that_can_expand_provider_access() {
        for routing in [
            json!({"data_collection": "allow"}),
            json!({"only": ["provider-with-unknown-policy"]}),
            json!({"sort": "price"}),
        ] {
            let mut body = chat("openai/gpt-5");
            body["provider"] = routing;
            assert!(validate(Provider::Openrouter, &serde_json::to_vec(&body).unwrap()).is_err());
        }
    }

    #[test]
    fn openrouter_accepts_native_cache_and_reasoning_replay_only_for_its_adapter() {
        let mut body = chat("anthropic/claude-sonnet-4.6");
        body["messages"] = json!([
            {
                "role": "system",
                "content": [{
                    "type": "text",
                    "text": "Use the tool once.",
                    "cache_control": {"type": "ephemeral", "ttl": "1h"}
                }]
            },
            {
                "role": "assistant",
                "content": null,
                "reasoning": "Checking the private value.",
                "reasoning_details": [{
                    "type": "reasoning.text",
                    "text": "Checking the private value.",
                    "format": "anthropic-claude-v1",
                    "index": 0,
                    "signature": "synthetic-signature"
                }],
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{}"},
                    "extra_content": {"google": {"thought_signature": "synthetic-thought-signature"}}
                }]
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "private result"}
        ]);
        let bytes = serde_json::to_vec(&body).unwrap();
        assert!(validate(Provider::Openrouter, &bytes).is_ok());

        body["model"] = json!(ABLITERATION_MODELS[0]);
        assert!(
            validate(
                Provider::AbliterationAi,
                &serde_json::to_vec(&body).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn non_openrouter_providers_cannot_smuggle_routing_fields() {
        let mut body = chat(ABLITERATION_MODELS[0]);
        body["provider"] = json!({"zdr": true});
        assert!(
            validate(
                Provider::AbliterationAi,
                &serde_json::to_vec(&body).unwrap()
            )
            .is_err()
        );
    }
}
