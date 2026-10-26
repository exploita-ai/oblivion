use serde_json::{Map, Value};

pub const MODELS: [&str; 3] = [
    "abliterated-model",
    "abliterated-model-large",
    "abliterated-model-large-v2",
];

// Closed request surface derived from OpenCode's openai-chat protocol. Serialize
// the validated value again: duplicate JSON keys cannot acquire different meaning
// in the provider's parser. Arbitrary provider settings are deliberately rejected.
pub fn validate(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
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
        ],
    )?;
    require(MODELS.contains(&string(required(request, "model")?)?))?;
    require(request.get("stream") == Some(&Value::Bool(true)))?;
    let messages = required(request, "messages")?.as_array().ok_or(())?;
    require(!messages.is_empty() && messages.len() <= 4096)?;
    messages.iter().try_for_each(message)?;
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
    serde_json::to_vec(&value).map_err(|_| ())
}

fn message(value: &Value) -> Result<(), ()> {
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
        ],
        "tool" => &["role", "content", "tool_call_id"],
        _ => return Err(()),
    };
    let fields = object(value, allowed)?;
    content(required(fields, "content")?, role)?;
    if role == "tool" {
        require(!string(required(fields, "tool_call_id")?)?.is_empty())?;
    }
    if let Some(calls) = fields.get("tool_calls") {
        let calls = calls.as_array().ok_or(())?;
        require(calls.len() <= 256)?;
        calls.iter().try_for_each(|call| {
            let call = object(call, &["id", "type", "function"])?;
            require(!string(required(call, "id")?)?.is_empty())?;
            require(required(call, "type")? == "function")?;
            let function = object(required(call, "function")?, &["name", "arguments"])?;
            name(required(function, "name")?)?;
            string(required(function, "arguments")?).map(|_| ())
        })?;
    }
    for key in ["reasoning_content", "reasoning", "reasoning_text"] {
        if let Some(value) = fields.get(key) {
            string(value)?;
        }
    }
    Ok(())
}

fn content(value: &Value, role: &str) -> Result<(), ()> {
    if value.is_string() || (role == "assistant" && value.is_null()) {
        return Ok(());
    }
    let parts = value.as_array().ok_or(())?;
    require(parts.len() <= 1024)?;
    parts.iter().try_for_each(|part| {
        let fields = part.as_object().ok_or(())?;
        match string(required(fields, "type")?)? {
            "text" => {
                let fields = object(part, &["type", "text"])?;
                string(required(fields, "text")?).map(|_| ())
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

fn require(valid: bool) -> Result<(), ()> {
    valid.then_some(()).ok_or(())
}
