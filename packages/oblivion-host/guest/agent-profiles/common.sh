# Sourced after the Safe's HOME and XDG paths have been selected.
export DO_NOT_TRACK=1
export OTEL_SDK_DISABLED=true
export OTEL_TRACES_EXPORTER=none
export OTEL_METRICS_EXPORTER=none
export OTEL_LOGS_EXPORTER=none
unset OTEL_EXPORTER_OTLP_ENDPOINT OTEL_EXPORTER_OTLP_HEADERS
unset OTEL_EXPORTER_OTLP_TRACES_ENDPOINT OTEL_EXPORTER_OTLP_TRACES_HEADERS
unset OTEL_EXPORTER_OTLP_METRICS_ENDPOINT OTEL_EXPORTER_OTLP_METRICS_HEADERS
unset OTEL_EXPORTER_OTLP_LOGS_ENDPOINT OTEL_EXPORTER_OTLP_LOGS_HEADERS
unset BETA_TRACING_ENDPOINT

# The first two clients can be launched simultaneously in one new Safe.
# Link complete defaults atomically, leaving an existing user config intact.
initialize_agent_config() {
    if [ -e "$2" ] || [ -L "$2" ]; then return; fi
    mkdir -p "$(dirname "$2")"
    profile_temp=$(mktemp "$(dirname "$2")/.oblivion-default.XXXXXX")
    cat "$1" > "$profile_temp"
    chmod 0600 "$profile_temp"
    if ! ln "$profile_temp" "$2" 2>/dev/null; then
        if [ ! -e "$2" ] && [ ! -L "$2" ]; then
            rm -f "$profile_temp"
            return 1
        fi
    fi
    rm -f "$profile_temp"
    unset profile_temp
}
