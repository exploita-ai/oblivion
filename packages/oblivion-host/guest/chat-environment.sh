#!/bin/sh
# Shared provider configuration for the server and its session-local clients.
# A revocable local capability is intentionally available to this session's
# tools. No infrastructure credential or arbitrary endpoint is supplied here.
OBLIVION_API_TOKEN=$(cat /run/oblivion-api/token)
OBLIVION_PROVIDER=$(cat /run/oblivion-api/provider)
export OBLIVION_API_TOKEN OBLIVION_PROVIDER
# Proxy-aware tools share only this opening's revocable capability. Programs
# that ignore these variables still have no direct route through the gateway.
. /usr/lib/oblivion/guest/tools-proxy.sh
case "$OBLIVION_PROVIDER" in
    abliteration-ai)
        ABLIT_KEY=$OBLIVION_API_TOKEN
        export ABLIT_KEY
        export OPENCODE_CONFIG_CONTENT='{"model":"abliteration-ai/abliterated-model","snapshots":false,"providers":{"abliteration-ai":{"settings":{"baseURL":"http://10.88.0.1:8111/v1"}}}}'
        ;;
    refuseless)
        REFUSELESS_API_KEY=$OBLIVION_API_TOKEN
        export REFUSELESS_API_KEY
        export OPENCODE_CONFIG_CONTENT='{"model":"refuseless/glm-5.3-abliterated","snapshots":false,"providers":{"refuseless":{"name":"Refuseless","env":["REFUSELESS_API_KEY"],"package":"@opencode/ai/providers/openai-compatible","settings":{"baseURL":"http://10.88.0.1:8111/v1","provider":"refuseless"},"models":{"glm-5.3-abliterated":{"name":"GLM 5.3 Abliterated","capabilities":{"tools":true,"reasoning":{"supported":true}},"limit":{"context":1048576,"output":131072}},"glm-5.3-flash-abliterated":{"name":"GLM 5.3 Flash Abliterated","capabilities":{"tools":true,"reasoning":{"supported":true}},"limit":{"context":1048576,"output":131072}},"deepseek-v4.1-flash-abliterated":{"name":"DeepSeek V4.1 Flash Abliterated","capabilities":{"tools":true,"reasoning":{"supported":true}},"limit":{"context":1048576,"output":130000}},"deepseek-v4.1-flash-fast":{"name":"DeepSeek V4.1 Flash 1017","capabilities":{"tools":true,"reasoning":{"supported":true}},"limit":{"context":1048576,"output":262144}},"minimax-m3.1-flash":{"name":"Minimax M3.1 Flash","capabilities":{"tools":true,"reasoning":{"supported":true}},"limit":{"context":1048576,"output":512000}},"deepseek-v4.1-flash-free":{"name":"DeepSeek V4.1 Flash Free","capabilities":{"tools":true,"reasoning":{"supported":true}},"limit":{"context":524288,"output":131072}}}}}}'
        ;;
    openrouter)
        OPENROUTER_API_KEY=$OBLIVION_API_TOKEN
        export OPENROUTER_API_KEY
        export OPENCODE_CONFIG_CONTENT='{"model":"openrouter/meta-llama/llama-3.3-70b-instruct","snapshots":false,"providers":{"openrouter":{"name":"OpenRouter · ZDR only","settings":{"baseURL":"http://10.88.0.1:8111/v1","provider":{"zdr":true,"data_collection":"deny","allow_fallbacks":false}}}}}'
        ;;
    *) exit 1 ;;
esac
OPENCODE_CONFIG_CONTENT=$(printf '%s' "$OPENCODE_CONFIG_CONTENT" | /usr/bin/python3 -c 'import json,sys; config=json.load(sys.stdin); config["instructions"]=["/usr/lib/oblivion/session-tools.md"]; print(json.dumps(config))')
export OPENCODE_CONFIG_CONTENT
