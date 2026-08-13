#!/bin/bash

HELLOWORLD_SERVER_ENDPOINT=http://helloworld-server.default:9999
SUMMARIZER_ENDPOINT=http://summarizer-agent.summarizer:9999

curl -X POST "${MCPGATEWAY_URL}/a2a" \
  -H "Authorization: Bearer ${MCPGATEWAY_BEARER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent\": {
      \"name\": \"helloworld-server\",
      \"endpoint_url\": \"${HELLOWORLD_SERVER_ENDPOINT}\",
      \"agent_type\": \"generic\",
      \"description\": \"External AI agent for helloworld-server\",
      \"passthrough_headers\": [\"Authorization\", \"X-Tenant-Id\"],
      \"tags\": [\"ai\", \"helloworld-server\"]
    },
    \"visibility\": \"public\"
  }"

curl -X POST "${MCPGATEWAY_URL}/a2a" \
  -H "Authorization: Bearer ${MCPGATEWAY_BEARER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent\": {
      \"name\": \"summarizer\",
      \"endpoint_url\": \"${SUMMARIZER_ENDPOINT}\",
      \"agent_type\": \"generic\",
      \"description\": \"External AI agent for summarizer\",
      \"passthrough_headers\": [\"Authorization\", \"X-Tenant-Id\"],
      \"tags\": [\"ai\", \"summarizer\"]
    },
    \"visibility\": \"public\"
  }"
