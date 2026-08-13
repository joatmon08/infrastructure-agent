#!/bin/bash

HELLOWORLD_SERVER_ENDPOINT=$(cd terraform/helloworld && terraform output -raw helloworld_agent_server_url)
TEST_CLIENT_ENDPOINT=$(cd terraform/helloworld && terraform output -raw test_client_url)
SUMMARIZER_ENDPOINT=$(cd terraform/summarizer && terraform output -raw summarizer_agent_url)

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
      \"name\": \"test-client\",
      \"endpoint_url\": \"${TEST_CLIENT_ENDPOINT}\",
      \"agent_type\": \"generic\",
      \"description\": \"External AI agent for test-client\",
      \"passthrough_headers\": [\"Authorization\", \"X-Tenant-Id\"],
      \"tags\": [\"ai\", \"test-client\"]
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
