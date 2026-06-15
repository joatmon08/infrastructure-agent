#!/bin/bash

# Script to check HCP Terraform run status
# Usage: ./scripts/check-run-status.sh <run-id> [interval-seconds]

RUN_ID="${1}"
INTERVAL="${2:-180}"  # Default to 3 minutes (180 seconds)
MAX_CHECKS="${3:-10}"  # Default to 10 checks before exiting

if [ -z "$RUN_ID" ]; then
    echo "Error: Run ID is required"
    echo "Usage: $0 <run-id> [interval-seconds]"
    exit 1
fi

# Get TFE_TOKEN from environment or credentials file
if [ -z "$TFE_TOKEN" ]; then
    CREDS_FILE="$HOME/.terraform.d/credentials.tfrc.json"
    if [ -f "$CREDS_FILE" ]; then
        TFE_TOKEN=$(jq -r '.credentials."app.terraform.io".token' "$CREDS_FILE")
        if [ "$TFE_TOKEN" = "null" ] || [ -z "$TFE_TOKEN" ]; then
            echo "Error: Could not read token from $CREDS_FILE"
            exit 1
        fi
    else
        echo "Error: TFE_TOKEN environment variable is not set and $CREDS_FILE not found"
        echo "Please set your Terraform Cloud API token:"
        echo "  export TFE_TOKEN=your-token-here"
        exit 1
    fi
fi

TFE_ADDRESS="${TFE_ADDRESS:-https://app.terraform.io}"

echo "Monitoring run: $RUN_ID"
echo "Checking every $INTERVAL seconds (max $MAX_CHECKS checks)"
echo "Press Ctrl+C to stop monitoring"
echo ""

check_run_status() {
    local response
    response=$(curl -s \
        --header "Authorization: Bearer $TFE_TOKEN" \
        --header "Content-Type: application/vnd.api+json" \
        "${TFE_ADDRESS}/api/v2/runs/${RUN_ID}")
    
    local status=$(echo "$response" | jq -r '.data.attributes.status')
    local message=$(echo "$response" | jq -r '.data.attributes.message')
    local has_changes=$(echo "$response" | jq -r '.data.attributes["has-changes"]')
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Status: $status"
    
    if [ "$message" != "null" ] && [ -n "$message" ]; then
        echo "  Message: $message"
    fi
    
    # Check if run is in a terminal state
    case "$status" in
        applied)
            echo ""
            echo "✓ Run completed successfully!"
            if [ "$has_changes" = "true" ]; then
                echo "  Changes were applied to infrastructure"
            else
                echo "  No changes were needed"
            fi
            return 0
            ;;
        errored)
            echo ""
            echo "✗ Run failed with errors"
            echo ""
            echo "Getting apply logs..."
            local apply_id=$(echo "$response" | jq -r '.data.relationships.apply.data.id')
            if [ "$apply_id" != "null" ]; then
                curl -s \
                    --header "Authorization: Bearer $TFE_TOKEN" \
                    "${TFE_ADDRESS}/api/v2/applies/${apply_id}/logs"
            fi
            return 1
            ;;
        canceled|discarded|force_canceled)
            echo ""
            echo "✗ Run was $status"
            return 1
            ;;
        planned)
            echo ""
            echo "✓ Plan completed - ready for apply"
            echo "Run needs manual approval in HCP Terraform UI"
            return 0
            ;;
        applying|apply_queued|plan_queued|planning|queuing|pending|cost_estimating|cost_estimated|policy_checking|policy_checked|policy_override|confirmed|post_plan_running|post_plan_completed)
            echo "  Current phase: $status"
            return 2
            ;;
        planned_and_finished)
            echo ""
            echo "✓ Plan completed (no apply needed)"
            return 0
            ;;
        *)
            echo "  Current phase: $status"
            return 2
            ;;
    esac
}

# Main monitoring loop
check_count=0
while true; do
    check_run_status
    exit_code=$?
    
    # Exit if terminal state (0 = success, 1 = failure)
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 1 ]; then
        exit $exit_code
    fi
    
    # Continue monitoring (exit_code = 2)
    check_count=$((check_count + 1))
    
    # Check if we've reached max checks
    if [ $check_count -ge $MAX_CHECKS ]; then
        echo ""
        echo "⚠ Maximum checks ($MAX_CHECKS) reached. Run may still be in progress."
        echo "Check HCP Terraform UI for current status: https://app.terraform.io"
        exit 2
    fi
    
    echo ""
    sleep "$INTERVAL"
done

# Made with Bob
