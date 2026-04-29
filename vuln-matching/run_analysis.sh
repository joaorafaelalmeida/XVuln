#!/bin/bash
# ============================================================
# run_analysis.sh
# Analyses security reports with LLaMA via Ollama
# Processes findings one at a time
# Separates output by STRIDE category into individual files
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABUSE_CASES="$SCRIPT_DIR/abuse_cases.txt"
PROMPT_TEMPLATE="$SCRIPT_DIR/prompt_template.txt"
PROMPT_UNMATCHED="$SCRIPT_DIR/prompt_unmatched.txt"
FILTERED_DIR="$SCRIPT_DIR/reports/filtered"
OUTPUT_FILE="$SCRIPT_DIR/analysis_output.md"
STRIDE_DIR="$SCRIPT_DIR/stride_output"
MODEL="llama3.1"
OLLAMA_URL="http://localhost:11434/api/generate"
BATCH_SIZE=1   # number of findings per LLaMA call

# STRIDE files
SPOOFING_FILE="$STRIDE_DIR/spoofing.md"
TAMPERING_FILE="$STRIDE_DIR/tampering.md"
REPUDIATION_FILE="$STRIDE_DIR/repudiation.md"
INFO_DISCLOSURE_FILE="$STRIDE_DIR/information_disclosure.md"
DOS_FILE="$STRIDE_DIR/denial_of_service.md"
EOP_FILE="$STRIDE_DIR/elevation_of_privilege.md"
UNMATCHED_FILE="$STRIDE_DIR/unmatched.md"

# ─────────────────────────────────────────────
# Initial checks
# ─────────────────────────────────────────────
echo ""
echo "🔍 Checking dependencies..."

if ! command -v ollama &>/dev/null; then
    echo "❌ Ollama not found. Install with: brew install ollama"
    exit 1
fi

if ! curl -s "$OLLAMA_URL" &>/dev/null; then
    echo "❌ Ollama is not running. Open another terminal and run: ollama serve"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "❌ jq not found. Install with: brew install jq"
    exit 1
fi

if [ ! -f "$ABUSE_CASES" ]; then
    echo "❌ File not found: $ABUSE_CASES"
    exit 1
fi

if [ ! -f "$PROMPT_TEMPLATE" ]; then
    echo "❌ File not found: $PROMPT_TEMPLATE"
    exit 1
fi

if [ ! -f "$PROMPT_UNMATCHED" ]; then
    echo "❌ File not found: $PROMPT_UNMATCHED"
    exit 1
fi

if [ ! -d "$FILTERED_DIR" ]; then
    echo "❌ Filtered reports directory not found: $FILTERED_DIR"
    echo "   Run first: python3 filter_reports.py"
    exit 1
fi

# ─────────────────────────────────────────────
# Initialise output
# ─────────────────────────────────────────────
ABUSE_CASES_CONTENT=$(cat "$ABUSE_CASES")
TEMPLATE=$(cat "$PROMPT_TEMPLATE")
TEMPLATE_UNMATCHED=$(cat "$PROMPT_UNMATCHED")

: > "$OUTPUT_FILE"

# Create the stride_output directory and initialise files
mkdir -p "$STRIDE_DIR"
for FILE in "$SPOOFING_FILE" "$TAMPERING_FILE" "$REPUDIATION_FILE" \
            "$INFO_DISCLOSURE_FILE" "$DOS_FILE" "$EOP_FILE" "$UNMATCHED_FILE"; do
    : > "$FILE"
done

echo "✅ All ready. Starting analysis with batches of $BATCH_SIZE findings..."
echo ""

# ─────────────────────────────────────────────
# Function: classify and distribute result blocks
# into the corresponding STRIDE files
# Arguments: $1=full_result
# ─────────────────────────────────────────────
distribute_to_stride() {
    local RESULT="$1"

    python3 - "$RESULT" "$SPOOFING_FILE" "$TAMPERING_FILE" "$REPUDIATION_FILE" \
        "$INFO_DISCLOSURE_FILE" "$DOS_FILE" "$EOP_FILE" "$UNMATCHED_FILE" << 'PYEOF'
import sys, re

result       = sys.argv[1]
spoofing     = sys.argv[2]
tampering    = sys.argv[3]
repudiation  = sys.argv[4]
info_disc    = sys.argv[5]
dos          = sys.argv[6]
eop          = sys.argv[7]
unmatched    = sys.argv[8]

# Mapping: keyword in header → destination file
STRIDE_MAP = {
    "spoofing":                 spoofing,
    "tampering":                tampering,
    "repudiation":              repudiation,
    "information disclosure":   info_disc,
    "denial of service":        dos,
    "elevation of privilege":   eop,
    "unmatched":                unmatched,
}

# Split the result into blocks separated by "---"
blocks = re.split(r'\n---\n', result.strip())

for block in blocks:
    block = block.strip()
    if not block:
        continue

    # Ensure the separator is present before the block
    block_with_sep = "\n" + block + "\n"

    # Find the first ### line to determine the category
    header_match = re.search(r'###\s+(.+)', block)
    if not header_match:
        continue

    header = header_match.group(1).lower()

    matched = False
    for keyword, filepath in STRIDE_MAP.items():
        if keyword in header:
            with open(filepath, "a") as f:
                f.write(block_with_sep)
            matched = True
            break

    # If no known category was found, go to unmatched
    if not matched:
        with open(unmatched, "a") as f:
            f.write(block_with_sep)

PYEOF
}

# ─────────────────────────────────────────────
# Function: call Ollama with a given prompt and batch JSON
# Returns the raw result string via stdout
# Arguments: $1=prompt  $2=batch_json  $3=batch_label
# ─────────────────────────────────────────────
call_ollama() {
    local PROMPT="$1"
    local BATCH_JSON="$2"
    local BATCH_LABEL="$3"

    local FULL_PROMPT="${PROMPT//__SCANNER_REPORT__/$BATCH_JSON}"

    local RESPONSE
    RESPONSE=$(curl -s -X POST "$OLLAMA_URL" \
        -H "Content-Type: application/json" \
        -d "$(jq -n \
            --arg model "$MODEL" \
            --arg prompt "$FULL_PROMPT" \
            '{model: $model, prompt: $prompt, stream: false, options: {num_predict: 2048, temperature: 0.1}}'
        )")

    local CURL_STATUS=$?

    if [ $CURL_STATUS -ne 0 ]; then
        echo "  ❌ Network error for $BATCH_LABEL" >&2
        echo ""
        return 1
    fi

    local OLLAMA_ERR
    OLLAMA_ERR=$(echo "$RESPONSE" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get('error',''))
except:
    print('')
" 2>/dev/null)

    if [ -n "$OLLAMA_ERR" ]; then
        echo "  ❌ Ollama error: $OLLAMA_ERR" >&2
        echo ""
        return 1
    fi

    echo "$RESPONSE" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('response', ''))
except Exception as e:
    print('')
"
    return 0
}

# ─────────────────────────────────────────────
# Function: send a finding to LLaMA
# Arguments: $1=scanner_name  $2=batch_json  $3=batch_num  $4=total_batches
# ─────────────────────────────────────────────
analyze_batch() {
    local SCANNER_NAME="$1"
    local BATCH_JSON="$2"
    local BATCH_NUM="$3"
    local TOTAL_BATCHES="$4"

    echo "  📦 Batch $BATCH_NUM/$TOTAL_BATCHES"

    # Build the prompt by substituting placeholders
    local PROMPT="${TEMPLATE//__ABUSE_CASES__/$ABUSE_CASES_CONTENT}"

    # Call Ollama with the main template
    local RESULT
    RESULT=$(call_ollama "$PROMPT" "$BATCH_JSON" "batch $BATCH_NUM")
    local CALL_STATUS=$?

    if [ $CALL_STATUS -ne 0 ]; then
        echo "" >> "$OUTPUT_FILE"
        echo "> ❌ Batch $BATCH_NUM/$TOTAL_BATCHES — Network error" >> "$OUTPUT_FILE"
        return 1
    fi

    # Check if the result is empty or whitespace-only
    local TRIMMED_RESULT
    TRIMMED_RESULT=$(echo "$RESULT" | tr -d '[:space:]')

    if [ -z "$TRIMMED_RESULT" ]; then
        echo "  ⚠️  Empty result from main prompt. Retrying with unmatched prompt..."

        # Build the unmatched prompt by substituting the finding placeholder
        local RESULT_UNMATCHED
        RESULT_UNMATCHED=$(call_ollama "$TEMPLATE_UNMATCHED" "$BATCH_JSON" "batch $BATCH_NUM (unmatched fallback)")
        local UNMATCHED_STATUS=$?

        if [ $UNMATCHED_STATUS -ne 0 ]; then
            echo "" >> "$OUTPUT_FILE"
            echo "> ❌ Batch $BATCH_NUM/$TOTAL_BATCHES — Unmatched fallback also failed (network error)" >> "$OUTPUT_FILE"
            return 1
        fi

        local TRIMMED_UNMATCHED
        TRIMMED_UNMATCHED=$(echo "$RESULT_UNMATCHED" | tr -d '[:space:]')

        if [ -z "$TRIMMED_UNMATCHED" ]; then
            echo "  ⚠️  Unmatched prompt also returned empty. Skipping batch $BATCH_NUM."
            return 0
        fi

        RESULT="$RESULT_UNMATCHED"
        echo "  ✅ Unmatched fallback produced a result."
    fi

    # Write to global output
    echo "" >> "$OUTPUT_FILE"
    echo "$RESULT" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    # Distribute into STRIDE files
    distribute_to_stride "$RESULT"

    echo "  ✅ Batch $BATCH_NUM complete"
    return 0
}

# ─────────────────────────────────────────────
# Main function: splits findings into batches
# and calls analyze_batch for each one
# Arguments: $1=scanner_name  $2=report_file
# ─────────────────────────────────────────────
analyze_report() {
    local SCANNER_NAME="$1"
    local REPORT_FILE="$2"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📡 Analysing: $SCANNER_NAME"
    echo "   File: $(basename "$REPORT_FILE")"
    SIZE_KB=$(wc -c < "$REPORT_FILE" | awk '{printf "%.0f", $1/1024}')
    echo "   Size: ${SIZE_KB} KB"

    # Determine the findings key (findings, raw_findings, or raw_output)
    local FINDINGS_KEY
    FINDINGS_KEY=$(python3 -c "
import json,sys
with open('$REPORT_FILE') as f:
    d=json.load(f)
if 'findings' in d:
    print('findings')
elif 'raw_findings' in d:
    print('raw_findings')
elif 'raw_output' in d:
    print('raw_output')
else:
    print('none')
")

    if [ "$FINDINGS_KEY" = "none" ]; then
        echo "   ⚠️  No 'findings' or 'raw_findings' field found. Skipping."
        return
    fi

    # Count total findings
    local TOTAL_FINDINGS
    TOTAL_FINDINGS=$(python3 -c "
import json
if '$FINDINGS_KEY' == 'raw_output':
    print(1)
else:
    with open('$REPORT_FILE') as f:
        d=json.load(f)
    print(len(d.get('$FINDINGS_KEY', [])))
")

    echo "   Total findings: $TOTAL_FINDINGS (field: $FINDINGS_KEY)"

    if [ "$TOTAL_FINDINGS" -eq 0 ]; then
        echo "   ℹ️  No findings to analyse."
        return
    fi

    # Calculate the number of batches
    local TOTAL_BATCHES
    TOTAL_BATCHES=$(python3 -c "import math; print(math.ceil($TOTAL_FINDINGS / $BATCH_SIZE))")

    echo "   Batches: $TOTAL_BATCHES (of $BATCH_SIZE findings each)"
    echo ""

    # Iterate over batches
    local BATCH_NUM=0
    local FAILED_BATCHES=0

    for START in $(seq 0 "$BATCH_SIZE" "$((TOTAL_FINDINGS - 1))"); do
        BATCH_NUM=$((BATCH_NUM + 1))
        local END=$((START + BATCH_SIZE))

        # Extract the batch as a JSON array
        local BATCH_JSON
        BATCH_JSON=$(python3 -c "
import json
with open('$REPORT_FILE') as f:
    d=json.load(f)
findings=d.get('$FINDINGS_KEY', [])
batch=findings[$START:$END]
if '$FINDINGS_KEY' == 'raw_output':
    out={
        'scanner': d.get('scanner','unknown'),
        'finding': findings
    }
else:
    out={
        'scanner': d.get('scanner','unknown'),
        'finding': batch
    }
print(json.dumps(out, indent=2))
")
        # debug print
        #echo "$BATCH_JSON"

        analyze_batch "$SCANNER_NAME" "$BATCH_JSON" "$BATCH_NUM" "$TOTAL_BATCHES"
        local STATUS=$?

        if [ $STATUS -ne 0 ]; then
            FAILED_BATCHES=$((FAILED_BATCHES + 1))
        fi

        # Pause between batches to avoid overloading Ollama
        if [ "$BATCH_NUM" -lt "$TOTAL_BATCHES" ]; then
            sleep 2
        fi
    done

    if [ "$FAILED_BATCHES" -gt 0 ]; then
        echo "   ⚠️  $FAILED_BATCHES batch(es) failed for $SCANNER_NAME"
    else
        echo "   ✅ $SCANNER_NAME complete ($TOTAL_BATCHES batches)"
    fi
    echo ""
}

# ─────────────────────────────────────────────
# Process each filtered report
# Order: smallest to largest
# ─────────────────────────────────────────────
for REPORT in \
    "$FILTERED_DIR/trivy_filtered.json" \
    "$FILTERED_DIR/falco_filtered.json" \
    "$FILTERED_DIR/nmap_filtered.json" \
    "$FILTERED_DIR/zap_filtered.json" \
    "$FILTERED_DIR/semgrep_filtered.json"
do
    if [ -f "$REPORT" ]; then
        SCANNER=$(basename "$REPORT" "_filtered.json")
        analyze_report "$SCANNER" "$REPORT"
    else
        echo "⚠️  Report not found, skipping: $(basename "$REPORT")"
    fi
done

# ─────────────────────────────────────────────
# Summary of generated STRIDE files
# ─────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Analysis complete!"
echo "📄 Global output:  $OUTPUT_FILE"
echo ""
echo "📂 STRIDE files generated in: $STRIDE_DIR"
for FILE in "$SPOOFING_FILE" "$TAMPERING_FILE" "$REPUDIATION_FILE" \
            "$INFO_DISCLOSURE_FILE" "$DOS_FILE" "$EOP_FILE" "$UNMATCHED_FILE"; do
    COUNT=$(grep -c "^### " "$FILE" 2>/dev/null || echo 0)
    printf "   %-35s  %s findings\n" "$(basename "$FILE")" "$COUNT"
done
echo ""
echo "To read a file:"
echo "  cat $STRIDE_DIR/spoofing.md | less"