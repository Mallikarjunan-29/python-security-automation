SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Define paths relative to project root
OUTPUT_DIR="$SCRIPT_DIR/../output"
BATCH_LOG="$OUTPUT_DIR/output_batch.log"
ANALYZE_LOG="$OUTPUT_DIR/output_analyze.log"
INPUT_JSON="$SCRIPT_DIR/../data/test_batch.json"

echo "Executing batch"
echo "============================================================================================"
curl -X POST http://localhost:5000/batch -H 'Content-Type: application/json' -d @"$INPUT_JSON" > "$BATCH_LOG"
echo "Health Status"
echo "============================================================================================"
curl http://localhost:5000/health

echo "Execute Single alert"
echo "============================================================================================"
curl -X POST http://localhost:5000/analyze -H 'Content-Type: application/json' -d '{
  "name": "Alert Name",
  "alert": {
    "user": "user@company.com",
    "source_ip": "1.2.3.4",
    "failed_logins": 5,
    "success": true,
    "time": "02:00",
    "location": "Location",
    "severity": "High"
  }
}' > "$ANALYZE_LOG"

echo "Execute health"
echo "============================================================================================"
curl http://localhost:5000/health