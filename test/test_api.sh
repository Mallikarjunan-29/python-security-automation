echo "Executing batch"
echo "============================================================================================"
curl -X POST http://localhost:5000/batch -H 'Content-Type: application/json' -d @../data/test_batch.json > output/output_batch.log
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
}' > output/output_analyze.log

echo "Execute health"
echo "============================================================================================"
curl http://localhost:5000/health