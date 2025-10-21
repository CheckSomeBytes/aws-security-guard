# Integration Test Quick Start

Get started testing AWS Security Watch in 5 minutes.

## Quick Test (CloudTrail Only)

```bash
# 1. Run the integration test (fully automated - no user input required)
python testing/integration_test.py --profile myprofile --service cloudtrail

# 2. Wait for completion (approximately 5-10 minutes)
#    The test runs automatically and shows progress updates

# 3. Check results
cat integration_test_results.log      # Human-readable text report
cat integration_test_results.json     # Machine-readable JSON
cat integration_test_findings.json    # Detailed findings database
```

**Note**: The integration test runs in **fully automated mode** - no user input is required. Progress updates are shown every 10 seconds during wait periods.

## Output Files

The test generates three main output files:

| File | Format | Best For |
|------|--------|----------|
| `integration_test_results.log` | **Text** | Quick review, sharing with team, printing |
| `integration_test_results.json` | JSON | CI/CD pipelines, programmatic analysis |
| `integration_test_findings.json` | JSON | Detailed investigation, debugging |

## Expected Output

```
======================================================================
Integration Test Configuration
======================================================================

Account ID: 123456789012
Region: us-east-1
Service: cloudtrail
Test name: abc123xyz
Monitor interval: 30 seconds
State directory: state-test
Log file: security-watch-test.log
Findings log: integration_test_findings.json

Running in automated mode - no user input required

======================================================================
Starting AWS Security Watch Monitor
======================================================================

Command: python aws_security_watch.py --interval 30 --state-dir state-test --log-file security-watch-test.log --profile myprofile
✓ Monitor started (PID: 12345)
ℹ Waiting 60 seconds for initial baseline scan...
  ... 60 seconds remaining
  ... 50 seconds remaining
  ... 40 seconds remaining
  ... 30 seconds remaining
  ... 20 seconds remaining
  ... 10 seconds remaining
✓ Baseline scan completed

======================================================================
Testing CloudTrail Monitoring in us-east-1
======================================================================

ℹ Running cloudtrail infrastructure test (automated mode - no user input required)...
ℹ This will create, modify, and delete AWS resources to trigger monitoring events

=== Testing CloudTrail in us-east-1 ===
Created S3 bucket: aws-security-watch-test-bucket1-abc123
Created S3 bucket: aws-security-watch-test-bucket2-abc123
Creating trail: aws-security-watch-test-trail-abc123
Started logging for trail: aws-security-watch-test-trail-abc123
Waiting 35 seconds...

Test 1: Stopping logging...
Waiting 35 seconds...
✓ Logging stopped

Restarting logging...
Waiting 35 seconds...
✓ Logging restarted

Test 2: Changing S3 destination...
Waiting 35 seconds...
✓ S3 destination changed to aws-security-watch-test-bucket2-abc123

Test 3: Updating event selectors to include S3 data events...
Waiting 35 seconds...
✓ Event selectors updated to include S3 data events

Test 4: Deleting trail...
Waiting 35 seconds...
✓ Trail deleted

✓ CloudTrail infrastructure test completed
✓ CloudTrail Test Execution: Test infrastructure completed successfully

ℹ Waiting for monitor to detect cloudtrail changes...
  ... 40 seconds remaining
  ... 30 seconds remaining
  ... 20 seconds remaining
  ... 10 seconds remaining
✓ Monitor cycle completed

✓ CloudTrail State Update: State file updated: trails=0
✓ CloudTrail Log Generation: Generated 4 log entries: StopLogging=1, StartLogging=1, UpdateTrailS3Bucket=1, DeleteTrail=1

======================================================================
Test Results Summary
======================================================================

Total Tests: 3
Passed: 3
Failed: 0

All Tests:
  ✓ CloudTrail Test Execution: Test infrastructure completed successfully
  ✓ CloudTrail State Update: State file updated: trails=0
  ✓ CloudTrail Log Generation: Generated 4 log entries: StopLogging=1, StartLogging=1, UpdateTrailS3Bucket=1, DeleteTrail=1

Findings Summary:
  log_entry: 20 findings
  log_summary: 3 findings
  state_resource: 0 findings
  test_execution: 3 findings
  test_metadata: 1 findings

✓ Detailed results saved to integration_test_results.json
✓ Findings log saved to integration_test_findings.json

======================================================================
Stopping AWS Security Watch Monitor
======================================================================

✓ Monitor stopped (PID: 12345)
```

## What Just Happened?

The integration test:

1. ✅ Started aws-security-watch in the background
2. ✅ Waited for baseline scan (first run, no logs)
3. ✅ Created a CloudTrail trail with S3 bucket
4. ✅ Stopped logging (should be logged)
5. ✅ Restarted logging (should be logged)
6. ✅ Changed S3 destination (should be logged)
7. ✅ Updated event selectors (should be logged)
8. ✅ Deleted trail (should be logged)
9. ✅ Verified state file was updated
10. ✅ Verified 4 log entries were generated
11. ✅ Stopped the monitor

## Verify the Results

### Check Generated Logs

```bash
cat security-watch-test.log | jq .
```

You should see entries like:
```json
{
  "eventTime": "2025-10-19T12:00:00Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "StopLogging",
  "awsRegion": "us-east-1",
  "responseElements": {
    "trailName": "aws-security-watch-test-trail-abc123"
  },
  "eventID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "readOnly": false,
  "eventType": "AWSSecurityWatch",
  "recipientAccountId": "123456789012"
}
```

### Check State File

```bash
# Find your account ID
aws sts get-caller-identity --profile myprofile --query Account --output text

# View state file (replace YOUR_ACCOUNT_ID)
cat state-test/YOUR_ACCOUNT_ID.json | jq .
```

## Test Other Services

### S3 Monitoring
```bash
python testing/integration_test.py --profile myprofile --service s3
```

### SQS Monitoring
```bash
python testing/integration_test.py --profile myprofile --service sqs
```

### SNS Monitoring
```bash
python testing/integration_test.py --profile myprofile --service sns
```

### All Services (15-30 minutes)
```bash
python testing/integration_test.py --profile myprofile --service all
```

## Common Options

### Faster Testing (Shorter Interval)
```bash
python testing/integration_test.py --profile myprofile --monitor-interval 20
```

### Test in Different Region
```bash
python testing/integration_test.py --profile myprofile --region us-west-2
```

### Custom Test Name
```bash
python testing/integration_test.py --profile myprofile --test-name mytest123
```

## Cleanup

The integration test cleans up its resources automatically. To manually clean up any leftover test resources:

```bash
# Clean current region
python testing/test_infrastructure.py --profile myprofile --cleanup

# Clean all regions
python testing/test_infrastructure.py --profile myprofile --cleanup --cleanup-all-regions
```

## Troubleshooting

### "Monitor process exited prematurely"

**Cause**: aws_security_watch.py failed to start

**Fix**: Run manually to see the error:
```bash
python aws_security_watch.py --profile myprofile --interval 30 --state-dir state-test
```

### "No new log entries generated"

**Cause**: Monitor didn't detect changes (likely timing issue)

**Fix**: Use longer interval:
```bash
python testing/integration_test.py --profile myprofile --monitor-interval 60
```

### "Permission denied" errors

**Cause**: Missing IAM permissions

**Fix**: Attach both policies to your IAM user/role:
- `iam-policies/monitoring-policy.json` (read permissions)
- `iam-policies/testing-policy.json` (write permissions)

## Next Steps

✅ **Passed all tests?** You're ready to deploy to production!

📚 **Want more details?** Read [INTEGRATION_TEST_GUIDE.md](INTEGRATION_TEST_GUIDE.md)

🚀 **Deploy to production**: See main [README.md](../README.md)

## Need Help?

1. Check [INTEGRATION_TEST_GUIDE.md](INTEGRATION_TEST_GUIDE.md) for detailed troubleshooting
2. Review monitor output with `--verbose` flag
3. Check `integration_test_results.json` for detailed results
