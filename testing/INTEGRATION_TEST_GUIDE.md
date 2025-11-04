# Integration Test Guide

This guide explains how to use the integration test to verify the end-to-end functionality of AWS Security Guard.

## Overview

The integration test (`integration_test.py`) validates that:

1. **Monitoring works**: The monitor detects AWS resource changes
2. **State files update**: State files are updated when monitored resources change
3. **Logs are generated**: CloudTrail-style logs are created for detected changes

## How It Works

The integration test follows this workflow:

```
1. Clean up previous test artifacts (logs, state files)
2. Start aws-security-guard.py in background
3. Wait for baseline scan to complete (2x monitor interval)
4. Run test_infrastructure.py to trigger AWS changes
   - Creates resources (trails, buckets, queues, topics, etc.)
   - Modifies resources (change configs, policies, etc.)
   - Deletes resources
5. Wait for monitor to detect changes (1x monitor interval + buffer)
6. Verify state file was updated with resource changes
7. Verify logs were generated for detected changes
8. Stop the monitor and print results
```

## Prerequisites

Before running the integration test, ensure you have:

1. **AWS credentials** configured with appropriate permissions:
   - Monitoring permissions (see `iam-policies/monitoring-policy.json`)
   - Testing permissions (see `iam-policies/testing-policy.json`)

2. **Python dependencies** installed:
   ```bash
   pip install -r requirements.txt
   ```

3. **AWS profile** configured (recommended):
   ```bash
   aws configure --profile myprofile
   ```

## Usage

### Basic Usage

Test CloudTrail monitoring (default):
```bash
python testing/integration_test.py --profile myprofile
```

### Test Specific Services

Test a specific service:
```bash
# CloudTrail
python testing/integration_test.py --profile myprofile --service cloudtrail

# S3 bucket monitoring
python testing/integration_test.py --profile myprofile --service s3

# SQS queue monitoring
python testing/integration_test.py --profile myprofile --service sqs

# SNS topic monitoring
python testing/integration_test.py --profile myprofile --service sns

# GuardDuty monitoring
python testing/integration_test.py --profile myprofile --service guardduty

# EventBridge monitoring
python testing/integration_test.py --profile myprofile --service eventbridge

# IAM role monitoring
python testing/integration_test.py --profile myprofile --service iam
```

### Test All Services

Run comprehensive test of all services:
```bash
python testing/integration_test.py --profile myprofile --service all
```

**Note**: Testing all services takes approximately 15-30 minutes depending on the monitor interval and AWS API response times.

### Advanced Options

Specify region:
```bash
python testing/integration_test.py --profile myprofile --region us-west-2
```

Use custom test name:
```bash
python testing/integration_test.py --profile myprofile --test-name mytest123
```

Customize monitor interval (faster testing):
```bash
python testing/integration_test.py --profile myprofile --monitor-interval 20
```

Use custom directories and files:
```bash
python testing/integration_test.py \
  --profile myprofile \
  --state-dir my-test-state \
  --log-file my-test.log
```

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--profile` | AWS profile name to use | None (uses default credentials) |
| `--region` | AWS region to test in | `us-east-1` |
| `--service` | Service to test (cloudtrail, s3, sqs, sns, guardduty, eventbridge, iam, all) | `cloudtrail` |
| `--test-name` | Test name for resource naming | Auto-generated |
| `--state-dir` | Directory for state files | `state-test` |
| `--log-file` | Log file path | `security-watch-test.log` |
| `--monitor-interval` | Monitor interval in seconds | `30` |

## What Gets Tested

### CloudTrail
- ✓ Trail creation detected
- ✓ StopLogging event logged
- ✓ StartLogging event logged
- ✓ S3 bucket destination change logged
- ✓ Event selector modifications logged
- ✓ Trail deletion logged
- ✓ State file updated with trail configurations

### S3
- ✓ Bucket creation (via CloudTrail linkage) detected
- ✓ Encryption changes logged (add, modify)
- ✓ Bucket size reduction >50% logged
- ✓ State file updated with bucket configurations

### SQS
- ✓ Queue creation (via S3 event notification) detected
- ✓ Encryption changes logged
- ✓ Policy changes logged
- ✓ Queue deletion logged
- ✓ State file updated with queue configurations

### SNS
- ✓ Topic creation (via S3 event notification) detected
- ✓ Subscription changes logged
- ✓ Encryption changes logged
- ✓ Policy changes logged
- ✓ Topic deletion logged
- ✓ State file updated with topic configurations

### GuardDuty
- ✓ Suppression rule creation logged
- ✓ Suppression rule modification logged
- ✓ Suppression rule deletion logged
- ✓ State file updated with detector and rule configurations

### EventBridge
- ✓ Rule creation logged
- ✓ Rule state changes logged (enable/disable)
- ✓ Event pattern changes logged
- ✓ Rule deletion logged
- ✓ State file updated with rule configurations

### IAM
- ✓ Role creation (via Lambda linkage) detected
- ✓ Trust policy changes logged
- ✓ Managed policy attachment/detachment logged
- ✓ Inline policy changes logged
- ✓ Role deletion logged
- ✓ State file updated with role configurations

## Understanding Test Results

### Success Output

When a test passes, you'll see:
```
✓ CloudTrail State Update: State file updated with 1 resources
✓ CloudTrail Log Generation: Generated 4 new log entries
```

### Failure Output

When a test fails, you'll see:
```
✗ CloudTrail State Update: State file was not updated
✗ CloudTrail Log Generation: No new log entries generated
```

### Test Summary

At the end, you'll see a summary:
```
======================================================================
Test Results Summary
======================================================================

Total Tests: 6
Passed: 6
Failed: 0

All Tests:
  ✓ CloudTrail Test Execution: Test infrastructure completed successfully
  ✓ CloudTrail State Update: State file updated with 1 resources
  ✓ CloudTrail Log Generation: Generated 4 new log entries
```

### Results File

Detailed results are saved to `integration_test_results.json`:
```json
{
  "timestamp": "2025-10-19T12:00:00.000000",
  "profile": "myprofile",
  "region": "us-east-1",
  "service": "cloudtrail",
  "test_name": "abc123xyz",
  "summary": {
    "total": 6,
    "passed": 6,
    "failed": 0
  },
  "results": [
    {
      "test": "CloudTrail Test Execution",
      "passed": true,
      "message": "Test infrastructure completed successfully",
      "timestamp": "2025-10-19T12:00:00.000000"
    }
  ]
}
```

## Troubleshooting

### Monitor Doesn't Start

**Problem**: Monitor process exits immediately

**Solution**:
1. Check that `aws-security-guard.py` exists in the current directory
2. Verify AWS credentials are configured correctly
3. Check for Python syntax errors by running manually:
   ```bash
   python aws-security-guard.py --profile myprofile --interval 30
   ```

### No State Changes Detected

**Problem**: Test reports "State file was not updated"

**Possible causes**:
1. Monitor interval too short - increase `--monitor-interval`
2. AWS API delays - wait longer between test steps
3. Permissions issue - check IAM policies
4. Monitor not running - check process with `ps aux | grep aws-security-guard`

**Solution**:
```bash
# Use longer monitor interval
python testing/integration_test.py --profile myprofile --monitor-interval 60
```

### No Logs Generated

**Problem**: Test reports "No new log entries generated"

**Possible causes**:
1. First run (baseline only, no changes logged)
2. Changes not detected (see "No State Changes Detected" above)
3. Monitor not running long enough

**Solution**:
1. Ensure this is not the first run (state file should exist before test)
2. Check log file manually: `cat security-watch-test.log`
3. Run monitor manually first to establish baseline:
   ```bash
   python aws-security-guard.py --profile myprofile --interval 30 --state-dir state-test
   # Wait for one cycle, then Ctrl+C
   # Now run integration test
   ```

### Test Infrastructure Fails

**Problem**: "Test infrastructure failed" error

**Possible causes**:
1. Insufficient AWS permissions
2. Resource limits exceeded
3. Region-specific issues

**Solution**:
1. Verify testing policy is attached (see `iam-policies/testing-policy.json`)
2. Check AWS service quotas
3. Try a different region: `--region us-west-2`

### Interactive Mode Prompts

**Problem**: Test hangs waiting for input

**Cause**: The `test_infrastructure.py` functions use interactive mode internally

**Solution**: This is expected behavior - the test prompts you to press Enter before each AWS change. This gives you time to:
1. Observe the monitor output
2. Check state files manually
3. Verify logs are being generated
4. Control the pace of testing

To skip interactive prompts, you would need to modify the integration test to pass `interactive=False` to test functions (not recommended for debugging).

## Best Practices

### 1. Use Isolated Test Resources

The test creates resources with `aws-security-guard-test-` prefix. Clean up after testing:
```bash
python testing/test_infrastructure.py --profile myprofile --cleanup
```

### 2. Use Dedicated Test State Directory

Don't mix test state with production monitoring:
```bash
# Test
python testing/integration_test.py --state-dir state-test

# Production
python aws-security-guard.py --state-dir state
```

### 3. Monitor Interval Tuning

- **Development/Testing**: Use short intervals (20-30 seconds)
- **Production**: Use longer intervals (120+ seconds)

```bash
# Fast testing
python testing/integration_test.py --monitor-interval 20

# Production-like testing
python testing/integration_test.py --monitor-interval 120
```

### 4. Test in Non-Production Account

Always test in a development/staging AWS account to avoid:
- Interfering with production resources
- Accidentally modifying production configurations
- Hitting service limits that affect production

### 5. Review Test Results

After running tests, review:
1. **Console output**: Immediate feedback on pass/fail
2. **integration_test_results.json**: Detailed results with timestamps
3. **security-watch-test.log**: Actual log entries generated
4. **state-test/{account-id}.json**: Final state captured

## Continuous Integration

### GitHub Actions Example

```yaml
name: Integration Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Run integration tests
        run: python testing/integration_test.py --service all --monitor-interval 30

      - name: Upload test results
        uses: actions/upload-artifact@v2
        if: always()
        with:
          name: test-results
          path: integration_test_results.json
```

## Manual Testing Workflow

For interactive testing and debugging:

### Step 1: Start Monitor Manually
```bash
python aws-security-guard.py \
  --profile myprofile \
  --interval 30 \
  --state-dir state-test \
  --log-file security-watch-test.log \
  --verbose
```

### Step 2: In Another Terminal, Run Test Infrastructure
```bash
python testing/test_infrastructure.py \
  --profile myprofile \
  --service cloudtrail \
  --interactive
```

### Step 3: Observe Changes

Watch the monitor terminal for:
- "✓ cloudtrail in us-east-1" (successful scan)
- "Changes detected, updating state file..."

### Step 4: Verify Files

Check state file:
```bash
cat state-test/YOUR_ACCOUNT_ID.json | jq .
```

Check logs:
```bash
tail -f security-watch-test.log | jq .
```

### Step 5: Stop Monitor
Press Ctrl+C in the monitor terminal

## Next Steps

After running integration tests successfully:

1. **Test in production**: Use production AWS profile with longer intervals
2. **Set up monitoring**: Deploy to production environment
3. **Configure alerts**: Set up alerts for critical log events
4. **Review logs regularly**: Establish baseline and investigate anomalies

## Support

If you encounter issues:

1. Check this guide's Troubleshooting section
2. Review the main README.md
3. Check monitor output with `--verbose` flag
4. File an issue with:
   - Command used
   - Error output
   - integration_test_results.json
   - Relevant log entries
