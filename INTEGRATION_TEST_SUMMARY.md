# Integration Test - Automated Mode

## Overview

The AWS Security Watch integration test now runs in **fully automated mode** with no user input required.

## Key Features

✅ **Fully Automated**: No manual intervention needed
✅ **Progress Updates**: Shows countdown timers every 10 seconds
✅ **Detailed Findings Log**: Tracks every resource, log entry, and event
✅ **Comprehensive Reporting**: JSON output with categorized findings
✅ **Multi-Service Support**: Test individual services or all at once

## Quick Start

```bash
# Test CloudTrail (5-10 minutes)
python testing/integration_test.py --profile myprofile --service cloudtrail

# Test all services (20-30 minutes)
python testing/integration_test.py --profile myprofile --service all
```

## What It Does (Automatically)

1. **Starts the monitor** in background
2. **Waits for baseline scan** (shows progress every 10 seconds)
3. **Runs infrastructure tests** to trigger AWS changes
4. **Waits for detection** (shows progress every 10 seconds)
5. **Verifies results**:
   - State file updated ✓
   - Logs generated ✓
   - Resources tracked ✓
6. **Generates reports**:
   - `integration_test_results.json` - Test pass/fail results
   - `integration_test_findings.json` - Detailed findings log
7. **Stops the monitor** automatically

## Progress Indicators

The test shows real-time progress:

```
ℹ Waiting 60 seconds for initial baseline scan...
  ... 60 seconds remaining
  ... 50 seconds remaining
  ... 40 seconds remaining
  ... 30 seconds remaining
  ... 20 seconds remaining
  ... 10 seconds remaining
✓ Baseline scan completed
```

## Output Files

After completion, you get:

| File | Format | Contents |
|------|--------|----------|
| `integration_test_results.log` | **Text** | Human-readable test report with all results |
| `integration_test_results.json` | JSON | Test results (pass/fail summary) |
| `integration_test_findings.json` | JSON | Detailed findings (resources, logs, events) |
| `security-watch-test.log` | JSON | CloudTrail-style logs generated |
| `state-test/ACCOUNT_ID.json` | JSON | State file with AWS resources |

**New!** The integration test now generates a comprehensive **text log** (`integration_test_results.log`) that's easy to read without JSON tools.

## Typical Runtime

| Service | Duration |
|---------|----------|
| CloudTrail | 5-10 minutes |
| S3 | 5-10 minutes |
| SQS | 5-10 minutes |
| SNS | 5-10 minutes |
| GuardDuty | 5-10 minutes |
| EventBridge | 5-10 minutes |
| IAM | 10-15 minutes |
| **All Services** | **20-30 minutes** |

## Customization

```bash
# Faster testing (shorter intervals)
python testing/integration_test.py --profile myprofile --monitor-interval 20

# Different region
python testing/integration_test.py --profile myprofile --region us-west-2

# Custom output location
python testing/integration_test.py \
  --profile myprofile \
  --findings-log my-findings.json \
  --log-file my-test.log
```

## Using the Text Report

The text report is designed for human readability:

```bash
# View the entire report
cat integration_test_results.log

# View with pager
less integration_test_results.log

# Search for failures
grep "FAIL" integration_test_results.log

# Search for errors
grep "ERROR" integration_test_results.log

# View just the summary section
head -n 50 integration_test_results.log

# View resources detected
grep -A 50 "RESOURCES DETECTED" integration_test_results.log
```

## Findings Log

The findings log (`integration_test_findings.json`) contains:

- **Resources detected**: Every CloudTrail trail, S3 bucket, SQS queue, etc.
- **Log entries**: All monitoring events generated
- **Timeline**: When each event occurred
- **Test metadata**: Configuration, account, region
- **Errors/warnings**: Any issues encountered

Example query:
```bash
# View summary
cat integration_test_findings.json | jq '.summary'

# List all resources
cat integration_test_findings.json | jq '.findings[] | select(.category == "state_resource")'

# Find errors
cat integration_test_findings.json | jq '.findings[] | select(.severity == "error")'
```

## CI/CD Integration

Perfect for automated testing:

```yaml
# GitHub Actions
- name: Run Integration Tests
  run: python testing/integration_test.py --service all --monitor-interval 30

- name: Check Results
  run: |
    errors=$(jq '.summary.by_severity.error' integration_test_findings.json)
    if [ "$errors" -gt 0 ]; then exit 1; fi
```

## Documentation

- **[QUICK_START.md](testing/QUICK_START.md)**: Get started in 5 minutes
- **[INTEGRATION_TEST_GUIDE.md](testing/INTEGRATION_TEST_GUIDE.md)**: Comprehensive guide
- **[FINDINGS_LOG.md](testing/FINDINGS_LOG.md)**: Findings log documentation
- **[testing/README.md](testing/README.md)**: Testing overview

## Troubleshooting

All issues are logged in the findings log:

```bash
# Check for errors
cat integration_test_findings.json | jq '.findings[] | select(.severity == "error")'

# Check test execution
cat integration_test_findings.json | jq '.findings[] | select(.category == "test_execution")'
```

## Summary

The integration test provides:
- ✅ Zero manual intervention required
- ✅ Real-time progress updates
- ✅ Comprehensive findings tracking
- ✅ Detailed audit trail
- ✅ Machine-readable output
- ✅ CI/CD ready

Run it, grab a coffee ☕, and come back to complete test results!
