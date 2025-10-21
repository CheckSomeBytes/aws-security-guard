# AWS Security Watch Testing Summary

This document provides an overview of the testing infrastructure for AWS Security Watch.

## Testing Components

### 1. Infrastructure Test (`testing/test_infrastructure.py`)

**Purpose**: Creates, modifies, and deletes AWS resources to simulate real-world changes.

**Features**:
- ✅ Tests all 8 monitored services (CloudTrail, GuardDuty, EventBridge, S3, SQS, SNS, Lambda, IAM)
- ✅ Interactive mode for manual testing
- ✅ Automated mode with configurable delays
- ✅ Comprehensive cleanup functionality
- ✅ Service-specific test selection
- ✅ Multi-region cleanup support

**Usage**:
```bash
# Interactive testing
python testing/test_infrastructure.py --profile myprofile --interactive

# Test specific service
python testing/test_infrastructure.py --profile myprofile --service cloudtrail

# Cleanup all test resources
python testing/test_infrastructure.py --profile myprofile --cleanup --cleanup-all-regions
```

**What it tests**:
- CloudTrail: Start/stop logging, S3 destination changes, event selectors, trail deletion
- S3: Encryption changes, bucket size reduction, CloudTrail bucket linkage
- SQS: Queue creation, encryption, policy changes, S3 event notifications
- SNS: Topic creation, subscriptions, encryption, policy changes
- GuardDuty: Suppression rule creation, modification, deletion
- EventBridge: Rule creation, state changes, event pattern updates
- Lambda: Function creation, code changes, configuration updates, role linkage
- IAM: Role creation, trust policy changes, managed/inline policies

### 2. Integration Test (`testing/integration_test.py`)

**Purpose**: End-to-end validation that the monitoring tool correctly detects and logs changes.

**Features**:
- ✅ Automated test orchestration
- ✅ State file verification
- ✅ Log entry verification
- ✅ Detailed test reporting (JSON + console)
- ✅ Service-specific or comprehensive testing
- ✅ Colored terminal output
- ✅ Automatic cleanup

**Workflow**:
```
1. Clean up previous test artifacts
2. Start aws_security_watch.py in background
3. Wait for baseline scan
4. Run test_infrastructure.py to trigger changes
5. Wait for monitor to detect changes
6. Verify state file updates
7. Verify log generation
8. Generate test report
9. Stop monitor
```

**Usage**:
```bash
# Quick test (CloudTrail only)
python testing/integration_test.py --profile myprofile --service cloudtrail

# Comprehensive test (all services)
python testing/integration_test.py --profile myprofile --service all

# Fast testing (shorter intervals)
python testing/integration_test.py --profile myprofile --monitor-interval 20
```

**Verification Points**:
- ✅ Monitor starts successfully
- ✅ Baseline scan completes
- ✅ Test infrastructure executes without errors
- ✅ State file is created/updated
- ✅ State contains expected resource counts
- ✅ Logs are generated for monitored events
- ✅ Log entries contain correct event details

### 3. Documentation

**Quick Start Guide** (`testing/QUICK_START.md`):
- Get started in 5 minutes
- Expected output examples
- Common commands
- Basic troubleshooting

**Integration Test Guide** (`testing/INTEGRATION_TEST_GUIDE.md`):
- Comprehensive testing documentation
- Detailed troubleshooting
- Best practices
- CI/CD integration examples
- Manual testing workflows

**Interactive Mode Example** (`testing/INTERACTIVE_MODE_EXAMPLE.md`):
- Step-by-step manual testing guide
- Real-world testing scenarios

**Testing Guide** (`testing/TESTING_GUIDE.md`):
- Original testing documentation
- Service-specific test details

## Test Coverage

### Services Monitored

| Service | Infrastructure Test | Integration Test | Auto-Cleanup |
|---------|-------------------|------------------|--------------|
| CloudTrail | ✅ | ✅ | ✅ |
| GuardDuty | ✅ | ✅ | ✅ |
| EventBridge | ✅ | ✅ | ✅ |
| S3 | ✅ | ✅ | ✅ |
| SQS | ✅ | ✅ | ✅ |
| SNS | ✅ | ✅ | ✅ |
| Lambda | ✅ | ✅ | ✅ |
| IAM | ✅ | ✅ | ✅ |

### Change Detection Coverage

| Change Type | Tested | Verified in State | Verified in Logs |
|-------------|--------|------------------|------------------|
| Resource Creation | ✅ | ✅ | ✅ |
| Resource Modification | ✅ | ✅ | ✅ |
| Resource Deletion | ✅ | ✅ | ✅ |
| Configuration Changes | ✅ | ✅ | ✅ |
| Policy Changes | ✅ | ✅ | ✅ |
| Encryption Changes | ✅ | ✅ | ✅ |

## Testing Workflow

### For Development

```bash
# 1. Make code changes to aws-security-watch

# 2. Run quick integration test
python testing/integration_test.py --profile dev --service cloudtrail --monitor-interval 20

# 3. Fix any issues

# 4. Run comprehensive test
python testing/integration_test.py --profile dev --service all

# 5. Review results
cat integration_test_results.json | jq .
```

### For CI/CD

```yaml
# Example GitHub Actions workflow
- name: Run Integration Tests
  run: |
    python testing/integration_test.py \
      --service all \
      --monitor-interval 30

- name: Upload Results
  uses: actions/upload-artifact@v2
  with:
    name: test-results
    path: integration_test_results.json
```

### For Manual Validation

```bash
# Terminal 1: Start monitor with verbose logging
python aws_security_watch.py \
  --profile myprofile \
  --interval 30 \
  --state-dir state-test \
  --log-file security-watch-test.log \
  --verbose

# Terminal 2: Run infrastructure tests interactively
python testing/test_infrastructure.py \
  --profile myprofile \
  --service cloudtrail \
  --interactive

# Terminal 3: Watch logs in real-time
tail -f security-watch-test.log | jq .

# Terminal 4: Watch state file changes
watch -n 5 'cat state-test/ACCOUNT_ID.json | jq .'
```

## Test Artifacts

After running tests, you'll have:

| File | Description |
|------|-------------|
| `integration_test_results.json` | Detailed test results with pass/fail status |
| `security-watch-test.log` | CloudTrail-style logs generated during testing |
| `state-test/ACCOUNT_ID.json` | State file capturing AWS resource configurations |

## Performance

### Integration Test Timing

| Test Scope | Approximate Duration | Monitor Interval |
|------------|---------------------|------------------|
| Single Service | 5-10 minutes | 30 seconds |
| All Services | 15-30 minutes | 30 seconds |
| Fast Testing | 3-5 minutes | 20 seconds |
| Production-like | 20-40 minutes | 120 seconds |

**Note**: Duration varies based on:
- AWS API response times
- Number of resources created/modified
- Monitor interval setting
- Interactive vs automated mode

## Best Practices

### 1. Test in Isolated Environment

✅ **DO**:
- Use dedicated test/dev AWS account
- Use separate state directory (`state-test`)
- Use separate log file (`security-watch-test.log`)

❌ **DON'T**:
- Test in production account
- Mix test and production state files
- Test in accounts with critical workloads

### 2. Clean Up After Testing

```bash
# Always clean up test resources
python testing/test_infrastructure.py --profile myprofile --cleanup --cleanup-all-regions

# Verify cleanup
aws resourcegroupstaggingapi get-resources \
  --profile myprofile \
  --resource-type-filters cloudtrail s3 sqs sns lambda iam \
  --query 'ResourceTagMappingList[?contains(ResourceARN, `aws-security-watch-test`)]'
```

### 3. Monitor Interval Tuning

- **Development**: 20-30 seconds (faster feedback)
- **Integration Testing**: 30-60 seconds (balance between speed and reliability)
- **Production**: 120+ seconds (reduce API calls, comply with rate limits)

### 4. Verify All Components

Before deploying to production, verify:
- ✅ State files are updated correctly
- ✅ Logs are generated for all change types
- ✅ No permission errors in logs
- ✅ Monitor runs stable for extended periods
- ✅ Cleanup removes all test resources

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Monitor exits immediately | Missing dependencies or invalid credentials | Run manually to see error: `python aws_security_watch.py --profile myprofile` |
| No state changes detected | Monitor interval too short | Increase `--monitor-interval` to 60+ |
| No logs generated | First run (baseline only) | Run integration test twice, second run will generate logs |
| Permission errors | Missing IAM policies | Attach monitoring-policy.json and testing-policy.json |
| Resource cleanup fails | Resources still in use | Wait a few minutes and retry cleanup |

### Debug Mode

Run with verbose logging to diagnose issues:

```bash
# Integration test
python testing/integration_test.py \
  --profile myprofile \
  --service cloudtrail \
  --monitor-interval 60

# Monitor with verbose output
python aws_security_watch.py \
  --profile myprofile \
  --interval 30 \
  --verbose
```

## Test Results Interpretation

### Successful Test

```json
{
  "summary": {
    "total": 9,
    "passed": 9,
    "failed": 0
  }
}
```

All verifications passed:
- ✅ Infrastructure test executed
- ✅ State file updated
- ✅ Logs generated

### Partial Failure

```json
{
  "summary": {
    "total": 9,
    "passed": 6,
    "failed": 3
  }
}
```

Some verifications failed. Check:
1. Which tests failed (see results array)
2. Error messages
3. AWS CloudWatch logs
4. Monitor output

### Complete Failure

```json
{
  "summary": {
    "total": 3,
    "passed": 0,
    "failed": 3
  }
}
```

Major issue preventing testing. Likely causes:
1. AWS credentials invalid
2. IAM permissions insufficient
3. Monitor not starting
4. Network/connectivity issues

## Continuous Integration

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
python testing/integration_test.py --service cloudtrail --monitor-interval 20
```

### Automated Testing Schedule

Run integration tests:
- ✅ On every PR
- ✅ On merge to main
- ✅ Nightly (comprehensive)
- ✅ Weekly (all regions)

## Metrics

Track test performance over time:
- Test execution time
- Pass/fail rates
- AWS API call counts
- Resource cleanup success rate

## Next Steps

1. **Run Quick Test**: Follow [QUICK_START.md](testing/QUICK_START.md)
2. **Comprehensive Testing**: Read [INTEGRATION_TEST_GUIDE.md](testing/INTEGRATION_TEST_GUIDE.md)
3. **Production Deployment**: See main [README.md](README.md)
4. **Set Up Monitoring**: Configure production monitoring with appropriate intervals

## Support

For testing issues:
1. Check troubleshooting sections in documentation
2. Review integration test results JSON
3. Enable verbose logging (`--verbose`)
4. Check AWS CloudTrail for API errors
5. File issue with detailed logs and results
