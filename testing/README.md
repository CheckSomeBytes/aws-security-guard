# AWS Security Watch Testing

This directory contains comprehensive testing tools for AWS Security Watch.

## Quick Start

**New to testing?** Start here:

```bash
# 1. Run the integration test for CloudTrail
python testing/integration_test.py --profile myprofile --service cloudtrail

# 2. Check the results
cat integration_test_results.json | jq .
```

See [QUICK_START.md](QUICK_START.md) for detailed quick start guide.

## Testing Tools

### 1. Integration Test (`integration_test.py`)

**End-to-end testing** that validates the entire monitoring workflow.

```bash
# Test a specific service
python integration_test.py --profile myprofile --service cloudtrail

# Test all services
python integration_test.py --profile myprofile --service all
```

**What it does**:
1. Starts aws-security-watch monitor in background
2. Runs infrastructure tests to trigger AWS changes
3. Verifies state files are updated
4. Verifies logs are generated
5. Reports results in JSON and console

**Documentation**: [INTEGRATION_TEST_GUIDE.md](INTEGRATION_TEST_GUIDE.md)

### 2. Infrastructure Test (`test_infrastructure.py`)

**Creates and modifies AWS resources** to simulate real-world changes.

```bash
# Interactive testing (recommended)
python test_infrastructure.py --profile myprofile --interactive

# Test specific service
python test_infrastructure.py --profile myprofile --service iam

# Cleanup all test resources
python test_infrastructure.py --profile myprofile --cleanup --cleanup-all-regions
```

**What it tests**:
- CloudTrail: Trail operations, logging, S3 changes
- S3: Bucket encryption, size reduction monitoring
- SQS: Queue operations, policies, S3 events
- SNS: Topics, subscriptions, encryption
- GuardDuty: Suppression rules
- EventBridge: Rules, patterns, state changes
- Lambda: Functions, code, configuration
- IAM: Roles, policies, trust relationships

**Documentation**: [TESTING_GUIDE.md](TESTING_GUIDE.md)

## Directory Structure

```
testing/
├── README.md                      # This file
├── integration_test.py            # End-to-end integration test
├── test_infrastructure.py         # AWS resource test generator
├── QUICK_START.md                 # 5-minute quick start guide
├── INTEGRATION_TEST_GUIDE.md      # Comprehensive integration test docs
├── TESTING_GUIDE.md               # Infrastructure test documentation
└── INTERACTIVE_MODE_EXAMPLE.md    # Manual testing examples
```

## Testing Workflow

### Automated Testing (Recommended)

Use the integration test for automated validation:

```bash
# Quick validation (5-10 minutes)
python integration_test.py --profile myprofile --service cloudtrail

# Comprehensive validation (15-30 minutes)
python integration_test.py --profile myprofile --service all
```

### Manual Testing

For debugging and development:

```bash
# Terminal 1: Start monitor
python ../aws_security_watch.py --profile myprofile --interval 30 --state-dir state-test --verbose

# Terminal 2: Run infrastructure test
python test_infrastructure.py --profile myprofile --service cloudtrail --interactive

# Terminal 3: Watch logs
tail -f security-watch-test.log | jq .
```

## Test Results

After running tests, check:

1. **Console output**: Immediate pass/fail feedback
2. **integration_test_results.json**: Detailed results
3. **security-watch-test.log**: Generated CloudTrail logs
4. **state-test/ACCOUNT_ID.json**: State file

Example results:
```json
{
  "summary": {
    "total": 9,
    "passed": 9,
    "failed": 0
  }
}
```

## Prerequisites

### AWS Permissions

Attach both IAM policies:
- **Monitoring**: `../iam-policies/monitoring-policy.json` (read access)
- **Testing**: `../iam-policies/testing-policy.json` (write access)

### AWS Profile

Configure credentials:
```bash
aws configure --profile myprofile
```

### Python Dependencies

```bash
pip install -r ../requirements.txt
```

## Common Commands

### Quick Tests

```bash
# CloudTrail (fastest, ~5 min)
python integration_test.py --profile myprofile --service cloudtrail

# S3 monitoring
python integration_test.py --profile myprofile --service s3

# All services (~20 min)
python integration_test.py --profile myprofile --service all
```

### With Custom Settings

```bash
# Faster testing (shorter interval)
python integration_test.py --profile myprofile --monitor-interval 20

# Different region
python integration_test.py --profile myprofile --region us-west-2

# Custom state and log files
python integration_test.py \
  --profile myprofile \
  --state-dir my-test-state \
  --log-file my-test.log
```

### Cleanup

```bash
# Clean current region
python test_infrastructure.py --profile myprofile --cleanup

# Clean all regions
python test_infrastructure.py --profile myprofile --cleanup --cleanup-all-regions

# Remove test artifacts
rm -rf state-test/
rm -f security-watch-test.log
rm -f integration_test_results.json
```

## Troubleshooting

### Monitor Won't Start

```bash
# Check for errors
python ../aws_security_watch.py --profile myprofile --interval 30 --state-dir state-test
```

### No Logs Generated

```bash
# Use longer monitor interval
python integration_test.py --profile myprofile --monitor-interval 60
```

### Permission Errors

```bash
# Verify IAM policies are attached
aws iam list-attached-user-policies --user-name YOUR_USER --profile myprofile

# Check for required permissions
aws cloudtrail describe-trails --profile myprofile
```

### Test Resources Not Cleaned Up

```bash
# List remaining test resources
aws resourcegroupstaggingapi get-resources \
  --profile myprofile \
  --query 'ResourceTagMappingList[?contains(ResourceARN, `aws-security-watch-test`)]'

# Force cleanup
python test_infrastructure.py --profile myprofile --cleanup --cleanup-all-regions
```

## Documentation

- **[QUICK_START.md](QUICK_START.md)**: Get started in 5 minutes
- **[INTEGRATION_TEST_GUIDE.md](INTEGRATION_TEST_GUIDE.md)**: Comprehensive integration test documentation
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)**: Infrastructure test documentation
- **[INTERACTIVE_MODE_EXAMPLE.md](INTERACTIVE_MODE_EXAMPLE.md)**: Manual testing examples

## Best Practices

### ✅ DO

- Test in dedicated dev/test AWS account
- Use separate state directories for testing
- Clean up resources after testing
- Review test results before deploying to production
- Run comprehensive tests before major releases

### ❌ DON'T

- Test in production AWS account
- Mix test and production state files
- Leave test resources running (costs money)
- Skip cleanup after failed tests
- Ignore permission errors

## Support

For help:
1. Check troubleshooting sections in documentation
2. Run with `--verbose` flag for detailed output
3. Review `integration_test_results.json`
4. Check AWS CloudTrail for API errors

## Next Steps

1. ✅ Run [Quick Start](QUICK_START.md) guide
2. ✅ Review [Integration Test Guide](INTEGRATION_TEST_GUIDE.md)
3. ✅ Run comprehensive tests (`--service all`)
4. ✅ Deploy to production (see main [README](../README.md))
