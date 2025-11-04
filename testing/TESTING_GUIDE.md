# AWS Security Guard - Testing Guide

This guide provides step-by-step instructions for testing the monitoring system to ensure it correctly detects infrastructure changes and generates appropriate logs.

## Overview

The testing process involves:
1. Running the monitoring script continuously
2. Making infrastructure changes via `test_infrastructure.py`
3. Verifying state file updates and log generation at each step using `test_monitoring_verification.py`

## Critical Fixes Applied

### Multi-Region Trail Handling
The monitoring system has been fixed to properly handle multi-region CloudTrail trails:

- **Issue**: Multi-region trails were appearing in the state file for every region, causing duplicates
- **Fix**: Modified `cloudtrail_monitor.py:16-85` to only track trails in their home region
- **Impact**: Each trail now appears only once in the state file (in its home region)

## Prerequisites

1. AWS credentials configured with appropriate permissions
2. Python 3.7+ installed
3. boto3 library installed

## Testing Process

### Step 1: Initial Setup

First, clean up any existing state to start fresh:

```bash
# Backup existing state (optional)
cp -r state state.backup

# Remove old state file to start fresh
rm state/*.json

# Clear the log file
> security-watch.log
```

### Step 2: Start the Monitoring Script

In Terminal 1, start the monitoring script:

```bash
python3 aws-security-guard.py \
  --profile sec-watch-test \
  --state-dir state \
  --log-file security-watch.log \
  --interval 120
```

Wait for the first monitoring cycle to complete. You should see:
```
First run for account XXXXXXXXXXXX - establishing baseline state
Monitoring 16 regions for account XXXXXXXXXXXX
...
State file updated
```

### Step 3: Run Test Infrastructure Script

In Terminal 2, run the test infrastructure script with a unique test name:

```bash
# Generate a unique test name (or use a specific one)
TEST_NAME=$(python3 -c "import random, string; print(''.join(random.choices(string.ascii_lowercase + string.digits, k=8)))")
echo "Test name: $TEST_NAME"

# Run with interactive mode (recommended for first-time testing)
python3 testing/test_infrastructure.py \
  --profile sec-watch-test \
  --region us-east-1 \
  --test-name $TEST_NAME \
  --interactive
```

### Step 4: Run Verification Script

In Terminal 3, run the verification script:

```bash
python3 testing/test_monitoring_verification.py \
  --profile sec-watch-test \
  --region us-east-1 \
  --test-name $TEST_NAME \
  --state-dir state \
  --log-file security-watch.log \
  --interactive
```

## Verification Points

The verification script will guide you through checking each test scenario:

### Test 1: CloudTrail StopLogging

**What happens:**
- Test infrastructure script stops logging on the test trail

**What to verify:**
1. **State File Update**
   - Check: `state/<account-id>.json`
   - Location: `regions.<region>.cloudtrail.<trail-name>.is_logging`
   - Expected: `false`

2. **Log Entry**
   - Check: `security-watch.log`
   - Expected entry:
     ```json
     {
       "timestamp": "2025-01-17 12:34:56",
       "account_id": "XXXXXXXXXXXX",
       "region": "us-east-1",
       "service": "cloudtrail",
       "event_name": "StopLogging",
       "trail_name": "aws-security-guard-test-trail-TESTNAME"
     }
     ```

### Test 2: S3 Bucket Change

**What happens:**
- Test infrastructure script changes the S3 destination bucket

**What to verify:**
1. **State File Update**
   - Location: `regions.<region>.cloudtrail.<trail-name>.s3_bucket`
   - Expected: `aws-security-guard-test-bucket2-TESTNAME`

2. **Log Entry**
   - Expected event: `UpdateTrailS3Bucket`
   - Should include both previous and current bucket names

### Test 3: Event Selectors Change

**What happens:**
- Test infrastructure script updates event selectors

**What to verify:**
1. **State File Update**
   - Location: `regions.<region>.cloudtrail.<trail-name>.event_selectors`
   - Expected: Array with new selector configuration

2. **Log Entry**
   - Expected event: `UpdateEventSelectors`
   - Should include the new selector configuration

### Test 4: DeleteTrail

**What happens:**
- Test infrastructure script deletes the trail

**What to verify:**
1. **State File Update**
   - Check: Trail should be removed from state file
   - Location: `regions.<region>.cloudtrail` should NOT contain trail

2. **Log Entry**
   - Expected event: `DeleteTrail`
   - Should include trail name and ARN

## Manual Verification Steps

If you prefer manual verification or need to debug:

### Check State File Manually

```bash
# Pretty-print the state file
cat state/<account-id>.json | jq .

# Check specific region's CloudTrail state
cat state/<account-id>.json | jq '.regions["us-east-1"].cloudtrail'

# Check if trail exists in state
cat state/<account-id>.json | jq '.regions["us-east-1"].cloudtrail["aws-security-guard-test-trail-TESTNAME"]'
```

### Check Log File Manually

```bash
# View recent log entries
tail -20 security-watch.log

# Search for specific event
grep "StopLogging" security-watch.log | tail -1 | jq .

# Count events by type
cat security-watch.log | jq -r '.event_name' | sort | uniq -c
```

### Compare State Changes

```bash
# Before running a test, save current state
cp state/<account-id>.json state/before.json

# After monitoring detects change
cp state/<account-id>.json state/after.json

# Show differences
diff -u state/before.json state/after.json
```

## Troubleshooting

### State File Not Updating

**Symptoms:**
- State file timestamp doesn't change after monitoring cycle
- No changes detected even though infrastructure changed

**Possible Causes:**
1. Monitoring script not running
2. Change detected but not significant enough (check has_changes logic)
3. Multi-region trail tracked in wrong region (should be fixed now)

**Solutions:**
```bash
# Check monitoring script is running
ps aux | grep aws-security-guard.py

# Check monitoring script output for errors
# (should be visible in Terminal 1)

# Verify the trail's home region matches where you expect to see it
aws cloudtrail describe-trails --profile sec-watch-test | jq '.trailList[] | {name: .Name, homeRegion: .HomeRegion}'
```

### Log Entry Not Generated

**Symptoms:**
- State file updated but no log entry created
- Expected event not in log file

**Possible Causes:**
1. First run (changes not logged on first run)
2. Logger not working correctly
3. Event detection logic has a bug

**Solutions:**
```bash
# Check if this is first run
grep "First run" security-watch.log

# Verify logger is working
grep "ERROR" security-watch.log
grep "Permission" security-watch.log

# Check monitoring script detected the change
# (should see "Changes detected, updating state file..." in Terminal 1)
```

### Multi-Region Trail Issues

**Symptoms:**
- Same trail appears in multiple regions in state file
- Changes to trail not detected

**This should be FIXED** by the latest changes to `cloudtrail_monitor.py`. If you still see this:

```bash
# Check which regions have the trail
cat state/<account-id>.json | jq '.regions | to_entries[] | select(.value.cloudtrail != null and .value.cloudtrail != {}) | {region: .key, trails: (.value.cloudtrail | keys)}'

# Should only show trail in its home region now
# If not, verify you're running the updated code
```

## Testing Multiple Trails

To test that the system handles multiple trails correctly:

```bash
# Create two test trails in the same region
python3 testing/test_infrastructure.py \
  --profile sec-watch-test \
  --region us-east-1 \
  --test-name test1 \
  --interactive

# In another terminal
python3 testing/test_infrastructure.py \
  --profile sec-watch-test \
  --region us-east-1 \
  --test-name test2 \
  --interactive
```

Both trails should appear in the state file and changes to each should be detected independently.

## Advanced Testing Scenarios

### Testing Global Resources

For resources that should be tracked globally (not per-region):

1. Multi-region trails with `include_global_events: true`
   - Should appear ONLY in home region
   - Changes should be detected in home region only

### Testing Permission Errors

To verify permission error handling:

```bash
# Remove CloudTrail permissions temporarily
# (modify IAM policy)

# Run monitoring - should log permission error
# Check log for PermissionError entries
grep "PermissionError" security-watch.log | jq .
```

### Load Testing

To test with all regions and services:

```bash
# Run with default settings (all regions)
python3 aws-security-guard.py --profile sec-watch-test

# Monitor resource usage
top -p $(pgrep -f aws-security-guard.py)
```

## Expected Results

After completing all tests, you should have:

1. ✅ State file with correct trail configuration (only in home region)
2. ✅ Log entries for all 4 CloudTrail test events
3. ✅ No duplicate trails across regions
4. ✅ Consistent state between monitoring cycles
5. ✅ Clean monitoring script output with no errors

## Cleanup

After testing:

```bash
# Test infrastructure script should auto-cleanup
# But verify no test resources remain:

# Check for test trails
aws cloudtrail list-trails --profile sec-watch-test --region us-east-1 | grep "security-watch-test"

# Check for test buckets
aws s3 ls --profile sec-watch-test | grep "security-watch-test"

# Remove test state file
rm state/*.json

# Archive test logs
mv security-watch.log security-watch-test-$(date +%Y%m%d-%H%M%S).log
```

## Next Steps

After verifying CloudTrail monitoring works correctly:

1. Test GuardDuty monitoring (follow same process)
2. Test EventBridge monitoring (follow same process)
3. Test with multiple AWS accounts
4. Set up continuous monitoring in production
