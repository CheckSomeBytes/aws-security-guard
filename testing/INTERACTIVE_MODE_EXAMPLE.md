# Interactive Mode Example

## Running the Test Script in Interactive Mode

### Command
```bash
python testing/test_infrastructure.py --profile myprofile --interactive
```

### Example Output

```
No test name provided, using generated name: a7x9k2m1

AWS Security Guard Test Suite
==================================================
Using AWS profile: myprofile
Test Name: a7x9k2m1
Region: us-east-1
Mode: Interactive (press Enter to proceed)
==================================================


=== Testing CloudTrail in us-east-1 ===
Created S3 bucket: aws-security-guard-test-bucket1-a7x9k2m1
Created S3 bucket: aws-security-guard-test-bucket2-a7x9k2m1
Creating trail: aws-security-guard-test-trail-a7x9k2m1
Started logging for trail: aws-security-guard-test-trail-a7x9k2m1

Trail created and logging started.
Press Enter to continue...
[User presses Enter]

Test 1: Stopping logging...
✓ Logging stopped
Press Enter to continue...
[User presses Enter]

Restarting logging...
✓ Logging restarted
Press Enter to continue...
[User presses Enter]

Test 2: Changing S3 destination...
✓ S3 destination changed to aws-security-guard-test-bucket2-a7x9k2m1
Press Enter to continue...
[User presses Enter]

Test 3: Updating event selectors...
✓ Event selectors updated
Press Enter to continue...
[User presses Enter]

Test 4: Deleting trail...
✓ Trail deleted
Cleaning up CloudTrail resources...
Deleted S3 bucket: aws-security-guard-test-bucket1-a7x9k2m1
Deleted S3 bucket: aws-security-guard-test-bucket2-a7x9k2m1


=== Testing GuardDuty in us-east-1 ===
Creating GuardDuty detector...
✓ Created detector: 12345abcdef67890
Detector created.
Press Enter to continue...
[User presses Enter]

Test 1: Creating suppression rule...
✓ Suppression rule created: aws-security-guard-test-filter-a7x9k2m1
Press Enter to continue...
[User presses Enter]

Test 2: Updating suppression rule...
✓ Suppression rule updated
Press Enter to continue...
[User presses Enter]

Test 3: Deleting suppression rule...
✓ Suppression rule deleted
Press Enter to continue...
[User presses Enter]

Cleaning up GuardDuty resources...
Deleted detector: 12345abcdef67890


=== Testing EventBridge in us-east-1 ===
Test 1: Creating EventBridge rule...
✓ EventBridge rule created: aws-security-guard-test-rule-a7x9k2m1
Rule created.
Press Enter to continue...
[User presses Enter]

Test 2: Disabling EventBridge rule...
✓ Rule disabled
Press Enter to continue...
[User presses Enter]

Test 3: Updating EventBridge rule pattern...
✓ Rule pattern updated and re-enabled
Press Enter to continue...
[User presses Enter]

Test 4: Deleting EventBridge rule...
✓ Rule deleted
Cleaning up EventBridge resources...

==================================================
=== All tests completed ===
==================================================
```

## Recommended Workflow

### Terminal 1: Start Monitoring Tool
```bash
python aws-security-guard.py --profile myprofile --interval 60 --max-workers 5
```

Output:
```
AWS Security Watch started
Using AWS profile: myprofile
Monitoring interval: 60 seconds
Log file: security-watch.log
State directory: state
Max parallel workers: 5

Monitoring 1 account(s)

--- Monitoring account: default (123456789012) ---
First run for account 123456789012 - establishing baseline state
Monitoring 20 regions for account 123456789012
  ✓ cloudtrail in us-east-1
  ✓ guardduty in us-east-1
  ✓ eventbridge in us-east-1
...
```

### Terminal 2: Run Tests Interactively
```bash
python testing/test_infrastructure.py --profile myprofile -i
```

### Steps:
1. Wait for the monitoring tool to complete its first baseline run
2. Press Enter in Terminal 2 to create the first test resource
3. Wait 60 seconds (or one monitoring cycle) in Terminal 1
4. Observe the monitoring tool detect the change
5. Check the log file: `tail -f security-watch.log`
6. Press Enter in Terminal 2 to proceed to the next test
7. Repeat steps 3-6 for each test

### Benefits:
- **Full control**: Proceed at your own pace
- **Real-time validation**: See each change detected immediately
- **Easy debugging**: If a change isn't detected, investigate before proceeding
- **Educational**: Understand exactly what triggers each event
- **No wasted time**: No waiting for long automated delays
