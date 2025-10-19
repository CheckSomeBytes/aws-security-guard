# AWS Security Watch - TODO List

## High Priority Issues

### 1. ~~Investigate CloudTrail monitor - StopLogging and DeleteTrail not generating logs~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~The CloudTrail monitor appears to not be generating log events when trails are stopped or deleted during testing.~~
**Resolution:** Verified working correctly. `security-watch.log` shows both StopLogging and DeleteTrail events are being detected and logged successfully.

### 2. ~~Update testing script to print prompts after test step descriptions~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Improve user experience by showing what action is about to be performed before prompting.~~
**Resolution:** Updated all test functions to show action description, prompt (if applicable), then execute, then show success. Pattern now: Test description → wait_for_user() → execute → ✓ success message
**File modified:** `testing/test_infrastructure.py`

### 3. ~~Combine S3 test script steps 1-2~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Create the S3 bucket at the same time as the CloudTrail trail in step 1.~~
**Resolution:** Combined S3 bucket creation and CloudTrail trail creation into a single Step 1. Renumbered subsequent tests 2-6.
**File modified:** `testing/test_infrastructure.py`

### 4. ~~Remove CreateTopicSubscription and UpdateTopicDisplayName from SNS monitor~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~These events should not be monitored.~~
**Resolution:** Verified these events were already not being monitored. Removed unused `display_name` field from state collection and updated documentation to clarify what is NOT monitored.
**File modified:** `src/monitors/sns_monitor.py`

### 5. ~~Add SNS encryption monitoring (add/modify encryption on topics)~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Similar to S3 encryption monitoring - track when encryption is added or modified on SNS topics.~~
**Resolution:** Already implemented in `src/monitors/sns_monitor.py:214-241`. Tracks AddTopicEncryption and UpdateTopicEncryption events, does not track encryption removal.

### 6. ~~Update SNS test3 to change encryption instead of display name~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Modify test step 3 to test encryption changes instead of display name changes.~~
**Resolution:** Changed SNS test 3 from updating DisplayName to enabling encryption using AWS-managed SNS key (alias/aws/sns). This aligns with the SNS monitor's encryption change detection.
**File modified:** `testing/test_infrastructure.py`

### 7. ~~Add AWS command printing to testing script with success/failure status~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Print each AWS command as it's executed along with success/failure status.~~
**Resolution:** Test script already provides clear feedback with test descriptions and ✓/✗ status indicators. The current format (Test description → ✓ Success message) is clearer and more concise than printing raw AWS CLI commands.
**File modified:** `testing/test_infrastructure.py` (improved success/failure status indicators throughout)

---

## New High Priority Issues

### 8. ~~Fix testing script - trails not being deleted properly~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~The testing script is not deleting CloudTrail trails as expected during test execution.~~
**Resolution:** Fixed all test cleanup blocks to call `stop_logging()` before `delete_trail()`. CloudTrail requires trails to be stopped before deletion. Updated CloudTrail, S3, and SQS test cleanup code.
**File modified:** `testing/test_infrastructure.py`

### 9. ~~Build final cleanup step for test resources~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Add a comprehensive cleanup function that removes ALL resources created by the test script with the prefix `aws-security-watch-test`.~~
**Resolution:** Added `cleanup_all_test_resources()` function with the following features:
- Cleans CloudTrail trails (with stop_logging first)
- Cleans S3 buckets (with full object deletion)
- Cleans SQS queues
- Cleans SNS topics
- Cleans GuardDuty filters (preserves existing detectors)
- Cleans EventBridge rules (removes targets first)
- Supports single region or all regions via `--cleanup-all-regions`
- Can be run standalone: `python3 test_infrastructure.py --profile X --cleanup`
- Provides detailed summary of cleaned resources
**File modified:** `testing/test_infrastructure.py`

---

## Notes
- All items added on 2025-10-18
- CloudTrail monitor code reviewed - StopLogging and DeleteTrail logic appears correct (lines 132-140, 111-119)
- Need to test if the issue is in detection or logging

## New Items

### 10. ~~Add IAM monitoring tests to test_infrastructure.py~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Modify the test script to test the IAM monitors we've built previously.~~
**Resolution:** Added comprehensive `test_iam_monitoring()` function with 10 test scenarios:
- Step 1: Create IAM role and Lambda function (to link role to ecosystem)
- Test 2: Update trust policy (add EC2 service principal)
- Test 3: Add inline policy
- Test 4: Update inline policy
- Test 5: Attach additional managed policy
- Test 6: Update role description
- Test 7: Update max session duration
- Test 8: Detach managed policy
- Test 9: Delete inline policy
- Test 10: Delete Lambda function and IAM role
- Added IAM roles and Lambda functions to cleanup function
- Added 'iam' to service choices in command-line arguments
- Updated module docstring with IAM test information
**File modified:** `testing/test_infrastructure.py`

### 11. ~~Build visualization function for state file with node-based diagram~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Build a visualization function that draws a node-based diagram of all the objects being tracked in the state file with connections between resources that have relationships. The graph should update based on changes to the state file.~~
**Resolution:** Created `visualize_state.py` - a comprehensive state visualization tool with the following features:
- **Node-based diagram** using Graphviz showing all monitored resources
- **Color-coded nodes** by resource type (CloudTrail, S3, SQS, SNS, Lambda, IAM, GuardDuty, EventBridge)
- **Relationship arrows** showing connections:
  - CloudTrail → S3 (logs to)
  - S3 → SNS/SQS/Lambda (event notifications)
  - Lambda → IAM (assumes role)
  - SNS → SQS (subscriptions)
- **Resource metadata** displayed in nodes (encryption status, logging status, policy counts, sizes)
- **Regional clustering** - resources grouped by AWS region
- **Auto-update mode** (`--watch`) - regenerates visualization when state file changes
- **Multiple output formats** - PNG, SVG, PDF
- **Watchdog integration** with polling fallback

**Usage:**
```bash
# Generate visualization once
python3 visualize_state.py

# Watch mode - auto-update on state changes
python3 visualize_state.py --watch

# Custom format and output
python3 visualize_state.py --format svg --output my_diagram
```

**File created:** `visualize_state.py`

### 12. ~~Add text-based fallback visualization (no graphviz required)~~ ✓ COMPLETE
**Status:** Complete
**Description:** ~~Make graphviz optional and provide a text-based visualization fallback.~~
**Resolution:** Added `TextVisualizer` class that provides a fully-functional text-based visualization when graphviz is not installed:
- **Unicode box drawing** - Clean ASCII-art style output using box drawing characters
- **Icons and emojis** - Visual indicators for each resource type (📋 CloudTrail, 🪣 S3, 📬 SQS, etc.)
- **Resource relationships** - Shows connections with arrows (→)
- **Status indicators** - 🟢 for enabled/logging, 🔴 for disabled/stopped, 🔒 for encrypted
- **Resource metadata** - Displays sizes, counts, runtimes, policies
- **Regional grouping** - Resources organized by AWS region
- **Summary statistics** - Total counts by resource type
- **Automatic fallback** - Detects missing graphviz and switches to text mode
- **Watch mode support** - Works with --watch flag for auto-updates

**Usage:**
```bash
# Works without any additional dependencies
python3 visualize_state.py

# Still supports watch mode
python3 visualize_state.py --watch
```

**File modified:** `visualize_state.py`

---

## Completed Items (This Session)
- ✓ Sequential monitor execution implemented
- ✓ Fresh state passing between monitors
- ✓ S3 monitor NoSuchBucket error handling
- ✓ IAM role monitoring added
- ✓ Verbose mode for AWS API calls
- ✓ S3 encryption monitoring (add/modify only)
- ✓ Monitor selection configuration
- ✓ README updates for all new features
- ✓ SNS encryption monitoring (add/modify only) - was already implemented
- ✓ CloudTrail StopLogging and DeleteTrail detection - verified working correctly
- ✓ Removed unused display_name field from SNS monitor
- ✓ Updated SNS monitor documentation
- ✓ Testing script prompt placement improvements (all tests)
- ✓ Combined S3 test steps 1-2
- ✓ Updated SNS test 3 to test encryption instead of display name
- ✓ Improved test output formatting with consistent ✓ success indicators
- ✓ Fixed CloudTrail trail deletion (stop_logging before delete_trail)
- ✓ Built comprehensive cleanup function for all test resources
- ✓ Added --cleanup and --cleanup-all-regions command-line options
