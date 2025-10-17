# Changelog

## Latest Updates

### Test Script - Interactive Mode

Added interactive mode to the test infrastructure script for better control during testing:

**New flag:** `--interactive` or `-i`

**Behavior:**
- **Automated mode** (default): Automatically waits 2 minutes between each test step
- **Interactive mode** (`-i`): Waits for user to press Enter before proceeding to next step

**Benefits:**
- Full control over test timing
- Coordinate with monitoring tool in real-time
- Observe each change being detected before proceeding
- No more waiting for timers - proceed at your own pace

**Usage:**
```bash
# Interactive mode
python testing/test_infrastructure.py --profile myprofile -i

# Automated mode (default)
python testing/test_infrastructure.py --profile myprofile
```

**Improved Output:**
- Clear step-by-step progress indicators (✓)
- Better formatted output with section separators
- Informative messages at each stage

### EventBridge Monitoring - Specific Event Names

EventBridge rule changes now generate more specific event names instead of generic "UpdateRule":

- `DisableRule` - Rule was disabled (ENABLED → DISABLED)
- `EnableRule` - Rule was enabled (DISABLED → ENABLED)
- `ChangeRuleLogic` - Event pattern or schedule expression changed
- `ChangeRuleEventBus` - Rule moved to different event bus
- `ChangeRuleTargets` - Rule targets were modified
- `UpdateRuleDescription` - Rule description changed
- `ChangeRuleRole` - Rule execution role changed
- `DeleteRule` - Rule was deleted

**Note:** `PutRule` (new rule creation) is not monitored per requirements.

### GuardDuty Monitoring - Suspension Detection

Added new monitoring capabilities:

- `SuspendDetector` - Detects when GuardDuty detector status changes from ENABLED to DISABLED
- `UpdateDataSources` - Detects changes to GuardDuty data sources (suspension of specific monitoring)

**Removed:**
- `DeleteFilter` - Suppression rule deletions are no longer monitored

### CloudTrail Monitoring Updates

**Removed:**
- `StartLogging` - Starting logging is no longer monitored (only StopLogging is tracked)

### Parallel Execution

The monitoring tool now runs checks in parallel for significantly improved performance:

**Service-Level Parallelization:**
- All 3 services (CloudTrail, GuardDuty, EventBridge) are checked simultaneously within each region
- Uses ThreadPoolExecutor with 3 workers per region

**Region-Level Parallelization:**
- Multiple regions are processed in parallel
- Configurable with `--max-workers` argument (default: 10)
- Example: `--max-workers 20` for faster execution

**Performance Impact:**
- ~20+ regions × 3 services = 60+ API calls can now run concurrently
- Monitoring cycle time reduced from minutes to seconds
- Configurable to balance speed vs API rate limits

## Events Currently Monitored

### CloudTrail
- `StopLogging` - Trail logging stopped
- `DeleteTrail` - Trail deleted
- `UpdateTrailS3Bucket` - S3 destination changed
- `UpdateEventSelectors` - Event selectors modified

### GuardDuty
- `SuspendDetector` - Detector suspended (ENABLED → DISABLED)
- `UpdateDataSources` - Data sources changed/suspended
- `CreateFilter` - Suppression rule created
- `UpdateFilter` - Suppression rule modified
- `UpdateS3PublishingDestination` - S3 publishing destination changed
- `UpdatePublishingDestination` - Other publishing destination changed
- `DeleteDetector` - Detector deleted

### EventBridge
- `DisableRule` - Rule disabled
- `EnableRule` - Rule enabled
- `ChangeRuleLogic` - Event pattern or schedule changed
- `ChangeRuleEventBus` - Event bus changed
- `ChangeRuleTargets` - Targets changed
- `UpdateRuleDescription` - Description changed
- `ChangeRuleRole` - Execution role changed
- `DeleteRule` - Rule deleted
