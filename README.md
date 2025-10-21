# AWS Security Watch

A Python-based monitoring tool that tracks configuration changes across AWS security services and generates CloudTrail-style logs.

## Features

Monitors the following AWS services across all regions:

### CloudTrail
- Trail logging status (StopLogging/StartLogging)
- Trail deletion
- S3 destination changes
- Event selector modifications

### GuardDuty
- Detector deletion
- Suppression rule creation, modification, and deletion
- Publishing destination changes (S3, CloudWatch)

### EventBridge
- Rule creation, modification, and deletion
- Rule state changes (enabled/disabled)
- Event pattern and schedule changes
- Target modifications

### S3 (CloudTrail Buckets)
- Bucket deletion
- Bucket size reductions greater than 50%
- Encryption changes:
  - Adding encryption to unencrypted buckets
  - Modifying encryption settings (e.g., AES256 to KMS)
  - Does NOT log encryption removal
- Event notification configuration changes:
  - Filter prefix/suffix changes
  - Event type changes
  - Destination changes (SQS, SNS, Lambda)

### SQS (S3 Event Destinations)
- Queue deletion
- Encryption setting changes
- Access policy changes
- Lambda event source mapping changes (triggers)

### SNS (CloudTrail Ecosystem Topics)
- Topic deletion
- Subscription changes (update, delete)
- Access policy changes
- Encryption changes:
  - Adding encryption to unencrypted topics
  - Modifying encryption settings (e.g., changing KMS key)
  - Does NOT log encryption removal

### Lambda (CloudTrail Ecosystem Functions)
- Function deletion
- Code changes (CodeSha256)
- Runtime changes
- Configuration changes (memory, timeout)
- Execution role changes
- Environment variable changes
- VPC configuration changes
- Layer changes

### IAM (Roles in CloudTrail Ecosystem)
- Role deletion
- Trust policy (AssumeRole) changes
- Managed policy attachment/detachment
- Inline policy changes (create, update, delete)
- Role description changes
- Max session duration changes

## Requirements

- Python 3.7+
- boto3
- AWS credentials with appropriate permissions

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd aws-security-watch
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Create configuration file for multi-account monitoring:
```bash
cp config.example.json config.json
```

4. (Optional) Edit `config.json` with your AWS credentials and accounts:
```json
{
  "credentials": {
    "access_key_id": "YOUR_ACCESS_KEY_ID",
    "secret_access_key": "YOUR_SECRET_ACCESS_KEY"
  },
  "accounts": [
    {
      "account_id": "123456789012",
      "role_arn": "arn:aws:iam::123456789012:role/SecurityMonitorRole",
      "name": "production"
    },
    {
      "account_id": "210987654321",
      "role_arn": "arn:aws:iam::210987654321:role/SecurityMonitorRole",
      "name": "staging",
      "monitors": ["cloudtrail", "guardduty", "eventbridge"]
    }
  ],
  "monitoring": {
    "interval_seconds": 120,
    "log_file": "security-watch.log",
    "state_directory": "state",
    "enabled_monitors": ["cloudtrail", "guardduty", "eventbridge", "s3", "sqs", "sns", "lambda", "iam"]
  }
}
```

**Note:** Configuration file is optional. You can run the tool using AWS profiles or environment variables without a config file.

## Configuration

### Credentials

The tool supports multiple credential sources in the following priority:

1. **AWS profile** - Specified via `--profile` command-line argument
2. **Config file credentials** - Specified in config file (if provided)
3. **Environment variables** - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
4. **AWS credentials file** - `~/.aws/credentials`

### Multi-Account Monitoring

To monitor multiple AWS accounts, configure cross-account roles:

1. Create an IAM role in each target account with the monitoring policy
2. Add a trust relationship allowing your base account to assume the role
3. Add accounts to `config.json` with their `role_arn`

### Monitoring Configuration

Configuration can be set via command-line arguments or config file (command-line args take priority):

- `interval_seconds` / `--interval`: How often to check for changes (default: 120)
- `log_file` / `--log-file`: Path to output log file (default: security-watch.log)
- `state_directory` / `--state-dir`: Directory to store state files (default: state)

### Monitor Selection

You can control which monitors run for each account:

**Global Monitor Selection:**
Set `enabled_monitors` in the `monitoring` section to specify default monitors for all accounts:
```json
"monitoring": {
  "enabled_monitors": ["cloudtrail", "guardduty", "eventbridge"]
}
```

**Per-Account Monitor Selection:**
Override the global setting by adding a `monitors` array to specific accounts:
```json
{
  "account_id": "123456789012",
  "name": "production",
  "monitors": ["cloudtrail", "guardduty"]
}
```

**Available Monitors:**
- `cloudtrail` - CloudTrail trail configuration monitoring
- `guardduty` - GuardDuty detector and rule monitoring
- `eventbridge` - EventBridge rule monitoring
- `s3` - S3 bucket monitoring (for CloudTrail buckets)
- `sqs` - SQS queue monitoring (for S3 event destinations)
- `sns` - SNS topic monitoring (for CloudTrail ecosystem)
- `lambda` - Lambda function monitoring (for CloudTrail ecosystem)
- `iam` - IAM role monitoring (for roles used in CloudTrail ecosystem)

**Default Behavior:**
- If no configuration is provided, all monitors are enabled
- Per-account settings override global settings
- If an account has no `monitors` specified, it uses the global `enabled_monitors`
- If neither is specified, all 8 monitors run by default

## Usage

### Command-Line Arguments

```bash
python aws_security_watch.py [OPTIONS]

Options:
  --profile PROFILE        AWS profile name to use
  --config CONFIG          Path to configuration file (optional)
  --interval SECONDS       Monitoring interval in seconds (default: 120)
  --log-file PATH          Path to log file (default: security-watch.log)
  --state-dir PATH         Directory to store state files (default: state)
  --max-workers NUM        Maximum parallel region workers (default: 10)
  --verbose, -v            Enable verbose logging of AWS API calls
```

### Usage Examples

**Simple usage with AWS profile:**
```bash
python aws_security_watch.py --profile myprofile
```

**With custom monitoring interval:**
```bash
python aws_security_watch.py --profile myprofile --interval 300
```

**With configuration file for multi-account monitoring:**
```bash
python aws_security_watch.py --config config.json
```

**Using AWS profile with custom config file:**
```bash
python aws_security_watch.py --profile myprofile --config config.json
```

**All custom settings:**
```bash
python aws_security_watch.py --profile myprofile --interval 180 --log-file custom.log --state-dir custom-state
```

**With increased parallelization (faster for many regions):**
```bash
python aws_security_watch.py --profile myprofile --max-workers 20
```

**With verbose AWS API logging (for debugging):**
```bash
python aws_security_watch.py --profile myprofile --verbose
```

**Using environment variables (no arguments):**
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
python aws_security_watch.py
```

### Performance Notes

The tool runs checks in parallel to maximize performance:
- **Region-level parallelization**: Multiple regions are processed in parallel (configurable with `--max-workers`)
- **Service-level execution**: Within each region, services run sequentially in dependency order to ensure fresh data:
  - **Tier 1** (parallel): CloudTrail, GuardDuty, EventBridge
  - **Tier 2**: S3 (depends on CloudTrail)
  - **Tier 3**: SQS (depends on S3)
  - **Tier 4**: SNS (depends on S3, SQS)
  - **Tier 5**: Lambda (depends on S3, SQS, SNS)
  - **Tier 6**: IAM (depends on Lambda)
- Default setting of 10 parallel region workers balances speed and API rate limits
- Increase `--max-workers` for faster execution if you have many regions and higher API limits

**Why Sequential Execution Within Regions:**
Services like S3, SQS, SNS, Lambda, and IAM discover resources from upstream services. Sequential execution ensures each monitor sees the current (just-scanned) state rather than stale data from the previous run. This eliminates race conditions where deleted resources are queried.

**Note on IAM Monitoring:**
- IAM is a global service, so IAM role monitoring only occurs in the `us-east-1` region to avoid duplicate checks
- IAM roles are discovered from Lambda functions and other services in the CloudTrail ecosystem
- Only roles that are actively used by monitored resources are tracked

### Verbose Mode

Enable verbose mode with `--verbose` or `-v` to see all AWS API calls being made:

```bash
python aws_security_watch.py --profile myprofile --verbose
```

This will output detailed logs showing:
- Service name and operation (e.g., `s3.GetBucketEncryption`)
- Region where the call is made
- Key parameters being passed (bucket names, queue URLs, etc.)

Example output:
```
[API] ec2.DescribeRegions (region=us-east-1)
[API] cloudtrail.DescribeTrails (region=us-east-1)
[API] s3.GetBucketLocation (region=us-east-1) [Bucket=my-cloudtrail-bucket]
[API] guardduty.ListDetectors (region=us-east-1)
```

Verbose mode is useful for:
- Debugging permission issues
- Understanding which AWS APIs are being called
- Troubleshooting monitor behavior
- Verifying API rate limiting concerns

### How It Works

The tool will:
1. Establish baseline state on first run (no logs generated)
2. Check all configured services every 2 minutes (or configured interval)
3. Generate CloudTrail-style logs for any detected changes
4. Continue monitoring until stopped with Ctrl+C

## Log Format

Logs are written in CloudTrail-compatible JSON format:

```json
{
  "eventTime": "2025-10-17T08:00:00Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "UpdateTrailS3Bucket",
  "awsRegion": "us-east-1",
  "responseElements": {
    "trailName": "my-trail",
    "previousS3Bucket": "old-bucket",
    "currentS3Bucket": "new-bucket"
  },
  "eventID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "readOnly": false,
  "eventType": "AWSSecurityWatch",
  "recipientAccountId": "123456789012"
}
```

## IAM Permissions

### Monitoring Policy

Attach the `iam-policies/monitoring-policy.json` to your IAM user or role. This grants read-only access to:
- CloudTrail trail configurations
- GuardDuty detectors and rules
- EventBridge rules
- S3 buckets (for CloudTrail destinations)
- SQS queues (for S3 event notifications)
- SNS topics (for CloudTrail ecosystem)
- Lambda functions (for CloudTrail ecosystem)
- IAM roles (for roles used by monitored resources)
- EC2 region listing
- STS for cross-account access

### Testing Policy

For running the test suite, attach `iam-policies/testing-policy.json` which includes:
- Full management of test resources
- CloudTrail, GuardDuty, and EventBridge write permissions
- S3 bucket creation and deletion

## Testing

A test script is provided to validate the monitoring functionality.

### Command-Line Arguments

```bash
python testing/test_infrastructure.py [OPTIONS]

Options:
  --profile PROFILE        AWS profile name to use
  --region REGION          AWS region to test in (default: us-east-1)
  --test-name NAME         Test name (auto-generated if not provided)
  --interactive, -i        Interactive mode: press Enter to proceed instead of waiting
```

### Usage Examples

**Simple usage (auto-generated test name):**
```bash
python testing/test_infrastructure.py
```

**With AWS profile:**
```bash
python testing/test_infrastructure.py --profile myprofile
```

**Interactive mode (recommended for testing):**
```bash
python testing/test_infrastructure.py --profile myprofile --interactive
```

**With specific region and test name:**
```bash
python testing/test_infrastructure.py --profile myprofile --region us-west-2 --test-name mytest123 -i
```

### What It Does

The test script will:
1. Create test resources (trails, detectors, rules) with `aws-security-watch-test-*` prefix
2. Modify configurations
3. Delete resources
4. Clean up all created resources

**Modes:**
- **Automated mode** (default): Waits 2 minutes between each step automatically
- **Interactive mode** (`--interactive` or `-i`): Waits for you to press Enter before each step, giving you control over timing

Run the monitoring tool alongside the test script to verify change detection.

**Recommended workflow:**
1. Start the monitoring tool: `python aws_security_watch.py --profile myprofile --interval 60`
2. In another terminal, run the test script in interactive mode: `python testing/test_infrastructure.py --profile myprofile -i`
3. Watch the monitoring tool detect each change in real-time
4. Press Enter in the test script terminal to proceed to the next change

## Project Structure

```
aws-security-watch/
├── aws_security_watch.py       # Main script
├── config.example.json         # Example configuration
├── requirements.txt            # Python dependencies
├── src/
│   ├── credentials.py         # AWS credential management
│   ├── state_manager.py       # State persistence
│   ├── logger.py              # CloudTrail-style logging
│   └── monitors/
│       ├── cloudtrail_monitor.py  # CloudTrail trail monitoring
│       ├── guardduty_monitor.py   # GuardDuty detector monitoring
│       ├── eventbridge_monitor.py # EventBridge rule monitoring
│       ├── s3_monitor.py          # S3 bucket monitoring
│       ├── sqs_monitor.py         # SQS queue monitoring
│       ├── sns_monitor.py         # SNS topic monitoring
│       ├── lambda_monitor.py      # Lambda function monitoring
│       └── iam_monitor.py         # IAM role monitoring
├── iam-policies/
│   ├── monitoring-policy.json # Read-only monitoring permissions
│   └── testing-policy.json    # Testing permissions
└── testing/
    └── test_infrastructure.py # Test suite
```

## Troubleshooting

### Permission Errors

If you see `AccessDenied` errors in logs:
1. Verify IAM policies are correctly attached
2. Check cross-account role trust relationships
3. Ensure credentials are valid and not expired

### No Changes Detected

- First run establishes baseline - no logs generated
- Wait for monitoring interval to complete
- Verify changes are being made in monitored regions
- Check state files in the state directory

### State Files

State files are stored per account in the `state/` directory:
- `{account-id}.json` - Contains last known configuration

To reset monitoring (re-establish baseline), delete state files.

## License

See LICENSE file for details.
