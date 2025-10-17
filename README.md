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
    }
  ],
  "monitoring": {
    "interval_seconds": 120,
    "log_file": "security-watch.log",
    "state_directory": "state"
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

**Using environment variables (no arguments):**
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
python aws_security_watch.py
```

### Performance Notes

The tool runs checks in parallel to maximize performance:
- **Service-level parallelization**: All 3 services (CloudTrail, GuardDuty, EventBridge) are checked simultaneously in each region
- **Region-level parallelization**: Multiple regions are processed in parallel (configurable with `--max-workers`)
- Default setting of 10 parallel workers balances speed and API rate limits
- Increase `--max-workers` for faster execution if you have many regions and higher API limits

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
│       ├── cloudtrail_monitor.py
│       ├── guardduty_monitor.py
│       └── eventbridge_monitor.py
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
