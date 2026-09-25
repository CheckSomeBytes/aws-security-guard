#!/usr/bin/env python3
"""
AWS Security Watch

Monitors AWS security service configurations and logs changes:
- CloudTrail
- GuardDuty
- EventBridge
- S3 (CloudTrail buckets)
- SQS (S3 event destinations)
- SNS (CloudTrail ecosystem topics)
- Lambda (CloudTrail ecosystem functions)
- IAM (Roles used in CloudTrail ecosystem)
"""

import time
import boto3
from typing import Dict, Any, List, Optional
from pathlib import Path
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

import credentials
import state_manager
import logger
import error_tracker as error_tracker_module
from monitors import cloudtrail_monitor, guardduty_monitor, eventbridge_monitor, s3_monitor, sqs_monitor, sns_monitor, lambda_monitor, iam_monitor


def get_all_regions(session: boto3.Session) -> List[str]:
    """
    Get all available AWS regions

    Args:
        session: boto3 session

    Returns:
        List of region names
    """
    ec2_client = session.client('ec2', region_name='us-east-1')
    response = ec2_client.describe_regions(AllRegions=False)
    return [region['RegionName'] for region in response['Regions']]


def monitor_service_in_region(
    service_name: str,
    monitor_module,
    session: boto3.Session,
    account_id: str,
    region: str,
    state_directory: str,
    log_file: str,
    is_first_run: bool,
    log_function,
    state_file_data: Optional[Dict[str, Any]] = None,
    error_tracker: Optional[error_tracker_module.ErrorTracker] = None
) -> Dict[str, Any]:
    """
    Monitor a single service in a single region

    Args:
        service_name: Name of the service (cloudtrail, guardduty, eventbridge, s3, etc.)
        monitor_module: The monitoring module to use
        session: boto3 session with appropriate credentials
        account_id: AWS account ID
        region: AWS region
        state_directory: Directory for state files
        log_file: Path to log file
        is_first_run: Whether this is the first run for this account
        log_function: Logging function for this service
        state_file_data: Complete state file data for resource discovery
        error_tracker: ErrorTracker instance for collecting API failures

    Returns:
        Dictionary with service name, status, current state, and any changes
    """
    try:
        # Check if monitor supports state_file_data and error_tracker parameters
        import inspect
        sig = inspect.signature(monitor_module.get_current_state)

        # Build kwargs based on what the monitor supports
        kwargs = {}
        if 'state_file_data' in sig.parameters:
            kwargs['state_file_data'] = state_file_data
        if 'error_tracker' in sig.parameters:
            kwargs['error_tracker'] = error_tracker

        current_state = monitor_module.get_current_state(session, region, **kwargs)

        previous_state = state_manager.get_service_state(
            state_directory, account_id, service_name, region
        )

        changes = []
        state_changed = False

        if not is_first_run:
            changes = monitor_module.detect_changes(previous_state, current_state)
            for change in changes:
                # Determine the data key based on service
                if service_name == 'cloudtrail':
                    data_key = 'trail_data'
                elif service_name == 'guardduty':
                    data_key = 'guardduty_data'
                elif service_name == 'eventbridge':
                    data_key = 'rule_data'
                elif service_name == 's3':
                    data_key = 's3_data'
                elif service_name == 'sqs':
                    data_key = 'sqs_data'
                elif service_name == 'sns':
                    data_key = 'sns_data'
                elif service_name == 'lambda':
                    data_key = 'lambda_data'
                elif service_name == 'iam':
                    data_key = 'iam_data'
                else:
                    # Default to service_name + '_data' for future services
                    data_key = f'{service_name}_data'

                log_function(
                    log_file,
                    account_id,
                    region,
                    change['event_name'],
                    change[data_key]
                )

            # Check if state has changed (including new resources added)
            # even if they weren't logged as changes
            state_changed = current_state != previous_state

        return {
            'service': service_name,
            'region': region,
            'status': 'success',
            'current_state': current_state,
            'has_changes': state_changed or is_first_run
        }

    except PermissionError as e:
        # Track the error for consolidated reporting in MonitoringAPIFailure log
        # Don't log individual permission errors - they'll be included in the summary
        if error_tracker:
            error_tracker.add_error(
                service=service_name,
                region=region,
                error_code='AccessDenied',
                error_message=str(e)
            )
        return {'service': service_name, 'region': region, 'status': 'permission_error', 'error': str(e), 'has_changes': False}
    except Exception as e:
        print(f"Error monitoring {service_name} in {region}: {str(e)}")
        # Track non-permission errors too
        if error_tracker:
            error_tracker.add_error(
                service=service_name,
                region=region,
                error_code='UnknownError',
                error_message=str(e)
            )
        return {'service': service_name, 'region': region, 'status': 'error', 'error': str(e), 'has_changes': False}


def get_enabled_monitors(account: Dict[str, Any], config: Dict[str, Any]) -> List[str]:
    """
    Get the list of enabled monitors for an account

    Args:
        account: Account configuration dictionary
        config: Global configuration dictionary

    Returns:
        List of enabled monitor names
    """
    # Check if account has specific monitors configured
    if 'monitors' in account:
        return account['monitors']

    # Check if global enabled_monitors is configured
    monitoring_config = config.get('monitoring', {})
    if 'enabled_monitors' in monitoring_config:
        return monitoring_config['enabled_monitors']

    # Default to all monitors
    return ['cloudtrail', 'guardduty', 'eventbridge', 's3', 'sqs', 'sns', 'lambda', 'iam']


def monitor_account_region(
    session: boto3.Session,
    account_id: str,
    region: str,
    state_directory: str,
    log_file: str,
    is_first_run: bool,
    enabled_monitors: List[str],
    error_tracker: Optional[error_tracker_module.ErrorTracker] = None
) -> Dict[str, Any]:
    """
    Monitor a single account in a single region (services run sequentially in dependency order)

    Args:
        session: boto3 session with appropriate credentials
        account_id: AWS account ID
        region: AWS region
        state_directory: Directory for state files
        log_file: Path to log file
        is_first_run: Whether this is the first run for this account
        enabled_monitors: List of monitor names to run
        error_tracker: ErrorTracker instance for collecting API failures

    Returns:
        Dictionary with region and collected service states
    """
    # Load old state file for comparison
    old_state_file_data = state_manager.load_state(state_directory, account_id) or {'regions': {}}

    # Create fresh state that accumulates current state as we scan
    # For cross-region dependencies (like IAM), we include old state from other regions
    # but use fresh state for the current region
    fresh_state_file_data = {'regions': old_state_file_data.get('regions', {}).copy()}
    if region not in fresh_state_file_data['regions']:
        fresh_state_file_data['regions'][region] = {}
    else:
        # Clear out current region's old data - we'll populate with fresh data
        fresh_state_file_data['regions'][region] = {}

    # Define all available services with dependencies
    # Services are organized in tiers based on dependencies
    all_services = {
        # Tier 1: No dependencies (can run in parallel)
        'tier1': [
            ('cloudtrail', cloudtrail_monitor, logger.log_cloudtrail_change),
            ('guardduty', guardduty_monitor, logger.log_guardduty_change),
            ('eventbridge', eventbridge_monitor, logger.log_eventbridge_change),
        ],
        # Tier 2: Depends on CloudTrail
        'tier2': [
            ('s3', s3_monitor, logger.log_s3_change),
        ],
        # Tier 3: Depends on S3
        'tier3': [
            ('sqs', sqs_monitor, logger.log_sqs_change),
        ],
        # Tier 4: Depends on S3 and SQS
        'tier4': [
            ('sns', sns_monitor, logger.log_sns_change),
        ],
        # Tier 5: Depends on S3, SQS, SNS
        'tier5': [
            ('lambda', lambda_monitor, logger.log_lambda_change),
        ],
        # Tier 6: Depends on Lambda
        'tier6': [
            ('iam', iam_monitor, logger.log_iam_change),
        ],
    }

    service_results = []

    # Process each tier sequentially
    for tier_name in ['tier1', 'tier2', 'tier3', 'tier4', 'tier5', 'tier6']:
        tier_services = all_services[tier_name]

        # Filter services based on enabled_monitors
        enabled_tier_services = [
            (name, module, log_func)
            for name, module, log_func in tier_services
            if name in enabled_monitors
        ]

        if not enabled_tier_services:
            continue

        # Tier 1 can run in parallel, others run sequentially
        if tier_name == 'tier1':
            # Run tier 1 services in parallel
            with ThreadPoolExecutor(max_workers=len(enabled_tier_services)) as executor:
                futures = []
                for service_name, monitor_module, log_function in enabled_tier_services:
                    future = executor.submit(
                        monitor_service_in_region,
                        service_name,
                        monitor_module,
                        session,
                        account_id,
                        region,
                        state_directory,
                        log_file,
                        is_first_run,
                        log_function,
                        fresh_state_file_data,  # Pass fresh state (empty for tier 1)
                        error_tracker  # Pass error tracker
                    )
                    futures.append(future)

                # Collect results
                for future in as_completed(futures):
                    result = future.result()
                    service_results.append(result)

                    # Only add current state to fresh_state for successful monitors
                    # Do NOT add state for permission_error or error status
                    if result['status'] == 'success' and 'current_state' in result:
                        fresh_state_file_data['regions'][region][result['service']] = result['current_state']

                    if result['status'] == 'success':
                        print(f"  ✓ {result['service']} in {region}")
                    elif result['status'] == 'permission_error':
                        print(f"  ✗ {result['service']} in {region}: Permission denied")
                    else:
                        print(f"  ✗ {result['service']} in {region}: Error")
        else:
            # Run other tiers sequentially
            for service_name, monitor_module, log_function in enabled_tier_services:
                result = monitor_service_in_region(
                    service_name,
                    monitor_module,
                    session,
                    account_id,
                    region,
                    state_directory,
                    log_file,
                    is_first_run,
                    log_function,
                    fresh_state_file_data,  # Pass accumulated fresh state
                    error_tracker  # Pass error tracker
                )
                service_results.append(result)

                # Only add current state to fresh_state for successful monitors
                # Do NOT add state for permission_error or error status
                if result['status'] == 'success' and 'current_state' in result:
                    fresh_state_file_data['regions'][region][result['service']] = result['current_state']

                if result['status'] == 'success':
                    print(f"  ✓ {result['service']} in {region}")
                elif result['status'] == 'permission_error':
                    print(f"  ✗ {result['service']} in {region}: Permission denied")
                else:
                    print(f"  ✗ {result['service']} in {region}: Error")

    return {
        'region': region,
        'service_results': service_results
    }


def monitor_account(
    session: boto3.Session,
    account_id: str,
    state_directory: str,
    log_file: str,
    enabled_monitors: List[str],
    max_workers: int = 10,
    specific_region: Optional[str] = None
) -> None:
    """
    Monitor all regions in an account (parallel regions, batch state updates)

    Args:
        session: boto3 session with appropriate credentials
        account_id: AWS account ID
        state_directory: Directory for state files
        log_file: Path to log file
        enabled_monitors: List of monitor names to run
        max_workers: Maximum number of parallel region workers (default: 10)
        specific_region: Specific region to monitor (optional, default: all regions)
    """
    # Create error tracker for this monitoring run
    error_tracker = error_tracker_module.ErrorTracker()
    run_start_time = time.time()

    is_first_run = state_manager.is_first_run(state_directory, account_id)
    if is_first_run:
        print(f"First run for account {account_id} - establishing baseline state")

    print(f"Enabled monitors: {', '.join(enabled_monitors)}")

    try:
        if specific_region:
            regions = [specific_region]
            print(f"Monitoring specific region: {specific_region}")
        else:
            regions = get_all_regions(session)
            print(f"Monitoring {len(regions)} regions for account {account_id}")

        # Monitor all regions in parallel
        region_results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for region in regions:
                future = executor.submit(
                    monitor_account_region,
                    session,
                    account_id,
                    region,
                    state_directory,
                    log_file,
                    is_first_run,
                    enabled_monitors,
                    error_tracker  # Pass error tracker to all regions
                )
                futures.append((future, region))

            # Wait for all regions to complete and collect results
            completed = 0
            for future, region in futures:
                try:
                    result = future.result()
                    region_results.append(result)
                    completed += 1
                    print(f"Completed {region} ({completed}/{len(regions)})")
                except Exception as e:
                    print(f"Error monitoring region {region}: {str(e)}")

        # Check if any changes occurred
        has_changes = False
        for region_result in region_results:
            for service_result in region_result.get('service_results', []):
                if service_result.get('has_changes', False):
                    has_changes = True
                    break
            if has_changes:
                break

        # Only update state file if there were changes
        if has_changes or is_first_run:
            print(f"Changes detected, updating state file...")
            # Build complete state from all results
            complete_state = state_manager.load_state(state_directory, account_id) or {'regions': {}}

            for region_result in region_results:
                region = region_result['region']

                # Only process regions with successful service results
                successful_services = [
                    s for s in region_result.get('service_results', [])
                    if s.get('status') == 'success' and 'current_state' in s
                ]

                # Skip regions where all services failed
                if not successful_services:
                    continue

                # Ensure region exists in complete state
                if region not in complete_state['regions']:
                    complete_state['regions'][region] = {}

                # Add successful service states
                for service_result in successful_services:
                    service_name = service_result['service']
                    complete_state['regions'][region][service_name] = service_result['current_state']

            # Write state file once with all updates
            state_manager.save_state(state_directory, account_id, complete_state)
            print(f"State file updated")
        else:
            print(f"No changes detected, state file unchanged")

        # Log API failures if any occurred
        run_duration = time.time() - run_start_time
        if error_tracker.has_errors():
            print(f"\n⚠ {error_tracker.get_error_count()} API failure(s) occurred during this run")
            logger.log_api_failures(
                log_file=log_file,
                account_id=account_id,
                api_failures=error_tracker.get_errors(),
                run_duration=run_duration
            )

    except Exception as e:
        print(f"Error getting regions for account {account_id}: {str(e)}")
        # Log API failures if any occurred during the failed run
        run_duration = time.time() - run_start_time
        logger.log_api_failures(
            log_file=log_file,
            account_id=account_id,
            api_failures=error_tracker.get_errors(),
            run_duration=run_duration
        )


def main():
    """Main monitoring loop"""
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='AWS Security Watch - Monitor AWS security service configurations')
    parser.add_argument('--profile', type=str, help='AWS profile name to use')
    parser.add_argument('--config', type=str, help='Path to configuration file (optional)')
    parser.add_argument('--interval', type=int, default=120, help='Monitoring interval in seconds (default: 120)')
    parser.add_argument('--log-file', type=str, default='security-watch.log', help='Path to log file (default: security-watch.log)')
    parser.add_argument('--state-dir', type=str, default='state', help='Directory to store state files (default: state)')
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum parallel region workers (default: 10)')
    parser.add_argument('--region', type=str, help='Specific AWS region to monitor (optional, default: all regions)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging of AWS API calls')
    parser.add_argument('--web', action='store_true', help='Also serve the web GUI (pipeline diagram, history, alerts)')
    parser.add_argument('--web-host', type=str, default='0.0.0.0', help='Web GUI bind address (default: 0.0.0.0)')
    parser.add_argument('--web-port', type=int, default=54100, help='Web GUI port (default: 54100)')
    args = parser.parse_args()

    # Configure logging based on verbose flag
    if args.verbose:
        # Enable boto3/botocore logging to show API calls
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Configure boto3 to log API calls at INFO level
        logging.getLogger('boto3').setLevel(logging.WARNING)
        logging.getLogger('botocore').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)

        # Create a custom logger for API events
        class APICallLogger:
            def __init__(self):
                self.logger = logging.getLogger('aws_api_calls')
                self.logger.setLevel(logging.INFO)

            def log_call(self, service, operation, region, **kwargs):
                # Build parameter summary
                param_summary = []
                for key, value in kwargs.items():
                    if value and key not in ['endpoint', 'client']:
                        if isinstance(value, str) and len(value) > 50:
                            value = value[:47] + '...'
                        param_summary.append(f"{key}={value}")
                        if len(param_summary) >= 3:
                            break

                param_str = ', '.join(param_summary) if param_summary else ''
                message = f"{service}.{operation} (region={region})"
                if param_str:
                    message += f" [{param_str}]"

                print(f"[API] {message}")

        global api_call_logger
        api_call_logger = APICallLogger()

        # Monkey-patch boto3 client creation to add event listeners
        original_client = boto3.client

        def logged_client(service_name, *args, **kwargs):
            client = original_client(service_name, *args, **kwargs)
            region = kwargs.get('region_name', 'us-east-1')

            # Wrap the client's meta.events to log before-call
            def log_before_call(event_name=None, **event_kwargs):
                operation = event_kwargs.get('operation_name', 'unknown')
                params = event_kwargs.get('params', {})

                # Extract key parameters
                key_params = {}
                important_keys = ['Bucket', 'QueueUrl', 'TopicArn', 'FunctionName', 'RoleName',
                                'TrailName', 'DetectorId', 'RuleName', 'Name']
                for key in important_keys:
                    if key in params:
                        key_params[key] = params[key]

                api_call_logger.log_call(service_name, operation, region, **key_params)

            client.meta.events.register('before-call', log_before_call)
            return client

        boto3.client = logged_client

        print("Verbose mode enabled - AWS API calls will be logged")
        print()

    # Load configuration if provided
    config = {}
    if args.config:
        config = credentials.load_config(args.config)
        if not config:
            print(f"Error: Configuration file '{args.config}' not found or empty.")
            sys.exit(1)

    # Get monitoring configuration (command-line args override config file)
    monitoring_config = credentials.get_monitoring_config(config)
    interval_seconds = args.interval if args.interval != 120 else monitoring_config.get('interval_seconds', 120)
    log_file = args.log_file if args.log_file != 'security-watch.log' else monitoring_config.get('log_file', 'security-watch.log')
    state_directory = args.state_dir if args.state_dir != 'state' else monitoring_config.get('state_directory', 'state')

    # Ensure state directory exists
    state_manager.ensure_state_directory(state_directory)

    print("AWS Security Watch started")
    if args.profile:
        print(f"Using AWS profile: {args.profile}")
    if args.config:
        print(f"Using config file: {args.config}")
    print(f"Monitoring interval: {interval_seconds} seconds")
    print(f"Log file: {log_file}")
    print(f"State directory: {state_directory}")
    print(f"Max parallel workers: {args.max_workers}")

    # Start the GUI before touching AWS so a port conflict fails fast
    if args.web:
        from web import server as web_server
        try:
            web_server.start_in_background(args.web_host, args.web_port, state_directory, log_file)
        except OSError as e:
            print(f"Error: Could not start web GUI on {args.web_host}:{args.web_port}: {e}")
            sys.exit(1)
        print(f"Web GUI: http://{args.web_host}:{args.web_port}")
    print()

    # Get base session (with profile if specified)
    base_session = credentials.get_base_session(config, profile_name=args.profile)

    # Get list of accounts to monitor
    accounts = credentials.get_accounts(config)

    if not accounts:
        # If no accounts specified, monitor using base credentials
        print("No accounts configured - monitoring with base credentials")
        try:
            sts = base_session.client('sts')
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            accounts = [{'account_id': account_id, 'name': 'default'}]
        except Exception as e:
            print(f"Error: Could not determine account ID: {str(e)}")
            sys.exit(1)

    print(f"Monitoring {len(accounts)} account(s)")
    print()

    # Main monitoring loop
    try:
        while True:
            for account in accounts:
                account_id = account['account_id']
                account_name = account.get('name', account_id)

                print(f"--- Monitoring account: {account_name} ({account_id}) ---")

                try:
                    # Get session for this account
                    if 'role_arn' in account:
                        session = credentials.get_account_session(
                            base_session,
                            account_id,
                            account['role_arn']
                        )
                    else:
                        session = base_session

                    # Get enabled monitors for this account
                    enabled_monitors = get_enabled_monitors(account, config)

                    # Monitor the account
                    monitor_account(session, account_id, state_directory, log_file, enabled_monitors, args.max_workers, args.region)

                except Exception as e:
                    print(f"Error monitoring account {account_name}: {str(e)}")
                    continue

            print(f"\nSleeping for {interval_seconds} seconds...")
            print()
            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print("\nAWS Security Watch stopped")
        sys.exit(0)


if __name__ == '__main__':
    main()
