#!/usr/bin/env python3
"""
AWS Security Watch

Monitors AWS security service configurations and logs changes:
- CloudTrail
- GuardDuty
- EventBridge
"""

import time
import boto3
from typing import Dict, Any, List, Optional
from pathlib import Path
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

import credentials
import state_manager
import logger
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
    state_file_data: Optional[Dict[str, Any]] = None
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

    Returns:
        Dictionary with service name, status, current state, and any changes
    """
    try:
        # Check if monitor supports state_file_data parameter
        import inspect
        sig = inspect.signature(monitor_module.get_current_state)
        if 'state_file_data' in sig.parameters:
            current_state = monitor_module.get_current_state(session, region, state_file_data)
        else:
            current_state = monitor_module.get_current_state(session, region)

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
        logger.log_permission_error(log_file, account_id, region, service_name, str(e))
        return {'service': service_name, 'region': region, 'status': 'permission_error', 'error': str(e), 'has_changes': False}
    except Exception as e:
        print(f"Error monitoring {service_name} in {region}: {str(e)}")
        return {'service': service_name, 'region': region, 'status': 'error', 'error': str(e), 'has_changes': False}


def monitor_account_region(
    session: boto3.Session,
    account_id: str,
    region: str,
    state_directory: str,
    log_file: str,
    is_first_run: bool
) -> Dict[str, Any]:
    """
    Monitor a single account in a single region (all services in parallel)

    Args:
        session: boto3 session with appropriate credentials
        account_id: AWS account ID
        region: AWS region
        state_directory: Directory for state files
        log_file: Path to log file
        is_first_run: Whether this is the first run for this account

    Returns:
        Dictionary with region and collected service states
    """
    # Load current state file for resource discovery
    state_file_data = state_manager.load_state(state_directory, account_id) or {'regions': {}}

    # Define services to monitor
    services = [
        ('cloudtrail', cloudtrail_monitor, logger.log_cloudtrail_change),
        ('guardduty', guardduty_monitor, logger.log_guardduty_change),
        ('eventbridge', eventbridge_monitor, logger.log_eventbridge_change),
        ('s3', s3_monitor, logger.log_s3_change),
        ('sqs', sqs_monitor, logger.log_sqs_change),
        ('sns', sns_monitor, logger.log_sns_change),
        ('lambda', lambda_monitor, logger.log_lambda_change),
        ('iam', iam_monitor, logger.log_iam_change)
    ]

    # Monitor all services in parallel
    service_results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for service_name, monitor_module, log_function in services:
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
                state_file_data
            )
            futures.append(future)

        # Wait for all services to complete and collect results
        for future in as_completed(futures):
            result = future.result()
            service_results.append(result)
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
    max_workers: int = 10
) -> None:
    """
    Monitor all regions in an account (parallel regions, batch state updates)

    Args:
        session: boto3 session with appropriate credentials
        account_id: AWS account ID
        state_directory: Directory for state files
        log_file: Path to log file
        max_workers: Maximum number of parallel region workers (default: 10)
    """
    is_first_run = state_manager.is_first_run(state_directory, account_id)
    if is_first_run:
        print(f"First run for account {account_id} - establishing baseline state")

    try:
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
                    is_first_run
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
                if region not in complete_state['regions']:
                    complete_state['regions'][region] = {}

                for service_result in region_result.get('service_results', []):
                    if service_result.get('status') == 'success' and 'current_state' in service_result:
                        service_name = service_result['service']
                        complete_state['regions'][region][service_name] = service_result['current_state']

            # Write state file once with all updates
            state_manager.save_state(state_directory, account_id, complete_state)
            print(f"State file updated")
        else:
            print(f"No changes detected, state file unchanged")

    except Exception as e:
        print(f"Error getting regions for account {account_id}: {str(e)}")


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
    args = parser.parse_args()

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

                    # Monitor the account
                    monitor_account(session, account_id, state_directory, log_file, args.max_workers)

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
