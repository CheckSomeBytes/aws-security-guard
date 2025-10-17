"""
CloudTrail Monitoring Module

Monitors CloudTrail configuration changes:
- StopLogging
- DeleteTrail
- Change to S3 Destination
- Changes to data selectors (event selectors)
"""

import boto3
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError


def get_current_state(session: boto3.Session, region: str) -> Dict[str, Any]:
    """
    Get current CloudTrail configuration state

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region to monitor

    Returns:
        Dictionary containing current trail configurations
        Only includes trails where this region is the home region to avoid duplicates
    """
    client = session.client('cloudtrail', region_name=region)

    try:
        trails = {}

        # Get all trails
        response = client.list_trails()

        for trail_info in response.get('Trails', []):
            trail_arn = trail_info['TrailARN']
            trail_name = trail_info['Name']
            trail_home_region = trail_info.get('HomeRegion')

            # CRITICAL FIX: Only process trails where this region is the home region
            # Multi-region trails appear in list_trails() for all regions, but we only
            # want to track them in their home region to avoid duplicates
            if trail_home_region and trail_home_region != region:
                continue

            try:
                # Get trail details
                trail_response = client.get_trail(Name=trail_arn)
                trail_config = trail_response.get('Trail', {})

                # Get trail status
                status_response = client.get_trail_status(Name=trail_arn)

                # Get event selectors
                try:
                    selector_response = client.get_event_selectors(TrailName=trail_arn)
                    event_selectors = selector_response.get('EventSelectors', [])
                    advanced_selectors = selector_response.get('AdvancedEventSelectors', [])
                except ClientError:
                    event_selectors = []
                    advanced_selectors = []

                trails[trail_name] = {
                    'arn': trail_arn,
                    's3_bucket': trail_config.get('S3BucketName'),
                    's3_key_prefix': trail_config.get('S3KeyPrefix'),
                    'is_logging': status_response.get('IsLogging', False),
                    'is_multi_region': trail_config.get('IsMultiRegionTrail', False),
                    'include_global_events': trail_config.get('IncludeGlobalServiceEvents', False),
                    'event_selectors': event_selectors,
                    'advanced_event_selectors': advanced_selectors,
                    'home_region': trail_config.get('HomeRegion')
                }

            except ClientError as e:
                print(f"Warning: Failed to get details for trail {trail_name}: {str(e)}")
                continue

        return trails

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            raise PermissionError(f"Access denied to CloudTrail in {region}: {str(e)}")
        raise


def detect_changes(
    previous_state: Optional[Dict[str, Any]],
    current_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect changes between previous and current state

    Args:
        previous_state: Previous trail configurations
        current_state: Current trail configurations

    Returns:
        List of detected changes
    """
    changes = []

    if previous_state is None:
        return changes  # First run, no changes to report

    previous_trails = set(previous_state.keys())
    current_trails = set(current_state.keys())

    # Detect deleted trails
    deleted_trails = previous_trails - current_trails
    for trail_name in deleted_trails:
        changes.append({
            'event_name': 'DeleteTrail',
            'trail_data': {
                'trailName': trail_name,
                'trailARN': previous_state[trail_name].get('arn')
            }
        })

    # Detect new trails (just record, don't treat as change for logging)
    # and modifications to existing trails
    for trail_name in current_trails:
        current_trail = current_state[trail_name]

        if trail_name not in previous_trails:
            # New trail - don't log as change
            continue

        previous_trail = previous_state[trail_name]

        # Check for StopLogging
        if previous_trail['is_logging'] and not current_trail['is_logging']:
            changes.append({
                'event_name': 'StopLogging',
                'trail_data': {
                    'trailName': trail_name,
                    'trailARN': current_trail['arn']
                }
            })

        # Note: StartLogging events are not monitored (removed per requirements)

        # Check for S3 destination changes
        if (previous_trail['s3_bucket'] != current_trail['s3_bucket'] or
            previous_trail['s3_key_prefix'] != current_trail['s3_key_prefix']):
            changes.append({
                'event_name': 'UpdateTrailS3Bucket',
                'trail_data': {
                    'trailName': trail_name,
                    'trailARN': current_trail['arn'],
                    'previousS3Bucket': previous_trail['s3_bucket'],
                    'currentS3Bucket': current_trail['s3_bucket'],
                    'previousS3KeyPrefix': previous_trail['s3_key_prefix'],
                    'currentS3KeyPrefix': current_trail['s3_key_prefix']
                }
            })

        # Check for event selector changes
        if (previous_trail['event_selectors'] != current_trail['event_selectors'] or
            previous_trail['advanced_event_selectors'] != current_trail['advanced_event_selectors']):
            changes.append({
                'event_name': 'UpdateEventSelectors',
                'trail_data': {
                    'trailName': trail_name,
                    'trailARN': current_trail['arn'],
                    'eventSelectors': current_trail['event_selectors'],
                    'advancedEventSelectors': current_trail['advanced_event_selectors']
                }
            })

    return changes
