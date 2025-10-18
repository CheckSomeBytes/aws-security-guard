"""
S3 Monitoring Module

Monitors S3 bucket configuration changes for buckets used as CloudTrail destinations:
- Bucket size reductions greater than 50%
- Bucket deletion
- Event notification prefix/suffix changes
- Event notification event type changes
- Event notification destination changes
- Encryption setting changes
"""

import boto3
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError


def _get_bucket_size(s3_client, bucket_name: str) -> int:
    """
    Calculate total bucket size by listing all objects

    Args:
        s3_client: boto3 S3 client
        bucket_name: Name of the S3 bucket

    Returns:
        Total size in bytes
    """
    total_size = 0
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                for obj in page['Contents']:
                    total_size += obj.get('Size', 0)
        return total_size
    except ClientError:
        return 0


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    """
    Get the region of an S3 bucket

    Args:
        s3_client: boto3 S3 client
        bucket_name: Name of the S3 bucket

    Returns:
        AWS region name (or 'us-east-1' if LocationConstraint is None)
    """
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        location = response.get('LocationConstraint')
        # None means us-east-1
        return location if location else 'us-east-1'
    except ClientError:
        return 'unknown'


def _parse_event_notifications(notification_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse S3 event notification configuration into a standardized format

    Args:
        notification_config: Raw notification configuration from AWS API

    Returns:
        List of normalized notification configurations
    """
    notifications = []

    # Process Queue configurations (SQS)
    for queue_config in notification_config.get('QueueConfigurations', []):
        notifications.append({
            'id': queue_config.get('Id', 'unknown'),
            'events': queue_config.get('Events', []),
            'filter': {
                'prefix': queue_config.get('Filter', {}).get('Key', {}).get('FilterRules', [{}])[0].get('Value', '') if any(r.get('Name') == 'prefix' for r in queue_config.get('Filter', {}).get('Key', {}).get('FilterRules', [])) else '',
                'suffix': queue_config.get('Filter', {}).get('Key', {}).get('FilterRules', [{}])[0].get('Value', '') if any(r.get('Name') == 'suffix' for r in queue_config.get('Filter', {}).get('Key', {}).get('FilterRules', [])) else ''
            },
            'destination_type': 'SQS',
            'destination_arn': queue_config.get('QueueArn', '')
        })

    # Process Topic configurations (SNS)
    for topic_config in notification_config.get('TopicConfigurations', []):
        filter_rules = topic_config.get('Filter', {}).get('Key', {}).get('FilterRules', [])
        prefix = ''
        suffix = ''
        for rule in filter_rules:
            if rule.get('Name') == 'prefix':
                prefix = rule.get('Value', '')
            elif rule.get('Name') == 'suffix':
                suffix = rule.get('Value', '')

        notifications.append({
            'id': topic_config.get('Id', 'unknown'),
            'events': topic_config.get('Events', []),
            'filter': {
                'prefix': prefix,
                'suffix': suffix
            },
            'destination_type': 'SNS',
            'destination_arn': topic_config.get('TopicArn', '')
        })

    # Process Lambda configurations
    for lambda_config in notification_config.get('LambdaFunctionConfigurations', []):
        filter_rules = lambda_config.get('Filter', {}).get('Key', {}).get('FilterRules', [])
        prefix = ''
        suffix = ''
        for rule in filter_rules:
            if rule.get('Name') == 'prefix':
                prefix = rule.get('Value', '')
            elif rule.get('Name') == 'suffix':
                suffix = rule.get('Value', '')

        notifications.append({
            'id': lambda_config.get('Id', 'unknown'),
            'events': lambda_config.get('Events', []),
            'filter': {
                'prefix': prefix,
                'suffix': suffix
            },
            'destination_type': 'Lambda',
            'destination_arn': lambda_config.get('LambdaFunctionArn', '')
        })

    return notifications


def get_current_state(
    session: boto3.Session,
    region: str,
    state_file_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Get current S3 bucket configuration state for CloudTrail buckets

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region to monitor
        state_file_data: Complete state file data (to read CloudTrail state)

    Returns:
        Dictionary containing current S3 bucket configurations
    """
    s3_client = session.client('s3', region_name=region)
    buckets = {}

    # If no state file data provided, return empty state
    if not state_file_data:
        return {'s3_buckets': buckets}

    # Get CloudTrail state to discover S3 buckets
    cloudtrail_state = state_file_data.get('regions', {}).get(region, {}).get('cloudtrail', {})

    # Extract unique S3 bucket names from CloudTrail trails
    bucket_trail_map = {}  # Map bucket name to trail ARN
    for trail_name, trail_config in cloudtrail_state.items():
        bucket_name = trail_config.get('s3_bucket')
        trail_arn = trail_config.get('arn')
        if bucket_name and trail_arn:
            bucket_trail_map[bucket_name] = trail_arn

    # Process each discovered bucket
    for bucket_name, source_trail_arn in bucket_trail_map.items():
        try:
            # Get bucket region
            bucket_region = _get_bucket_region(s3_client, bucket_name)

            # Get bucket size
            bucket_size = _get_bucket_size(s3_client, bucket_name)

            # Get versioning status
            try:
                versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = versioning_response.get('Status', 'Disabled')
            except ClientError:
                versioning_status = 'Unknown'

            # Get encryption configuration
            encryption_config = {}
            try:
                encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                if rules:
                    default_encryption = rules[0].get('ApplyServerSideEncryptionByDefault', {})
                    encryption_config = {
                        'SSEAlgorithm': default_encryption.get('SSEAlgorithm', ''),
                        'KMSMasterKeyID': default_encryption.get('KMSMasterKeyID', '')
                    }
            except ClientError as e:
                # Bucket may not have encryption configured
                if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                    print(f"Warning: Could not get encryption for bucket {bucket_name}: {str(e)}")

            # Get event notification configuration
            event_notifications = []
            try:
                notification_response = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
                event_notifications = _parse_event_notifications(notification_response)
            except ClientError as e:
                print(f"Warning: Could not get notifications for bucket {bucket_name}: {str(e)}")

            # Build bucket state
            buckets[bucket_name] = {
                'arn': f'arn:aws:s3:::{bucket_name}',
                'region': bucket_region,
                'source_trail_arn': source_trail_arn,
                'bucket_size_bytes': bucket_size,
                'versioning': versioning_status,
                'encryption': encryption_config,
                'event_notifications': event_notifications,
                'accessible': True
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDenied', 'NoSuchBucket', 'AllAccessDisabled']:
                # Cross-account bucket or inaccessible bucket
                buckets[bucket_name] = {
                    'arn': f'arn:aws:s3:::{bucket_name}',
                    'region': 'unknown',
                    'source_trail_arn': source_trail_arn,
                    'accessible': False,
                    'error': f'Cross-account or inaccessible bucket: {error_code}'
                }
            else:
                print(f"Warning: Error processing bucket {bucket_name}: {str(e)}")

    return {'s3_buckets': buckets}


def detect_changes(
    previous_state: Optional[Dict[str, Any]],
    current_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect changes between previous and current S3 bucket state

    Args:
        previous_state: Previous S3 bucket configurations
        current_state: Current S3 bucket configurations

    Returns:
        List of detected changes
    """
    changes = []

    if previous_state is None:
        return changes  # First run, no changes to report

    previous_buckets = previous_state.get('s3_buckets', {})
    current_buckets = current_state.get('s3_buckets', {})

    # Detect bucket deletions
    deleted_buckets = set(previous_buckets.keys()) - set(current_buckets.keys())
    for bucket_name in deleted_buckets:
        prev_bucket = previous_buckets[bucket_name]
        changes.append({
            'event_name': 'DeleteBucket',
            's3_data': {
                'bucketName': bucket_name,
                'bucketArn': prev_bucket.get('arn'),
                'sourceTrailArn': prev_bucket.get('source_trail_arn')
            }
        })

    # Detect changes in existing buckets
    for bucket_name in current_buckets.keys():
        if bucket_name not in previous_buckets:
            # New bucket - don't log as change
            continue

        current_bucket = current_buckets[bucket_name]
        previous_bucket = previous_buckets[bucket_name]

        # Skip if bucket is not accessible
        if not current_bucket.get('accessible', True):
            continue

        # Check for bucket size reduction > 50%
        prev_size = previous_bucket.get('bucket_size_bytes', 0)
        curr_size = current_bucket.get('bucket_size_bytes', 0)

        if prev_size > 0:  # Only check if we have a previous size
            reduction_percentage = ((prev_size - curr_size) / prev_size) * 100
            if reduction_percentage > 50:
                changes.append({
                    'event_name': 'S3BucketSizeReduction',
                    's3_data': {
                        'bucketName': bucket_name,
                        'bucketArn': current_bucket.get('arn'),
                        'sourceTrailArn': current_bucket.get('source_trail_arn'),
                        'previousSizeBytes': prev_size,
                        'currentSizeBytes': curr_size,
                        'reductionPercentage': round(reduction_percentage, 2)
                    }
                })

        # Check for encryption changes
        prev_encryption = previous_bucket.get('encryption', {})
        curr_encryption = current_bucket.get('encryption', {})

        if prev_encryption != curr_encryption:
            changes.append({
                'event_name': 'UpdateBucketEncryption',
                's3_data': {
                    'bucketName': bucket_name,
                    'bucketArn': current_bucket.get('arn'),
                    'sourceTrailArn': current_bucket.get('source_trail_arn'),
                    'previousEncryption': prev_encryption,
                    'currentEncryption': curr_encryption
                }
            })

        # Check for event notification changes
        prev_notifications = {n['id']: n for n in previous_bucket.get('event_notifications', [])}
        curr_notifications = {n['id']: n for n in current_bucket.get('event_notifications', [])}

        # Check each current notification for changes
        for notif_id, curr_notif in curr_notifications.items():
            if notif_id not in prev_notifications:
                # New notification - don't log
                continue

            prev_notif = prev_notifications[notif_id]

            # Check for prefix changes
            prev_prefix = prev_notif.get('filter', {}).get('prefix', '')
            curr_prefix = curr_notif.get('filter', {}).get('prefix', '')
            if prev_prefix != curr_prefix:
                changes.append({
                    'event_name': 'UpdateBucketNotificationFilterPrefix',
                    's3_data': {
                        'bucketName': bucket_name,
                        'bucketArn': current_bucket.get('arn'),
                        'notificationId': notif_id,
                        'previousPrefix': prev_prefix,
                        'currentPrefix': curr_prefix,
                        'destinationType': curr_notif.get('destination_type'),
                        'destinationArn': curr_notif.get('destination_arn')
                    }
                })

            # Check for suffix changes
            prev_suffix = prev_notif.get('filter', {}).get('suffix', '')
            curr_suffix = curr_notif.get('filter', {}).get('suffix', '')
            if prev_suffix != curr_suffix:
                changes.append({
                    'event_name': 'UpdateBucketNotificationFilterSuffix',
                    's3_data': {
                        'bucketName': bucket_name,
                        'bucketArn': current_bucket.get('arn'),
                        'notificationId': notif_id,
                        'previousSuffix': prev_suffix,
                        'currentSuffix': curr_suffix,
                        'destinationType': curr_notif.get('destination_type'),
                        'destinationArn': curr_notif.get('destination_arn')
                    }
                })

            # Check for event type changes
            prev_events = set(prev_notif.get('events', []))
            curr_events = set(curr_notif.get('events', []))
            if prev_events != curr_events:
                changes.append({
                    'event_name': 'UpdateBucketNotificationEvents',
                    's3_data': {
                        'bucketName': bucket_name,
                        'bucketArn': current_bucket.get('arn'),
                        'notificationId': notif_id,
                        'previousEvents': list(prev_events),
                        'currentEvents': list(curr_events),
                        'destinationType': curr_notif.get('destination_type'),
                        'destinationArn': curr_notif.get('destination_arn')
                    }
                })

            # Check for destination changes
            prev_dest = prev_notif.get('destination_arn', '')
            curr_dest = curr_notif.get('destination_arn', '')
            if prev_dest != curr_dest:
                changes.append({
                    'event_name': 'UpdateBucketNotificationDestination',
                    's3_data': {
                        'bucketName': bucket_name,
                        'bucketArn': current_bucket.get('arn'),
                        'notificationId': notif_id,
                        'previousDestination': prev_dest,
                        'currentDestination': curr_dest,
                        'destinationType': curr_notif.get('destination_type')
                    }
                })

    return changes
