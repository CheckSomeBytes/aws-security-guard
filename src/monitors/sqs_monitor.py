"""
SQS Monitoring Module

Monitors SQS queue configuration changes for queues used as S3 event notification destinations:
- Queue deletion
- Encryption setting changes
- Access policy changes
- Lambda event source mapping changes (triggers)
"""

import boto3
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError
import json


def _parse_queue_url_from_arn(queue_arn: str, region: str) -> str:
    """
    Convert SQS ARN to queue URL

    Args:
        queue_arn: SQS queue ARN (arn:aws:sqs:region:account-id:queue-name)
        region: AWS region

    Returns:
        Queue URL
    """
    # ARN format: arn:aws:sqs:region:account-id:queue-name
    parts = queue_arn.split(':')
    if len(parts) >= 6:
        account_id = parts[4]
        queue_name = parts[5]
        return f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"
    return ""


def get_current_state(
    session: boto3.Session,
    region: str,
    state_file_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Get current SQS queue configuration state for queues used as S3 event destinations

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region to monitor
        state_file_data: Complete state file data (to read S3 state)

    Returns:
        Dictionary containing current SQS queue configurations
    """
    sqs_client = session.client('sqs', region_name=region)
    lambda_client = session.client('lambda', region_name=region)
    queues = {}

    # If no state file data provided, return empty state
    if not state_file_data:
        return {'sqs_queues': queues}

    # Get S3 state to discover SQS queues
    s3_state = state_file_data.get('regions', {}).get(region, {}).get('s3', {})

    # Extract unique SQS ARNs from S3 event notifications
    queue_bucket_map = {}  # Map queue ARN to source S3 bucket
    for bucket_name, bucket_config in s3_state.get('s3_buckets', {}).items():
        for notification in bucket_config.get('event_notifications', []):
            if notification.get('destination_type') == 'SQS':
                queue_arn = notification.get('destination_arn')
                if queue_arn:
                    queue_bucket_map[queue_arn] = bucket_name

    # Process each discovered queue
    for queue_arn, source_bucket in queue_bucket_map.items():
        try:
            # Convert ARN to URL
            queue_url = _parse_queue_url_from_arn(queue_arn, region)
            if not queue_url:
                print(f"Warning: Could not parse queue URL from ARN: {queue_arn}")
                continue

            # Get queue attributes
            try:
                response = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=['All']
                )
                attributes = response.get('Attributes', {})

                # Extract encryption settings
                encryption = {}
                if 'KmsMasterKeyId' in attributes:
                    encryption['KmsMasterKeyId'] = attributes['KmsMasterKeyId']
                if 'KmsDataKeyReusePeriodSeconds' in attributes:
                    encryption['KmsDataKeyReusePeriodSeconds'] = attributes['KmsDataKeyReusePeriodSeconds']

                # Parse access policy
                access_policy = {}
                if 'Policy' in attributes:
                    try:
                        access_policy = json.loads(attributes['Policy'])
                    except json.JSONDecodeError:
                        access_policy = {}

                # Get Lambda event source mappings for this queue
                lambda_event_sources = []
                try:
                    # List all event source mappings and filter by this queue ARN
                    paginator = lambda_client.get_paginator('list_event_source_mappings')
                    for page in paginator.paginate(EventSourceArn=queue_arn):
                        for mapping in page.get('EventSourceMappings', []):
                            lambda_event_sources.append({
                                'uuid': mapping.get('UUID'),
                                'function_arn': mapping.get('FunctionArn'),
                                'batch_size': mapping.get('BatchSize'),
                                'state': mapping.get('State')
                            })
                except ClientError:
                    # May not have lambda permissions or no mappings exist
                    pass

                # Extract queue name from ARN
                queue_name = queue_arn.split(':')[-1] if ':' in queue_arn else queue_url.split('/')[-1]

                # Build queue state
                queues[queue_url] = {
                    'arn': queue_arn,
                    'queue_name': queue_name,
                    'region': region,
                    'source_s3_bucket': source_bucket,
                    'encryption': encryption,
                    'access_policy': access_policy,
                    'lambda_event_sources': lambda_event_sources,
                    'accessible': True
                }

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ['AWS.SimpleQueueService.NonExistentQueue', 'QueueDoesNotExist']:
                    # Queue doesn't exist (may have been deleted)
                    continue
                elif error_code in ['AccessDenied', 'AccessDeniedException']:
                    # Cross-account queue or insufficient permissions
                    queue_name = queue_arn.split(':')[-1] if ':' in queue_arn else 'unknown'
                    queues[queue_url] = {
                        'arn': queue_arn,
                        'queue_name': queue_name,
                        'region': region,
                        'source_s3_bucket': source_bucket,
                        'accessible': False,
                        'error': f'Cross-account or inaccessible queue: {error_code}'
                    }
                else:
                    print(f"Warning: Error processing queue {queue_arn}: {str(e)}")

        except Exception as e:
            print(f"Warning: Unexpected error processing queue {queue_arn}: {str(e)}")

    return {'sqs_queues': queues}


def detect_changes(
    previous_state: Optional[Dict[str, Any]],
    current_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect changes between previous and current SQS queue state

    Args:
        previous_state: Previous SQS queue configurations
        current_state: Current SQS queue configurations

    Returns:
        List of detected changes
    """
    changes = []

    if previous_state is None:
        return changes  # First run, no changes to report

    previous_queues = previous_state.get('sqs_queues', {})
    current_queues = current_state.get('sqs_queues', {})

    # Detect queue deletions
    deleted_queues = set(previous_queues.keys()) - set(current_queues.keys())
    for queue_url in deleted_queues:
        prev_queue = previous_queues[queue_url]
        changes.append({
            'event_name': 'DeleteQueue',
            'sqs_data': {
                'queueUrl': queue_url,
                'queueArn': prev_queue.get('arn'),
                'queueName': prev_queue.get('queue_name'),
                'sourceS3Bucket': prev_queue.get('source_s3_bucket')
            }
        })

    # Detect changes in existing queues
    for queue_url in current_queues.keys():
        if queue_url not in previous_queues:
            # New queue - don't log as change
            continue

        current_queue = current_queues[queue_url]
        previous_queue = previous_queues[queue_url]

        # Skip if queue is not accessible
        if not current_queue.get('accessible', True):
            continue

        # Check for encryption changes
        prev_encryption = previous_queue.get('encryption', {})
        curr_encryption = current_queue.get('encryption', {})

        if prev_encryption != curr_encryption:
            changes.append({
                'event_name': 'UpdateQueueEncryption',
                'sqs_data': {
                    'queueUrl': queue_url,
                    'queueArn': current_queue.get('arn'),
                    'queueName': current_queue.get('queue_name'),
                    'sourceS3Bucket': current_queue.get('source_s3_bucket'),
                    'previousEncryption': prev_encryption,
                    'currentEncryption': curr_encryption
                }
            })

        # Check for access policy changes
        prev_policy = previous_queue.get('access_policy', {})
        curr_policy = current_queue.get('access_policy', {})

        if prev_policy != curr_policy:
            changes.append({
                'event_name': 'UpdateQueuePolicy',
                'sqs_data': {
                    'queueUrl': queue_url,
                    'queueArn': current_queue.get('arn'),
                    'queueName': current_queue.get('queue_name'),
                    'sourceS3Bucket': current_queue.get('source_s3_bucket'),
                    'previousPolicy': prev_policy,
                    'currentPolicy': curr_policy
                }
            })

        # Check for Lambda event source mapping changes
        prev_mappings = {m['uuid']: m for m in previous_queue.get('lambda_event_sources', [])}
        curr_mappings = {m['uuid']: m for m in current_queue.get('lambda_event_sources', [])}

        # Detect removed mappings
        removed_mapping_uuids = set(prev_mappings.keys()) - set(curr_mappings.keys())
        if removed_mapping_uuids:
            removed_mappings = [prev_mappings[uuid] for uuid in removed_mapping_uuids]
            changes.append({
                'event_name': 'DeleteQueueLambdaTrigger',
                'sqs_data': {
                    'queueUrl': queue_url,
                    'queueArn': current_queue.get('arn'),
                    'queueName': current_queue.get('queue_name'),
                    'sourceS3Bucket': current_queue.get('source_s3_bucket'),
                    'removedTriggers': removed_mappings
                }
            })

        # Detect added mappings
        added_mapping_uuids = set(curr_mappings.keys()) - set(prev_mappings.keys())
        if added_mapping_uuids:
            added_mappings = [curr_mappings[uuid] for uuid in added_mapping_uuids]
            changes.append({
                'event_name': 'CreateQueueLambdaTrigger',
                'sqs_data': {
                    'queueUrl': queue_url,
                    'queueArn': current_queue.get('arn'),
                    'queueName': current_queue.get('queue_name'),
                    'sourceS3Bucket': current_queue.get('source_s3_bucket'),
                    'addedTriggers': added_mappings
                }
            })

        # Detect modified mappings (same UUID but different attributes)
        for uuid in set(prev_mappings.keys()) & set(curr_mappings.keys()):
            if prev_mappings[uuid] != curr_mappings[uuid]:
                changes.append({
                    'event_name': 'UpdateQueueLambdaTrigger',
                    'sqs_data': {
                        'queueUrl': queue_url,
                        'queueArn': current_queue.get('arn'),
                        'queueName': current_queue.get('queue_name'),
                        'sourceS3Bucket': current_queue.get('source_s3_bucket'),
                        'triggerUuid': uuid,
                        'previousTrigger': prev_mappings[uuid],
                        'currentTrigger': curr_mappings[uuid]
                    }
                })

    return changes
