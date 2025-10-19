"""
SNS Monitoring Module

Monitors SNS topic configuration changes for topics used in the CloudTrail ecosystem:
- Topics used as S3 event notification destinations
- Topics subscribed to by SQS queues
- Topic deletion
- Subscription changes (delete and update only, not creation)
- Access policy changes
- Encryption being added or modified (does not track encryption removal)

Note: Does NOT monitor:
- Display name changes
- Subscription creation
"""

import boto3
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError
import json


def get_current_state(
    session: boto3.Session,
    region: str,
    state_file_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Get current SNS topic configuration state for topics in CloudTrail ecosystem

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region to monitor
        state_file_data: Complete state file data (to read S3 and SQS state)

    Returns:
        Dictionary containing current SNS topic configurations
    """
    sns_client = session.client('sns', region_name=region)
    topics = {}

    # If no state file data provided, return empty state
    if not state_file_data:
        return {'sns_topics': topics}

    # Get S3 state to discover SNS topics from event notifications
    s3_state = state_file_data.get('regions', {}).get(region, {}).get('s3', {})

    # Get SQS state to discover SNS topics from queue subscriptions
    sqs_state = state_file_data.get('regions', {}).get(region, {}).get('sqs', {})

    # Extract unique SNS ARNs from S3 event notifications
    topic_sources = {}  # Map topic ARN to list of source resources

    # Discover from S3 event notifications
    for bucket_name, bucket_config in s3_state.get('s3_buckets', {}).items():
        for notification in bucket_config.get('event_notifications', []):
            if notification.get('destination_type') == 'SNS':
                topic_arn = notification.get('destination_arn')
                if topic_arn:
                    if topic_arn not in topic_sources:
                        topic_sources[topic_arn] = []
                    topic_sources[topic_arn].append({
                        'type': 's3_bucket',
                        'name': bucket_name
                    })

    # Discover from SQS queue subscriptions (check queue policies for SNS)
    for queue_url, queue_config in sqs_state.get('sqs_queues', {}).items():
        access_policy = queue_config.get('access_policy', {})
        # Parse policy to find SNS topic ARNs
        for statement in access_policy.get('Statement', []):
            principal = statement.get('Principal', {})
            if isinstance(principal, dict):
                service = principal.get('Service', '')
                if service == 'sns.amazonaws.com':
                    # Check if there's a condition with source ARN
                    condition = statement.get('Condition', {})
                    for condition_key, condition_value in condition.items():
                        if 'ArnEquals' in condition_key or 'ArnLike' in condition_key:
                            for arn_key, arn_value in condition_value.items():
                                if 'SourceArn' in arn_key or 'aws:SourceArn' in arn_key:
                                    if isinstance(arn_value, str) and 'arn:aws:sns:' in arn_value:
                                        topic_arn = arn_value
                                        if topic_arn not in topic_sources:
                                            topic_sources[topic_arn] = []
                                        topic_sources[topic_arn].append({
                                            'type': 'sqs_queue',
                                            'name': queue_config.get('queue_name', queue_url)
                                        })

    # Process each discovered topic
    for topic_arn, sources in topic_sources.items():
        try:
            # Get topic attributes
            try:
                response = sns_client.get_topic_attributes(TopicArn=topic_arn)
                attributes = response.get('Attributes', {})

                # Extract encryption settings
                encryption = {}
                if 'KmsMasterKeyId' in attributes:
                    encryption['KmsMasterKeyId'] = attributes['KmsMasterKeyId']

                # Parse access policy
                access_policy = {}
                if 'Policy' in attributes:
                    try:
                        access_policy = json.loads(attributes['Policy'])
                    except json.JSONDecodeError:
                        access_policy = {}

                # Get subscriptions for this topic
                subscriptions = []
                try:
                    paginator = sns_client.get_paginator('list_subscriptions_by_topic')
                    for page in paginator.paginate(TopicArn=topic_arn):
                        for sub in page.get('Subscriptions', []):
                            subscriptions.append({
                                'subscription_arn': sub.get('SubscriptionArn'),
                                'protocol': sub.get('Protocol'),
                                'endpoint': sub.get('Endpoint'),
                                'owner': sub.get('Owner')
                            })
                except ClientError:
                    # May not have permissions or topic doesn't exist
                    pass

                # Extract topic name from ARN
                topic_name = topic_arn.split(':')[-1] if ':' in topic_arn else topic_arn

                # Build topic state
                topics[topic_arn] = {
                    'arn': topic_arn,
                    'topic_name': topic_name,
                    'region': region,
                    'sources': sources,
                    'encryption': encryption,
                    'access_policy': access_policy,
                    'subscriptions': subscriptions,
                    'accessible': True
                }

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NotFound':
                    # Topic doesn't exist (may have been deleted)
                    continue
                elif error_code in ['AccessDenied', 'AccessDeniedException', 'AuthorizationError']:
                    # Cross-account topic or insufficient permissions
                    topic_name = topic_arn.split(':')[-1] if ':' in topic_arn else 'unknown'
                    topics[topic_arn] = {
                        'arn': topic_arn,
                        'topic_name': topic_name,
                        'region': region,
                        'sources': sources,
                        'accessible': False,
                        'error': f'Cross-account or inaccessible topic: {error_code}'
                    }
                else:
                    print(f"Warning: Error processing topic {topic_arn}: {str(e)}")

        except Exception as e:
            print(f"Warning: Unexpected error processing topic {topic_arn}: {str(e)}")

    return {'sns_topics': topics}


def detect_changes(
    previous_state: Optional[Dict[str, Any]],
    current_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect changes between previous and current SNS topic state

    Args:
        previous_state: Previous SNS topic configurations
        current_state: Current SNS topic configurations

    Returns:
        List of detected changes
    """
    changes = []

    if previous_state is None:
        return changes  # First run, no changes to report

    previous_topics = previous_state.get('sns_topics', {})
    current_topics = current_state.get('sns_topics', {})

    # Detect topic deletions
    deleted_topics = set(previous_topics.keys()) - set(current_topics.keys())
    for topic_arn in deleted_topics:
        prev_topic = previous_topics[topic_arn]
        changes.append({
            'event_name': 'DeleteTopic',
            'sns_data': {
                'topicArn': topic_arn,
                'topicName': prev_topic.get('topic_name'),
                'sources': prev_topic.get('sources', [])
            }
        })

    # Detect changes in existing topics
    for topic_arn in current_topics.keys():
        if topic_arn not in previous_topics:
            # New topic - don't log as change
            continue

        current_topic = current_topics[topic_arn]
        previous_topic = previous_topics[topic_arn]

        # Skip if topic is not accessible
        if not current_topic.get('accessible', True):
            continue

        # Check for encryption changes - track when encryption is ADDED or MODIFIED
        prev_encryption = previous_topic.get('encryption', {})
        curr_encryption = current_topic.get('encryption', {})

        # Log when encryption is added (previous was empty, current has encryption)
        if not prev_encryption and curr_encryption:
            changes.append({
                'event_name': 'AddTopicEncryption',
                'sns_data': {
                    'topicArn': topic_arn,
                    'topicName': current_topic.get('topic_name'),
                    'sources': current_topic.get('sources', []),
                    'addedEncryption': curr_encryption
                }
            })
        # Log when encryption is modified (both had encryption, but different settings)
        elif prev_encryption and curr_encryption and prev_encryption != curr_encryption:
            changes.append({
                'event_name': 'UpdateTopicEncryption',
                'sns_data': {
                    'topicArn': topic_arn,
                    'topicName': current_topic.get('topic_name'),
                    'sources': current_topic.get('sources', []),
                    'previousEncryption': prev_encryption,
                    'currentEncryption': curr_encryption
                }
            })
        # Note: We do NOT log when encryption is removed (prev_encryption and not curr_encryption)

        # Check for access policy changes
        prev_policy = previous_topic.get('access_policy', {})
        curr_policy = current_topic.get('access_policy', {})

        if prev_policy != curr_policy:
            changes.append({
                'event_name': 'UpdateTopicPolicy',
                'sns_data': {
                    'topicArn': topic_arn,
                    'topicName': current_topic.get('topic_name'),
                    'sources': current_topic.get('sources', []),
                    'previousPolicy': prev_policy,
                    'currentPolicy': curr_policy
                }
            })

        # Check for subscription changes
        prev_subs = {s['subscription_arn']: s for s in previous_topic.get('subscriptions', [])}
        curr_subs = {s['subscription_arn']: s for s in current_topic.get('subscriptions', [])}

        # Detect removed subscriptions
        removed_sub_arns = set(prev_subs.keys()) - set(curr_subs.keys())
        if removed_sub_arns:
            removed_subs = [prev_subs[arn] for arn in removed_sub_arns]
            changes.append({
                'event_name': 'DeleteTopicSubscription',
                'sns_data': {
                    'topicArn': topic_arn,
                    'topicName': current_topic.get('topic_name'),
                    'sources': current_topic.get('sources', []),
                    'removedSubscriptions': removed_subs
                }
            })

        # Note: We do not monitor added subscriptions (CreateTopicSubscription)

        # Detect modified subscriptions (same ARN but different attributes)
        for sub_arn in set(prev_subs.keys()) & set(curr_subs.keys()):
            if prev_subs[sub_arn] != curr_subs[sub_arn]:
                changes.append({
                    'event_name': 'UpdateTopicSubscription',
                    'sns_data': {
                        'topicArn': topic_arn,
                        'topicName': current_topic.get('topic_name'),
                        'sources': current_topic.get('sources', []),
                        'subscriptionArn': sub_arn,
                        'previousSubscription': prev_subs[sub_arn],
                        'currentSubscription': curr_subs[sub_arn]
                    }
                })

        # Note: We do not monitor display name changes (UpdateTopicDisplayName)

    return changes
