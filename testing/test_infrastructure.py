#!/usr/bin/env python3
"""
Test Infrastructure Script

Creates, modifies, and deletes AWS resources to test AWS Security Guard functionality.
Tests the following scenarios:
- CloudTrail: StopLogging, S3 bucket changes, event selector changes, DeleteTrail
- S3: Bucket encryption, object operations, size reduction monitoring
- SQS: Queue creation, encryption, policy changes, deletion
- SNS: Topic creation, encryption, policy changes, subscription management
- GuardDuty: Suppression rule creation/modification/deletion
- EventBridge: Rule creation/modification/deletion
- IAM: Role trust policy changes, managed/inline policies, description/max session duration

Usage:
  # Run all tests in a random region
  python3 test_infrastructure.py --profile my-profile

  # Run specific service tests interactively
  python3 test_infrastructure.py --profile my-profile --service iam --interactive

  # Clean up all test resources in current region
  python3 test_infrastructure.py --profile my-profile --cleanup

  # Clean up all test resources across ALL regions
  python3 test_infrastructure.py --profile my-profile --cleanup --cleanup-all-regions
"""

import boto3
import time
import json
import random
import string
from typing import Dict, Any, List
from botocore.exceptions import ClientError

# Global configuration
DELAY_SECONDS = 35  # 2 minutes - delay between test steps in non-interactive mode


def create_s3_bucket(s3_client, bucket_name: str, region: str) -> str:
    """Create an S3 bucket for testing"""
    try:
        if region == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )

        # Apply bucket policy for CloudTrail
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket_name}"
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                }
            ]
        }
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )

        print(f"Created S3 bucket: {bucket_name}")
        return bucket_name
    except ClientError as e:
        print(f"Error creating S3 bucket: {str(e)}")
        raise


def delete_s3_bucket(s3_client, bucket_name: str) -> None:
    """Delete an S3 bucket and all its contents"""
    try:
        # Delete all objects first
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                s3_client.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': objects}
                )

        # Delete bucket
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"Deleted S3 bucket: {bucket_name}")
    except ClientError as e:
        print(f"Error deleting S3 bucket: {str(e)}")


def wait_for_user(interactive: bool, delay_seconds: int, message: str = None) -> None:
    """
    Wait for user input or timer based on interactive mode
    Handles both interactive terminals and background execution

    Args:
        interactive: If True, wait for user to press Enter. If False, sleep for delay_seconds
        delay_seconds: Number of seconds to wait in non-interactive mode
        message: Optional message to display
    """
    if message:
        print(f"\n{message}")

    if interactive:
        # Check if stdin is available
        import sys
        if sys.stdin.isatty():
            try:
                input("Press Enter to continue...")
            except EOFError:
                print("Warning: EOF detected, falling back to timer mode")
                print(f"Waiting {delay_seconds} seconds...")
                time.sleep(delay_seconds)
        else:
            # Running in background or redirected stdin
            print(f"Non-interactive environment detected, waiting {delay_seconds} seconds...")
            time.sleep(delay_seconds)
    else:
        print(f"Waiting {delay_seconds} seconds...")
        time.sleep(delay_seconds)


def test_cloudtrail(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """Test CloudTrail monitoring"""
    print(f"\n=== Testing CloudTrail in {region} ===")
    cloudtrail = session.client('cloudtrail', region_name=region)
    s3 = session.client('s3', region_name=region)

    trail_name = f"aws-security-guard-test-trail-{test_name}"
    bucket1_name = f"aws-security-guard-test-bucket1-{test_name}".lower()
    bucket2_name = f"aws-security-guard-test-bucket2-{test_name}".lower()

    try:
        # Create S3 buckets
        create_s3_bucket(s3, bucket1_name, region)
        create_s3_bucket(s3, bucket2_name, region)

        # Create CloudTrail
        print(f"Creating trail: {trail_name}")
        cloudtrail.create_trail(
            Name=trail_name,
            S3BucketName=bucket1_name,
            IsMultiRegionTrail=False
        )

        # Start logging
        cloudtrail.start_logging(Name=trail_name)
        print(f"Started logging for trail: {trail_name}")
        wait_for_user(interactive, DELAY_SECONDS, "Trail created and logging started.")

        # Test 1: Stop logging
        print("\nTest 1: Stopping logging...")
        wait_for_user(interactive, DELAY_SECONDS)
        cloudtrail.stop_logging(Name=trail_name)
        print("✓ Logging stopped")

        # Restart logging for next test
        print("\nRestarting logging...")
        wait_for_user(interactive, DELAY_SECONDS)
        cloudtrail.start_logging(Name=trail_name)
        print("✓ Logging restarted")

        # Test 2: Change S3 destination
        print("\nTest 2: Changing S3 destination...")
        wait_for_user(interactive, DELAY_SECONDS)
        cloudtrail.update_trail(
            Name=trail_name,
            S3BucketName=bucket2_name
        )
        print(f"✓ S3 destination changed to {bucket2_name}")

        # Test 3: Update event selectors (add S3 data events)
        print("\nTest 3: Updating event selectors to include S3 data events...")
        wait_for_user(interactive, DELAY_SECONDS)
        cloudtrail.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    'ReadWriteType': 'All',
                    'IncludeManagementEvents': True,
                    'DataResources': [
                        {
                            'Type': 'AWS::S3::Object',
                            'Values': [f'arn:aws:s3:::{bucket1_name}/']
                        }
                    ]
                }
            ]
        )
        print("✓ Event selectors updated to include S3 data events")

        # Test 4: Delete trail
        print("\nTest 4: Deleting trail...")
        wait_for_user(interactive, DELAY_SECONDS)
        cloudtrail.delete_trail(Name=trail_name)
        print("✓ Trail deleted")

    except Exception as e:
        print(f"Error in CloudTrail test: {str(e)}")
    finally:
        # Cleanup
        print("Cleaning up CloudTrail resources...")
        try:
            # Stop logging first (required before deletion)
            try:
                cloudtrail.stop_logging(Name=trail_name)
            except:
                pass
            # Now delete the trail
            cloudtrail.delete_trail(Name=trail_name)
            print(f"✓ Cleaned up trail: {trail_name}")
        except Exception as e:
            print(f"Note: Could not delete trail: {str(e)}")

        delete_s3_bucket(s3, bucket1_name)
        delete_s3_bucket(s3, bucket2_name)


def test_guardduty(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """Test GuardDuty monitoring"""
    print(f"\n=== Testing GuardDuty in {region} ===")
    guardduty = session.client('guardduty', region_name=region)

    detector_id = None
    created_detector = False  # Track if we created the detector
    filter_name = f"aws-security-guard-test-filter-{test_name}"

    try:
        # Check for existing detectors
        print("Checking for existing GuardDuty detectors...")
        response = guardduty.list_detectors()

        if response['DetectorIds']:
            # Use existing detector
            detector_id = response['DetectorIds'][0]
            print(f"✓ Using existing detector: {detector_id}")
            created_detector = False
        else:
            # Create new detector
            print("Creating GuardDuty detector...")
            response = guardduty.create_detector(Enable=True)
            detector_id = response['DetectorId']
            created_detector = True
            print(f"✓ Created detector: {detector_id}")

        wait_for_user(interactive, DELAY_SECONDS, "Detector ready.")

        # Test 1: Create suppression rule
        print("\nTest 1: Creating suppression rule...")
        wait_for_user(interactive, DELAY_SECONDS)
        guardduty.create_filter(
            DetectorId=detector_id,
            Name=filter_name,
            Description="Test suppression rule",
            Action="ARCHIVE",
            FindingCriteria={
                'Criterion': {
                    'severity': {
                        'Gte': 0,
                        'Lte': 3
                    }
                }
            }
        )
        print(f"✓ Suppression rule created: {filter_name}")

        # Test 2: Update suppression rule
        print("\nTest 2: Updating suppression rule...")
        wait_for_user(interactive, DELAY_SECONDS)
        guardduty.update_filter(
            DetectorId=detector_id,
            FilterName=filter_name,
            Description="Updated test suppression rule",
            FindingCriteria={
                'Criterion': {
                    'severity': {
                        'Gte': 0,
                        'Lte': 5
                    }
                }
            }
        )
        print("✓ Suppression rule updated")

        # Test 3: Delete suppression rule
        print("\nTest 3: Deleting suppression rule...")
        wait_for_user(interactive, DELAY_SECONDS)
        guardduty.delete_filter(
            DetectorId=detector_id,
            FilterName=filter_name
        )
        print("✓ Suppression rule deleted")

        # Test 4: Suspend detector (only if we created it or it's already enabled)
        if created_detector:
            print("\nTest 4: Suspending GuardDuty detector...")
            wait_for_user(interactive, DELAY_SECONDS)
            guardduty.update_detector(
                DetectorId=detector_id,
                Enable=False
            )
            print("✓ Detector suspended")

            # Test 5: Delete detector
            print("\nTest 5: Deleting GuardDuty detector...")
            wait_for_user(interactive, DELAY_SECONDS)
            guardduty.delete_detector(DetectorId=detector_id)
            print("✓ Detector deleted")
            detector_id = None  # Set to None so cleanup doesn't try to delete again

    except Exception as e:
        print(f"Error in GuardDuty test: {str(e)}")
    finally:
        # Cleanup
        print("Cleaning up GuardDuty resources...")
        if detector_id:
            # Clean up filter (always try to delete test filter)
            try:
                guardduty.delete_filter(
                    DetectorId=detector_id,
                    FilterName=filter_name
                )
            except:
                pass

            # Only delete detector if we created it
            if created_detector:
                try:
                    guardduty.delete_detector(DetectorId=detector_id)
                    print(f"Deleted detector: {detector_id}")
                except Exception as e:
                    print(f"Error deleting detector: {str(e)}")
            else:
                print(f"Preserved existing detector: {detector_id}")


def test_s3_monitoring(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """Test S3 bucket monitoring"""
    print(f"\n=== Testing S3 Monitoring in {region} ===")
    cloudtrail = session.client('cloudtrail', region_name=region)
    s3 = session.client('s3', region_name=region)

    trail_name = f"aws-security-guard-test-trail-{test_name}"
    bucket_name = f"aws-security-guard-test-bucket-s3mon-{test_name}".lower()

    try:
        # Step 1: Create S3 bucket and CloudTrail trail together
        print(f"\nStep 1: Creating S3 bucket and CloudTrail trail...")
        create_s3_bucket(s3, bucket_name, region)
        print(f"✓ S3 bucket created: {bucket_name}")
        cloudtrail.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=False
        )
        cloudtrail.start_logging(Name=trail_name)
        print(f"✓ CloudTrail created and linked to S3 bucket: {trail_name}")
        wait_for_user(interactive, DELAY_SECONDS)

        # Test 2: Add encryption to bucket
        print("\nTest 2: Adding bucket encryption...")
        wait_for_user(interactive, DELAY_SECONDS)
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        print("✓ Encryption added")

        # Test 3: Upload some objects to create bucket size
        print("\nTest 3: Uploading objects to bucket...")
        wait_for_user(interactive, DELAY_SECONDS)
        for i in range(10):
            s3.put_object(
                Bucket=bucket_name,
                Key=f'test-object-{i}.txt',
                Body=b'X' * 1000000  # 1MB each = 10MB total
            )
        print("✓ Uploaded 10 objects (10MB total)")

        # Test 4: Delete most objects to trigger size reduction >50%
        print("\nTest 4: Deleting 8 objects to trigger size reduction...")
        wait_for_user(interactive, DELAY_SECONDS)
        for i in range(8):
            s3.delete_object(Bucket=bucket_name, Key=f'test-object-{i}.txt')
        print("✓ Deleted 8 objects (should trigger >50% size reduction alert)")

        # Test 5: Change encryption settings
        print("\nTest 5: Changing encryption settings...")
        wait_for_user(interactive, DELAY_SECONDS)
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms'
                        }
                    }
                ]
            }
        )
        print("✓ Encryption changed to KMS")

        # Test 6: Delete CloudTrail and bucket
        print("\nTest 6: Deleting CloudTrail and bucket...")
        wait_for_user(interactive, DELAY_SECONDS)
        cloudtrail.delete_trail(Name=trail_name)
        print("✓ CloudTrail deleted")

    except Exception as e:
        print(f"Error in S3 monitoring test: {str(e)}")
    finally:
        # Cleanup
        print("Cleaning up S3 monitoring test resources...")
        try:
            # Stop logging first (required before deletion)
            try:
                cloudtrail.stop_logging(Name=trail_name)
            except:
                pass
            cloudtrail.delete_trail(Name=trail_name)
            print(f"✓ Cleaned up trail: {trail_name}")
        except Exception as e:
            print(f"Note: Could not delete trail: {str(e)}")

        delete_s3_bucket(s3, bucket_name)


def test_sqs_monitoring(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """Test SQS queue monitoring"""
    print(f"\n=== Testing SQS Monitoring in {region} ===")
    cloudtrail = session.client('cloudtrail', region_name=region)
    s3 = session.client('s3', region_name=region)
    sqs = session.client('sqs', region_name=region)

    trail_name = f"aws-security-guard-test-trail-{test_name}"
    bucket_name = f"aws-security-guard-test-bucket-sqsmon-{test_name}".lower()
    queue_name = f"aws-security-guard-test-queue-{test_name}"
    queue_url = None

    try:
        # Create S3 bucket
        print(f"Creating S3 bucket: {bucket_name}")
        create_s3_bucket(s3, bucket_name, region)

        # Create CloudTrail to link the bucket
        print(f"Creating CloudTrail: {trail_name}")
        cloudtrail.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=False
        )
        cloudtrail.start_logging(Name=trail_name)
        print(f"✓ CloudTrail created and linked to S3 bucket")

        # Test 1: Create SQS queue
        print("\nTest 1: Creating SQS queue...")
        response = sqs.create_queue(
            QueueName=queue_name,
            Attributes={
                'MessageRetentionPeriod': '345600'  # 4 days
            }
        )
        queue_url = response['QueueUrl']

        # Get queue ARN
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])
        queue_arn = attrs['Attributes']['QueueArn']
        print(f"✓ SQS queue created: {queue_name}")
        wait_for_user(interactive, DELAY_SECONDS, "SQS queue created.")

        # Test 2: Configure S3 event notification to SQS
        print("\nTest 2: Configuring S3 event notification to SQS...")
        wait_for_user(interactive, DELAY_SECONDS)
        # Add permission to SQS to allow S3 to send messages
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:s3:::{bucket_name}"
                        }
                    }
                }
            ]
        }
        sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={'Policy': json.dumps(policy)}
        )

        # Configure S3 notification
        s3.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                'QueueConfigurations': [
                    {
                        'Id': 'test-notification',
                        'QueueArn': queue_arn,
                        'Events': ['s3:ObjectCreated:*']
                    }
                ]
            }
        )
        print("✓ S3 event notification configured to SQS")

        # Test 3: Add encryption to queue
        print("\nTest 3: Adding encryption to SQS queue...")
        wait_for_user(interactive, DELAY_SECONDS)
        sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                'KmsMasterKeyId': 'alias/aws/sqs',
                'KmsDataKeyReusePeriodSeconds': '300'
            }
        )
        print("✓ Encryption added to queue")

        # Test 4: Update queue policy
        print("\nTest 4: Updating queue access policy...")
        wait_for_user(interactive, DELAY_SECONDS)
        updated_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:s3:::{bucket_name}"
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sqs:GetQueueAttributes",
                    "Resource": queue_arn
                }
            ]
        }
        sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={'Policy': json.dumps(updated_policy)}
        )
        print("✓ Queue policy updated")

        # Test 5: Delete queue
        print("\nTest 5: Deleting SQS queue...")
        wait_for_user(interactive, DELAY_SECONDS)
        sqs.delete_queue(QueueUrl=queue_url)
        print("✓ Queue deleted")

    except Exception as e:
        print(f"Error in SQS monitoring test: {str(e)}")
    finally:
        # Cleanup
        print("Cleaning up SQS monitoring test resources...")
        if queue_url:
            try:
                sqs.delete_queue(QueueUrl=queue_url)
            except:
                pass

        try:
            # Stop logging first (required before deletion)
            try:
                cloudtrail.stop_logging(Name=trail_name)
            except:
                pass
            cloudtrail.delete_trail(Name=trail_name)
            print(f"✓ Cleaned up trail: {trail_name}")
        except Exception as e:
            print(f"Note: Could not delete trail: {str(e)}")

        delete_s3_bucket(s3, bucket_name)


def test_sns_monitoring(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """Test SNS monitoring via S3 event notifications"""
    print(f"\n=== Testing SNS Monitoring in {region} ===")

    s3 = session.client('s3', region_name=region)
    sns_client = session.client('sns', region_name=region)
    cloudtrail = session.client('cloudtrail', region_name=region)
    sts = session.client('sts')

    account_id = sts.get_caller_identity()['Account']
    bucket_name = f"aws-security-guard-test-bucket1-{test_name}"
    trail_name = f"aws-security-guard-test-trail-{test_name}"
    topic_name = f"aws-security-guard-test-topic-{test_name}"
    topic_arn = None

    try:
        # Create S3 bucket for CloudTrail
        print(f"Test Setup: Creating S3 bucket and CloudTrail trail...")
        bucket_name = create_s3_bucket(s3, bucket_name, region)

        # Create CloudTrail trail
        cloudtrail.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name
        )
        cloudtrail.start_logging(Name=trail_name)
        print(f"Created CloudTrail trail: {trail_name}")

        # Test 1: Create SNS topic and configure as S3 event destination
        print("\nTest 1: Create SNS topic for S3 notifications")
        topic_response = sns_client.create_topic(Name=topic_name)
        topic_arn = topic_response['TopicArn']
        print(f"Created SNS topic: {topic_arn}")

        # Add topic policy to allow S3 to publish
        topic_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "SNS:Publish",
                    "Resource": topic_arn,
                    "Condition": {
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:s3:::{bucket_name}"
                        }
                    }
                }
            ]
        }
        sns_client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName='Policy',
            AttributeValue=json.dumps(topic_policy)
        )

        # Configure S3 to send notifications to SNS
        s3.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                'TopicConfigurations': [
                    {
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'Key': {
                                'FilterRules': [
                                    {'Name': 'prefix', 'Value': 'AWSLogs/'},
                                    {'Name': 'suffix', 'Value': '.gz'}
                                ]
                            }
                        }
                    }
                ]
            }
        )
        print(f"Configured S3 bucket to send notifications to SNS topic")
        wait_for_user(interactive, DELAY_SECONDS, f"Wait {DELAY_SECONDS}s for monitoring to detect SNS topic creation")

        # Test 2: Create subscription
        print("\nTest 2: Add email subscription to SNS topic")
        subscription_response = sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol='email',
            Endpoint='test@example.com'
        )
        print(f"Added subscription (pending confirmation): {subscription_response['SubscriptionArn']}")
        wait_for_user(interactive, DELAY_SECONDS, f"Wait {DELAY_SECONDS}s for monitoring to detect subscription creation")

        # Test 3: Enable encryption on SNS topic
        print("\nTest 3: Enable encryption on SNS topic")
        wait_for_user(interactive, DELAY_SECONDS)
        sns_client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName='KmsMasterKeyId',
            AttributeValue='alias/aws/sns'
        )
        print(f"✓ Enabled encryption on SNS topic (using AWS managed key)")

        # Test 4: Update topic policy
        print("\nTest 4: Update SNS topic policy")
        wait_for_user(interactive, DELAY_SECONDS)
        updated_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "SNS:Publish",
                    "Resource": topic_arn,
                    "Condition": {
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:s3:::{bucket_name}"
                        }
                    }
                },
                {
                    "Sid": "AllowAccountAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "SNS:GetTopicAttributes",
                    "Resource": topic_arn
                }
            ]
        }
        sns_client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName='Policy',
            AttributeValue=json.dumps(updated_policy)
        )
        print(f"✓ Updated SNS topic policy")

        # Test 5: Delete topic (should be detected as topic deletion)
        print("\nTest 5: Delete SNS topic")
        wait_for_user(interactive, DELAY_SECONDS)
        # First remove S3 notification configuration
        s3.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={}
        )
        print(f"✓ Removed S3 notification configuration")
        wait_for_user(interactive, DELAY_SECONDS)

        # Now delete the topic
        sns_client.delete_topic(TopicArn=topic_arn)
        print(f"✓ Deleted SNS topic: {topic_arn}")
        topic_arn = None  # Mark as deleted

        print("\n=== SNS Monitoring Tests Completed ===\n")

    finally:
        # Cleanup
        print("\nCleaning up test resources...")
        try:
            if topic_arn:
                try:
                    # Remove S3 notifications first
                    s3.put_bucket_notification_configuration(
                        Bucket=bucket_name,
                        NotificationConfiguration={}
                    )
                except Exception:
                    pass
                try:
                    sns_client.delete_topic(TopicArn=topic_arn)
                    print(f"Deleted SNS topic: {topic_arn}")
                except Exception as e:
                    print(f"Note: Could not delete SNS topic: {str(e)}")
        except Exception:
            pass

        try:
            cloudtrail.stop_logging(Name=trail_name)
            cloudtrail.delete_trail(Name=trail_name)
            print(f"Deleted CloudTrail trail: {trail_name}")
        except Exception as e:
            print(f"Note: Could not delete CloudTrail trail: {str(e)}")

        try:
            delete_s3_bucket(s3, bucket_name)
        except Exception:
            pass


def test_eventbridge(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """Test EventBridge monitoring"""
    print(f"\n=== Testing EventBridge in {region} ===")
    events = session.client('events', region_name=region)

    rule_name = f"aws-security-guard-test-rule-{test_name}"

    try:
        # Test 1: Create rule
        print("\nTest 1: Creating EventBridge rule...")
        wait_for_user(interactive, DELAY_SECONDS)
        events.put_rule(
            Name=rule_name,
            State='ENABLED',
            Description='Test EventBridge rule',
            EventPattern=json.dumps({
                'source': ['aws.ec2'],
                'detail-type': ['EC2 Instance State-change Notification']
            })
        )
        print(f"✓ EventBridge rule created: {rule_name}")

        # Test 2: Update rule (change state)
        print("\nTest 2: Disabling EventBridge rule...")
        wait_for_user(interactive, DELAY_SECONDS)
        events.put_rule(
            Name=rule_name,
            State='DISABLED',
            Description='Test EventBridge rule',
            EventPattern=json.dumps({
                'source': ['aws.ec2'],
                'detail-type': ['EC2 Instance State-change Notification']
            })
        )
        print("✓ Rule disabled")

        # Test 3: Update rule (change event pattern)
        print("\nTest 3: Updating EventBridge rule pattern...")
        wait_for_user(interactive, DELAY_SECONDS)
        events.put_rule(
            Name=rule_name,
            State='ENABLED',
            Description='Updated test rule',
            EventPattern=json.dumps({
                'source': ['aws.s3'],
                'detail-type': ['Object Created']
            })
        )
        print("✓ Rule pattern updated and re-enabled")

        # Test 4: Delete rule
        print("\nTest 4: Deleting EventBridge rule...")
        wait_for_user(interactive, DELAY_SECONDS)
        events.delete_rule(Name=rule_name)
        print("✓ Rule deleted")

    except Exception as e:
        print(f"Error in EventBridge test: {str(e)}")
    finally:
        # Cleanup
        print("Cleaning up EventBridge resources...")
        try:
            events.delete_rule(Name=rule_name)
        except:
            pass


def test_iam_monitoring(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """
    Test IAM role monitoring including Lambda execution roles and service roles

    Tests:
    - Lambda execution role creation and monitoring
    - Service roles with monitored service principals (Lambda, S3, SNS, SQS, CloudTrail)
    - Trust policy modifications
    - Permission policy changes (managed and inline)
    - Multiple service principals in one role
    """
    print(f"\n=== Testing IAM Monitoring in {region} ===")

    iam = session.client('iam')
    lambda_client = session.client('lambda', region_name=region)
    s3 = session.client('s3')

    # Role names
    lambda_exec_role = f"aws-security-guard-test-lambda-exec-{test_name}"
    lambda_service_role = f"aws-security-guard-test-lambda-svc-{test_name}"
    s3_service_role = f"aws-security-guard-test-s3-svc-{test_name}"
    multi_service_role = f"aws-security-guard-test-multi-svc-{test_name}"

    lambda_function_name = f"aws-security-guard-test-lambda-{test_name}"
    bucket_name = f"aws-security-guard-test-bucket-iam-{test_name}".lower()

    created_roles = []
    lambda_exec_role_arn = None
    function_arn = None

    try:
        # Step 1: Create Lambda execution role and function
        print("\n--- Step 1: Creating Lambda execution role and function ---")
        wait_for_user(interactive, DELAY_SECONDS)

        # Create trust policy for Lambda
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        role_response = iam.create_role(
            RoleName=lambda_exec_role,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Test Lambda execution role for IAM monitoring",
            MaxSessionDuration=3600
        )
        lambda_exec_role_arn = role_response['Role']['Arn']
        created_roles.append(lambda_exec_role)
        print(f"✓ Created Lambda execution role: {lambda_exec_role}")

        # Attach a managed policy
        iam.attach_role_policy(
            RoleName=lambda_exec_role,
            PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        )
        print(f"✓ Attached managed policy: AWSLambdaBasicExecutionRole")

        # Create a simple Lambda function to link the role to the ecosystem
        # First create S3 bucket for deployment package
        create_s3_bucket(s3, bucket_name, region)

        # Create a minimal Lambda deployment package
        lambda_code = """
def lambda_handler(event, context):
    return {'statusCode': 200, 'body': 'Hello from test Lambda'}
"""
        import zipfile
        import io
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr('lambda_function.py', lambda_code)
        zip_buffer.seek(0)

        # Create Lambda function
        import time
        time.sleep(10)  # Wait for role to propagate

        lambda_response = lambda_client.create_function(
            FunctionName=lambda_function_name,
            Runtime='python3.11',
            Role=lambda_exec_role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_buffer.read()},
            Timeout=30,
            MemorySize=128
        )
        function_arn = lambda_response['FunctionArn']
        print(f"✓ Created Lambda function: {lambda_function_name}")

        # Step 2: Update Lambda execution role trust policy
        print("\n--- Step 2: Updating Lambda execution role trust policy ---")
        wait_for_user(interactive, DELAY_SECONDS)

        updated_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["lambda.amazonaws.com", "ec2.amazonaws.com"]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        iam.update_assume_role_policy(
            RoleName=lambda_exec_role,
            PolicyDocument=json.dumps(updated_trust_policy)
        )
        print("✓ Updated trust policy (added EC2 service)")

        # Step 3: Add inline policy
        print("\n--- Step 3: Adding inline policy to Lambda execution role ---")
        wait_for_user(interactive, DELAY_SECONDS)

        inline_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*"
                }
            ]
        }

        iam.put_role_policy(
            RoleName=lambda_exec_role,
            PolicyName='TestInlinePolicy',
            PolicyDocument=json.dumps(inline_policy)
        )
        print("✓ Added inline policy: TestInlinePolicy")

        # Step 4: Create Lambda service role
        print("\n--- Step 4: Creating Lambda service role ---")
        wait_for_user(interactive, DELAY_SECONDS)

        lambda_svc_trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        }

        iam.create_role(
            RoleName=lambda_service_role,
            AssumeRolePolicyDocument=json.dumps(lambda_svc_trust),
            Description='Lambda service role'
        )
        created_roles.append(lambda_service_role)
        print(f"✓ Created Lambda service role: {lambda_service_role}")

        # Step 5: Create S3 service role with inline policy
        print("\n--- Step 5: Creating S3 service role ---")
        wait_for_user(interactive, DELAY_SECONDS)

        s3_svc_trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        }

        iam.create_role(
            RoleName=s3_service_role,
            AssumeRolePolicyDocument=json.dumps(s3_svc_trust),
            Description='S3 service role'
        )
        created_roles.append(s3_service_role)
        print(f"✓ Created S3 service role: {s3_service_role}")

        s3_inline_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["sns:Publish"], "Resource": "*"}]
        }

        iam.put_role_policy(
            RoleName=s3_service_role,
            PolicyName='S3NotificationPolicy',
            PolicyDocument=json.dumps(s3_inline_policy)
        )
        print(f"✓ Added inline policy to S3 service role")

        # Step 6: Create multi-service role
        print("\n--- Step 6: Creating multi-service role (Lambda + SNS + SQS) ---")
        wait_for_user(interactive, DELAY_SECONDS)

        multi_svc_trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": ["lambda.amazonaws.com", "sns.amazonaws.com", "sqs.amazonaws.com"]},
                "Action": "sts:AssumeRole"
            }]
        }

        iam.create_role(
            RoleName=multi_service_role,
            AssumeRolePolicyDocument=json.dumps(multi_svc_trust),
            Description='Multi-service role'
        )
        created_roles.append(multi_service_role)
        print(f"✓ Created multi-service role: {multi_service_role}")

        # Step 7: Modify Lambda service role trust policy
        print("\n--- Step 7: Modifying Lambda service role trust policy ---")
        wait_for_user(interactive, DELAY_SECONDS)

        modified_svc_trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": ["lambda.amazonaws.com", "cloudtrail.amazonaws.com"]},
                "Action": "sts:AssumeRole"
            }]
        }

        iam.update_assume_role_policy(
            RoleName=lambda_service_role,
            PolicyDocument=json.dumps(modified_svc_trust)
        )
        print(f"✓ Modified trust policy for {lambda_service_role} (added CloudTrail)")

        # Step 8: Update S3 service role permissions
        print("\n--- Step 8: Updating S3 service role permissions ---")
        wait_for_user(interactive, DELAY_SECONDS)

        updated_s3_inline = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["sns:Publish", "sqs:SendMessage"], "Resource": "*"}]
        }

        iam.put_role_policy(
            RoleName=s3_service_role,
            PolicyName='S3NotificationPolicy',
            PolicyDocument=json.dumps(updated_s3_inline)
        )
        print(f"✓ Updated inline policy for {s3_service_role} (added SQS)")

        # Step 9: Clean up
        print("\n--- Step 9: Cleaning up test resources ---")
        wait_for_user(interactive, DELAY_SECONDS)

        # Delete Lambda function
        lambda_client.delete_function(FunctionName=lambda_function_name)
        print(f"✓ Deleted Lambda function: {lambda_function_name}")
        function_arn = None

    except Exception as e:
        print(f"Error in IAM monitoring test: {str(e)}")
    finally:
        # Cleanup
        print("\n--- Cleaning up IAM monitoring test resources ---")

        # Delete Lambda function
        if function_arn:
            try:
                lambda_client.delete_function(FunctionName=lambda_function_name)
                print(f"✓ Cleaned up Lambda function: {lambda_function_name}")
            except Exception as e:
                print(f"Note: Could not delete Lambda function: {str(e)}")

        # Delete all IAM roles
        for role_name in created_roles:
            try:
                # Detach all managed policies
                try:
                    attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                    for policy in attached_policies.get('AttachedPolicies', []):
                        try:
                            iam.detach_role_policy(
                                RoleName=role_name,
                                PolicyArn=policy['PolicyArn']
                            )
                        except:
                            pass
                except:
                    pass

                # Delete all inline policies
                try:
                    inline_policies = iam.list_role_policies(RoleName=role_name)
                    for policy_name in inline_policies.get('PolicyNames', []):
                        try:
                            iam.delete_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name
                            )
                        except:
                            pass
                except:
                    pass

                # Delete the role
                iam.delete_role(RoleName=role_name)
                print(f"✓ Cleaned up IAM role: {role_name}")
            except Exception as e:
                print(f"Note: Could not delete IAM role {role_name}: {str(e)}")

        # Delete S3 bucket
        delete_s3_bucket(s3, bucket_name)


def generate_random_test_name(length: int = 8) -> str:
    """Generate a random test name using lowercase letters and digits"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def cleanup_all_test_resources(session: boto3.Session, region: str = None, all_regions: bool = False) -> None:
    """
    Comprehensive cleanup of all test resources with 'aws-security-guard-test' prefix

    Args:
        session: boto3 session with appropriate credentials
        region: Specific region to clean (default: session's default region)
        all_regions: If True, clean resources across all available regions
    """
    print("\n" + "=" * 70)
    print("=== CLEANUP: Removing all aws-security-guard-test resources ===")
    print("=" * 70)

    # Determine regions to clean
    if all_regions:
        ec2 = session.client('ec2')
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        print(f"\nCleaning resources in ALL regions ({len(regions)} regions)")
    else:
        if region:
            regions = [region]
        else:
            regions = [session.region_name or 'us-east-1']
        print(f"\nCleaning resources in region: {regions[0]}")

    total_cleaned = {
        'cloudtrail_trails': 0,
        's3_buckets': 0,
        'sqs_queues': 0,
        'sns_topics': 0,
        'guardduty_filters': 0,
        'guardduty_detectors': 0,
        'eventbridge_rules': 0,
        'lambda_functions': 0,
        'iam_roles': 0
    }

    for region_name in regions:
        print(f"\n--- Cleaning region: {region_name} ---")

        # 1. Clean CloudTrail trails
        try:
            cloudtrail = session.client('cloudtrail', region_name=region_name)
            response = cloudtrail.list_trails()
            for trail_info in response.get('Trails', []):
                # Name field can be either trail name or ARN (if trail is in different region)
                # TrailARN is always the full ARN
                trail_arn = trail_info.get('TrailARN', trail_info['Name'])

                # Extract trail name from ARN for display and filtering
                if trail_arn.startswith('arn:aws:cloudtrail:'):
                    trail_name = trail_arn.split('/')[-1]
                else:
                    trail_name = trail_arn

                if 'aws-security-guard-test' in trail_name.lower():
                    try:
                        # Stop logging first (use ARN for cross-region trails)
                        try:
                            cloudtrail.stop_logging(Name=trail_arn)
                        except:
                            pass

                        # Delete trail (use ARN to handle cross-region trails)
                        cloudtrail.delete_trail(Name=trail_arn)
                        print(f"✓ Deleted CloudTrail trail: {trail_name}")
                        total_cleaned['cloudtrail_trails'] += 1
                    except Exception as e:
                        print(f"✗ Failed to delete trail {trail_name}: {str(e)}")
        except Exception as e:
            print(f"Error listing CloudTrail trails in {region_name}: {str(e)}")

        # 2. Clean S3 buckets (S3 is global, only check once)
        if region_name == regions[0] or not all_regions:
            try:
                s3 = session.client('s3')
                response = s3.list_buckets()
                for bucket in response.get('Buckets', []):
                    bucket_name = bucket['Name']
                    if 'aws-security-guard-test' in bucket_name.lower():
                        try:
                            # Get bucket region
                            try:
                                bucket_region = s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
                                if bucket_region is None:
                                    bucket_region = 'us-east-1'
                            except:
                                bucket_region = 'us-east-1'

                            # Only delete if we're cleaning all regions or it's in our target region
                            if all_regions or bucket_region == region_name:
                                delete_s3_bucket(s3, bucket_name)
                                total_cleaned['s3_buckets'] += 1
                        except Exception as e:
                            print(f"✗ Failed to delete bucket {bucket_name}: {str(e)}")
            except Exception as e:
                print(f"Error listing S3 buckets: {str(e)}")

        # 3. Clean SQS queues
        try:
            sqs = session.client('sqs', region_name=region_name)
            response = sqs.list_queues(QueueNamePrefix='aws-security-guard-test')
            for queue_url in response.get('QueueUrls', []):
                try:
                    sqs.delete_queue(QueueUrl=queue_url)
                    print(f"✓ Deleted SQS queue: {queue_url.split('/')[-1]}")
                    total_cleaned['sqs_queues'] += 1
                except Exception as e:
                    print(f"✗ Failed to delete queue {queue_url}: {str(e)}")
        except Exception as e:
            if 'NonExistentQueue' not in str(e):
                print(f"Error listing SQS queues in {region_name}: {str(e)}")

        # 4. Clean SNS topics
        try:
            sns = session.client('sns', region_name=region_name)
            paginator = sns.get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page.get('Topics', []):
                    topic_arn = topic['TopicArn']
                    topic_name = topic_arn.split(':')[-1]
                    if 'aws-security-guard-test' in topic_name.lower():
                        try:
                            sns.delete_topic(TopicArn=topic_arn)
                            print(f"✓ Deleted SNS topic: {topic_name}")
                            total_cleaned['sns_topics'] += 1
                        except Exception as e:
                            print(f"✗ Failed to delete topic {topic_name}: {str(e)}")
        except Exception as e:
            print(f"Error listing SNS topics in {region_name}: {str(e)}")

        # 5. Clean GuardDuty filters (but preserve existing detectors)
        try:
            guardduty = session.client('guardduty', region_name=region_name)
            detector_response = guardduty.list_detectors()
            for detector_id in detector_response.get('DetectorIds', []):
                try:
                    filter_response = guardduty.list_filters(DetectorId=detector_id)
                    for filter_name in filter_response.get('FilterNames', []):
                        if 'aws-security-guard-test' in filter_name.lower():
                            try:
                                guardduty.delete_filter(DetectorId=detector_id, FilterName=filter_name)
                                print(f"✓ Deleted GuardDuty filter: {filter_name}")
                                total_cleaned['guardduty_filters'] += 1
                            except Exception as e:
                                print(f"✗ Failed to delete filter {filter_name}: {str(e)}")
                except Exception:
                    pass
        except Exception as e:
            print(f"Error listing GuardDuty resources in {region_name}: {str(e)}")

        # 6. Clean EventBridge rules
        try:
            events = session.client('events', region_name=region_name)
            paginator = events.get_paginator('list_rules')
            for page in paginator.paginate():
                for rule in page.get('Rules', []):
                    rule_name = rule['Name']
                    if 'aws-security-guard-test' in rule_name.lower():
                        try:
                            # Remove targets first
                            try:
                                targets_response = events.list_targets_by_rule(Rule=rule_name)
                                target_ids = [t['Id'] for t in targets_response.get('Targets', [])]
                                if target_ids:
                                    events.remove_targets(Rule=rule_name, Ids=target_ids)
                            except:
                                pass
                            # Now delete the rule
                            events.delete_rule(Name=rule_name)
                            print(f"✓ Deleted EventBridge rule: {rule_name}")
                            total_cleaned['eventbridge_rules'] += 1
                        except Exception as e:
                            print(f"✗ Failed to delete rule {rule_name}: {str(e)}")
        except Exception as e:
            print(f"Error listing EventBridge rules in {region_name}: {str(e)}")

        # 7. Clean Lambda functions
        try:
            lambda_client = session.client('lambda', region_name=region_name)
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page.get('Functions', []):
                    function_name = function['FunctionName']
                    if 'aws-security-guard-test' in function_name.lower():
                        try:
                            lambda_client.delete_function(FunctionName=function_name)
                            print(f"✓ Deleted Lambda function: {function_name}")
                            total_cleaned['lambda_functions'] += 1
                        except Exception as e:
                            print(f"✗ Failed to delete function {function_name}: {str(e)}")
        except Exception as e:
            print(f"Error listing Lambda functions in {region_name}: {str(e)}")

    # 8. Clean IAM roles (only once, IAM is global)
    if regions:
        try:
            iam = session.client('iam')
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    role_name = role['RoleName']
                    if 'aws-security-guard-test' in role_name.lower():
                        try:
                            # Detach all managed policies
                            try:
                                attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                                for policy in attached_policies.get('AttachedPolicies', []):
                                    try:
                                        iam.detach_role_policy(
                                            RoleName=role_name,
                                            PolicyArn=policy['PolicyArn']
                                        )
                                    except:
                                        pass
                            except:
                                pass

                            # Delete all inline policies
                            try:
                                inline_policies = iam.list_role_policies(RoleName=role_name)
                                for policy_name in inline_policies.get('PolicyNames', []):
                                    try:
                                        iam.delete_role_policy(
                                            RoleName=role_name,
                                            PolicyName=policy_name
                                        )
                                    except:
                                        pass
                            except:
                                pass

                            # Delete the role
                            iam.delete_role(RoleName=role_name)
                            print(f"✓ Deleted IAM role: {role_name}")
                            total_cleaned['iam_roles'] += 1
                        except Exception as e:
                            print(f"✗ Failed to delete role {role_name}: {str(e)}")
        except Exception as e:
            print(f"Error listing IAM roles: {str(e)}")

    # Print summary
    print("\n" + "=" * 70)
    print("=== Cleanup Summary ===")
    print("=" * 70)
    for resource_type, count in total_cleaned.items():
        if count > 0:
            print(f"  {resource_type.replace('_', ' ').title()}: {count}")

    total = sum(total_cleaned.values())
    if total == 0:
        print("  No test resources found to clean up")
    else:
        print(f"\nTotal resources cleaned: {total}")
    print("=" * 70 + "\n")


def main():
    """Main test function"""
    import sys
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='AWS Security Watch Test Suite')
    parser.add_argument('--profile', type=str, help='AWS profile name to use')
    parser.add_argument('--region', type=str, help='AWS region to test in (default: randomized per test)')
    parser.add_argument('--test-name', type=str, help='Test name (auto-generated if not provided)')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode: press Enter to proceed instead of waiting')
    parser.add_argument('--service', type=str, choices=['cloudtrail', 's3', 'sqs', 'sns', 'guardduty', 'eventbridge', 'iam', 'all'],
                        default='all', help='Service to test (default: all)')
    parser.add_argument('--cleanup', action='store_true', help='Clean up all test resources and exit')
    parser.add_argument('--cleanup-all-regions', action='store_true', help='Clean up test resources in ALL regions (use with --cleanup)')
    args = parser.parse_args()

    # Create session with profile if specified
    if args.profile:
        session = boto3.Session(profile_name=args.profile)
    else:
        session = boto3.Session()

    # Handle cleanup mode
    if args.cleanup:
        cleanup_all_test_resources(
            session=session,
            region=args.region,
            all_regions=args.cleanup_all_regions
        )
        return

    # Generate random test name if not provided
    if args.test_name:
        test_name = args.test_name
    else:
        test_name = generate_random_test_name()
        print(f"No test name provided, using generated name: {test_name}")

    # Define available regions for testing
    available_regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
        'ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2'
    ]

    # Randomly select a region for each test (or use specified region)
    if args.region:
        test_region = args.region
        print(f"\nAWS Security Watch Test Suite")
        print("=" * 50)
        if args.profile:
            print(f"Using AWS profile: {args.profile}")
        print(f"Test Name: {test_name}")
        print(f"Region: {args.region}")
        print(f"Service: {args.service}")
    else:
        test_region = random.choice(available_regions)
        print(f"\nAWS Security Watch Test Suite")
        print("=" * 50)
        if args.profile:
            print(f"Using AWS profile: {args.profile}")
        print(f"Test Name: {test_name}")
        print(f"Region: {test_region} (randomized)")
        print(f"Service: {args.service}")

    if args.interactive:
        print(f"Mode: Interactive (press Enter to proceed)")
    else:
        print(f"Mode: Automated (2-minute delays between steps)")
    print("=" * 50)
    print()

    # Run tests based on service filter
    if args.service in ['cloudtrail', 'all']:
        test_cloudtrail(session, test_region, test_name, args.interactive)

    if args.service in ['s3', 'all']:
        test_s3_monitoring(session, test_region, test_name, args.interactive)

    if args.service in ['sqs', 'all']:
        test_sqs_monitoring(session, test_region, test_name, args.interactive)

    if args.service in ['sns', 'all']:
        test_sns_monitoring(session, test_region, test_name, args.interactive)

    if args.service in ['guardduty', 'all']:
        test_guardduty(session, test_region, test_name, args.interactive)

    if args.service in ['eventbridge', 'all']:
        test_eventbridge(session, test_region, test_name, args.interactive)

    if args.service in ['iam', 'all']:
        test_iam_monitoring(session, test_region, test_name, args.interactive)

    print("\n" + "=" * 50)
    print("=== All tests completed ===")
    print("=" * 50)


if __name__ == '__main__':
    main()
