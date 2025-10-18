#!/usr/bin/env python3
"""
Test Infrastructure Script

Creates, modifies, and deletes AWS resources to test AWS Security Watch functionality.
Tests the following scenarios:
- CloudTrail: StopLogging, S3 bucket changes, event selector changes, DeleteTrail
- GuardDuty: Suppression rule creation/modification/deletion, publishing destination changes
- EventBridge: Rule creation/modification/deletion
"""

import boto3
import time
import json
import random
import string
from typing import Dict, Any, List
from botocore.exceptions import ClientError


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

    trail_name = f"aws-security-watch-test-trail-{test_name}"
    bucket1_name = f"aws-security-watch-test-bucket1-{test_name}".lower()
    bucket2_name = f"aws-security-watch-test-bucket2-{test_name}".lower()

    delay_seconds = 120  # 2 minutes

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
        wait_for_user(interactive, delay_seconds, "Trail created and logging started.")

        # Test 1: Stop logging
        print("\nTest 1: Stopping logging...")
        cloudtrail.stop_logging(Name=trail_name)
        print("✓ Logging stopped")
        wait_for_user(interactive, delay_seconds)

        # Restart logging for next test
        print("\nRestarting logging...")
        cloudtrail.start_logging(Name=trail_name)
        print("✓ Logging restarted")
        wait_for_user(interactive, delay_seconds)

        # Test 2: Change S3 destination
        print("\nTest 2: Changing S3 destination...")
        cloudtrail.update_trail(
            Name=trail_name,
            S3BucketName=bucket2_name
        )
        print(f"✓ S3 destination changed to {bucket2_name}")
        wait_for_user(interactive, delay_seconds)

        # Test 3: Update event selectors
        print("\nTest 3: Updating event selectors...")
        cloudtrail.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    'ReadWriteType': 'All',
                    'IncludeManagementEvents': True,
                    'DataResources': []
                }
            ]
        )
        print("✓ Event selectors updated")
        wait_for_user(interactive, delay_seconds)

        # Test 4: Delete trail
        print("\nTest 4: Deleting trail...")
        cloudtrail.delete_trail(Name=trail_name)
        print("✓ Trail deleted")

    except Exception as e:
        print(f"Error in CloudTrail test: {str(e)}")
    finally:
        # Cleanup
        print("Cleaning up CloudTrail resources...")
        try:
            cloudtrail.delete_trail(Name=trail_name)
        except:
            pass

        delete_s3_bucket(s3, bucket1_name)
        delete_s3_bucket(s3, bucket2_name)


def test_guardduty(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """Test GuardDuty monitoring"""
    print(f"\n=== Testing GuardDuty in {region} ===")
    guardduty = session.client('guardduty', region_name=region)

    detector_id = None
    created_detector = False  # Track if we created the detector
    filter_name = f"aws-security-watch-test-filter-{test_name}"
    delay_seconds = 120  # 2 minutes

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

        wait_for_user(interactive, delay_seconds, "Detector ready.")

        # Test 1: Create suppression rule
        print("\nTest 1: Creating suppression rule...")
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
        wait_for_user(interactive, delay_seconds)

        # Test 2: Update suppression rule
        print("\nTest 2: Updating suppression rule...")
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
        wait_for_user(interactive, delay_seconds)

        # Test 3: Delete suppression rule
        print("\nTest 3: Deleting suppression rule...")
        guardduty.delete_filter(
            DetectorId=detector_id,
            FilterName=filter_name
        )
        print("✓ Suppression rule deleted")
        wait_for_user(interactive, delay_seconds)

        # Test 4: Suspend detector (only if we created it or it's already enabled)
        if created_detector:
            print("\nTest 4: Suspending GuardDuty detector...")
            guardduty.update_detector(
                DetectorId=detector_id,
                Enable=False
            )
            print("✓ Detector suspended")
            wait_for_user(interactive, delay_seconds)

            # Test 5: Delete detector
            print("\nTest 5: Deleting GuardDuty detector...")
            guardduty.delete_detector(DetectorId=detector_id)
            print("✓ Detector deleted")
            detector_id = None  # Set to None so cleanup doesn't try to delete again
            wait_for_user(interactive, delay_seconds)

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

    trail_name = f"aws-security-watch-test-trail-{test_name}"
    bucket_name = f"aws-security-watch-test-bucket-s3mon-{test_name}".lower()

    delay_seconds = 120  # 2 minutes

    try:
        # Create S3 bucket
        print(f"Creating S3 bucket: {bucket_name}")
        create_s3_bucket(s3, bucket_name, region)
        wait_for_user(interactive, delay_seconds, "S3 bucket created.")

        # Create CloudTrail to link the bucket
        print(f"Creating CloudTrail: {trail_name}")
        cloudtrail.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=False
        )
        cloudtrail.start_logging(Name=trail_name)
        print(f"✓ CloudTrail created and linked to S3 bucket")
        wait_for_user(interactive, delay_seconds)

        # Test 1: Add encryption to bucket
        print("\nTest 1: Adding bucket encryption...")
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
        wait_for_user(interactive, delay_seconds)

        # Test 2: Configure S3 event notification (we'll need a dummy SQS queue for this)
        # For now, we'll skip this in the basic test since it requires SQS setup
        # This will be tested more thoroughly in the comprehensive ecosystem test

        # Test 3: Upload some objects to create bucket size
        print("\nTest 3: Uploading objects to bucket...")
        for i in range(10):
            s3.put_object(
                Bucket=bucket_name,
                Key=f'test-object-{i}.txt',
                Body=b'X' * 1000000  # 1MB each = 10MB total
            )
        print("✓ Uploaded 10 objects (10MB total)")
        wait_for_user(interactive, delay_seconds)

        # Test 4: Delete most objects to trigger size reduction >50%
        print("\nTest 4: Deleting 8 objects to trigger size reduction...")
        for i in range(8):
            s3.delete_object(Bucket=bucket_name, Key=f'test-object-{i}.txt')
        print("✓ Deleted 8 objects (should trigger >50% size reduction alert)")
        wait_for_user(interactive, delay_seconds)

        # Test 5: Change encryption settings
        print("\nTest 5: Changing encryption settings...")
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
        wait_for_user(interactive, delay_seconds)

        # Test 6: Delete CloudTrail and bucket
        print("\nTest 6: Deleting CloudTrail and bucket...")
        cloudtrail.delete_trail(Name=trail_name)
        print("✓ CloudTrail deleted")

    except Exception as e:
        print(f"Error in S3 monitoring test: {str(e)}")
    finally:
        # Cleanup
        print("Cleaning up S3 monitoring test resources...")
        try:
            cloudtrail.delete_trail(Name=trail_name)
        except:
            pass

        delete_s3_bucket(s3, bucket_name)


def test_eventbridge(session: boto3.Session, region: str, test_name: str, interactive: bool = False) -> None:
    """Test EventBridge monitoring"""
    print(f"\n=== Testing EventBridge in {region} ===")
    events = session.client('events', region_name=region)

    rule_name = f"aws-security-watch-test-rule-{test_name}"
    delay_seconds = 120  # 2 minutes

    try:
        # Test 1: Create rule
        print("Test 1: Creating EventBridge rule...")
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
        wait_for_user(interactive, delay_seconds, "Rule created.")

        # Test 2: Update rule (change state)
        print("\nTest 2: Disabling EventBridge rule...")
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
        wait_for_user(interactive, delay_seconds)

        # Test 3: Update rule (change event pattern)
        print("\nTest 3: Updating EventBridge rule pattern...")
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
        wait_for_user(interactive, delay_seconds)

        # Test 4: Delete rule
        print("\nTest 4: Deleting EventBridge rule...")
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


def generate_random_test_name(length: int = 8) -> str:
    """Generate a random test name using lowercase letters and digits"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


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
    args = parser.parse_args()

    # Generate random test name if not provided
    if args.test_name:
        test_name = args.test_name
    else:
        test_name = generate_random_test_name()
        print(f"No test name provided, using generated name: {test_name}")

    # Create session with profile if specified
    if args.profile:
        session = boto3.Session(profile_name=args.profile)
    else:
        session = boto3.Session()

    # Define available regions for testing
    available_regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
        'ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2'
    ]

    # Randomly select a region for each test (or use specified region)
    if args.region:
        cloudtrail_region = args.region
        guardduty_region = args.region
        eventbridge_region = args.region
        print(f"\nAWS Security Watch Test Suite")
        print("=" * 50)
        if args.profile:
            print(f"Using AWS profile: {args.profile}")
        print(f"Test Name: {test_name}")
        print(f"Region: {args.region} (all tests)")
    else:
        cloudtrail_region = random.choice(available_regions)
        guardduty_region = random.choice(available_regions)
        eventbridge_region = random.choice(available_regions)
        print(f"\nAWS Security Watch Test Suite")
        print("=" * 50)
        if args.profile:
            print(f"Using AWS profile: {args.profile}")
        print(f"Test Name: {test_name}")
        print(f"CloudTrail Region: {cloudtrail_region}")
        print(f"GuardDuty Region: {guardduty_region}")
        print(f"EventBridge Region: {eventbridge_region}")

    if args.interactive:
        print(f"Mode: Interactive (press Enter to proceed)")
    else:
        print(f"Mode: Automated (2-minute delays between steps)")
    print("=" * 50)
    print()

    # Run tests with randomly selected regions
    test_cloudtrail(session, cloudtrail_region, test_name, args.interactive)
    test_s3_monitoring(session, cloudtrail_region, test_name, args.interactive)
    test_guardduty(session, guardduty_region, test_name, args.interactive)
    test_eventbridge(session, eventbridge_region, test_name, args.interactive)

    print("\n" + "=" * 50)
    print("=== All tests completed ===")
    print("=" * 50)


if __name__ == '__main__':
    main()
