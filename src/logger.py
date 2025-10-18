"""
Logging Module

Handles CloudTrail-style event logging for security configuration changes.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


def log_event(
    log_file: str,
    event_source: str,
    event_name: str,
    account_id: str,
    region: str,
    response_elements: Optional[Dict[str, Any]] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None
) -> None:
    """
    Log a security event in CloudTrail format

    Args:
        log_file: Path to log file
        event_source: AWS service source (e.g., 'cloudtrail.amazonaws.com')
        event_name: Name of the event (e.g., 'UpdateTrailS3Bucket')
        account_id: AWS account ID
        region: AWS region
        response_elements: Response data from the change
        error_code: Error code if event represents an error
        error_message: Error message if event represents an error
    """
    event = {
        "eventTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "responseElements": response_elements or {},
        "eventID": str(uuid.uuid4()),
        "readOnly": False,
        "eventType": "AWSSecurityWatch",
        "recipientAccountId": account_id
    }

    # Add error information if present
    if error_code or error_message:
        event["errorCode"] = error_code
        event["errorMessage"] = error_message

    # Write log entry (one JSON object per line for easy parsing)
    try:
        with open(log_file, 'a') as f:
            f.write(json.dumps(event))
            f.write('\n')
    except IOError as e:
        print(f"Error: Failed to write log entry: {str(e)}")


def log_cloudtrail_change(
    log_file: str,
    account_id: str,
    region: str,
    event_name: str,
    trail_data: Dict[str, Any]
) -> None:
    """
    Log a CloudTrail configuration change

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region
        event_name: Type of change
        trail_data: Trail configuration data
    """
    log_event(
        log_file=log_file,
        event_source="cloudtrail.amazonaws.com",
        event_name=event_name,
        account_id=account_id,
        region=region,
        response_elements=trail_data
    )


def log_guardduty_change(
    log_file: str,
    account_id: str,
    region: str,
    event_name: str,
    guardduty_data: Dict[str, Any]
) -> None:
    """
    Log a GuardDuty configuration change

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region
        event_name: Type of change
        guardduty_data: GuardDuty configuration data
    """
    log_event(
        log_file=log_file,
        event_source="guardduty.amazonaws.com",
        event_name=event_name,
        account_id=account_id,
        region=region,
        response_elements=guardduty_data
    )


def log_eventbridge_change(
    log_file: str,
    account_id: str,
    region: str,
    event_name: str,
    rule_data: Dict[str, Any]
) -> None:
    """
    Log an EventBridge rule change

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region
        event_name: Type of change
        rule_data: EventBridge rule data
    """
    log_event(
        log_file=log_file,
        event_source="events.amazonaws.com",
        event_name=event_name,
        account_id=account_id,
        region=region,
        response_elements=rule_data
    )


def log_s3_change(
    log_file: str,
    account_id: str,
    region: str,
    event_name: str,
    s3_data: Dict[str, Any]
) -> None:
    """
    Log an S3 bucket configuration change

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region
        event_name: Type of change
        s3_data: S3 bucket configuration data
    """
    log_event(
        log_file=log_file,
        event_source="s3.amazonaws.com",
        event_name=event_name,
        account_id=account_id,
        region=region,
        response_elements=s3_data
    )


def log_sqs_change(
    log_file: str,
    account_id: str,
    region: str,
    event_name: str,
    sqs_data: Dict[str, Any]
) -> None:
    """
    Log an SQS queue configuration change

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region
        event_name: Type of change
        sqs_data: SQS queue configuration data
    """
    log_event(
        log_file=log_file,
        event_source="sqs.amazonaws.com",
        event_name=event_name,
        account_id=account_id,
        region=region,
        response_elements=sqs_data
    )


def log_sns_change(
    log_file: str,
    account_id: str,
    region: str,
    event_name: str,
    sns_data: Dict[str, Any]
) -> None:
    """
    Log an SNS topic configuration change

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region
        event_name: Type of change
        sns_data: SNS topic configuration data
    """
    log_event(
        log_file=log_file,
        event_source="sns.amazonaws.com",
        event_name=event_name,
        account_id=account_id,
        region=region,
        response_elements=sns_data
    )


def log_permission_error(
    log_file: str,
    account_id: str,
    region: str,
    service: str,
    error_message: str
) -> None:
    """
    Log a permission error

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region
        service: Service that failed
        error_message: Error message
    """
    log_event(
        log_file=log_file,
        event_source=f"{service}.amazonaws.com",
        event_name="PermissionError",
        account_id=account_id,
        region=region,
        error_code="AccessDenied",
        error_message=error_message
    )
