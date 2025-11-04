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


def log_lambda_change(
    log_file: str,
    account_id: str,
    region: str,
    event_name: str,
    lambda_data: Dict[str, Any]
) -> None:
    """
    Log a Lambda function configuration change

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region
        event_name: Type of change
        lambda_data: Lambda function configuration data
    """
    log_event(
        log_file=log_file,
        event_source="lambda.amazonaws.com",
        event_name=event_name,
        account_id=account_id,
        region=region,
        response_elements=lambda_data
    )


def log_iam_change(
    log_file: str,
    account_id: str,
    region: str,
    event_name: str,
    iam_data: Dict[str, Any]
) -> None:
    """
    Log an IAM role configuration change

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        region: AWS region (us-east-1 for IAM global)
        event_name: Type of change
        iam_data: IAM role configuration data
    """
    log_event(
        log_file=log_file,
        event_source="iam.amazonaws.com",
        event_name=event_name,
        account_id=account_id,
        region=region,
        response_elements=iam_data
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


def log_api_failures(
    log_file: str,
    account_id: str,
    api_failures: list,
    run_duration: Optional[float] = None
) -> None:
    """
    Log API failures that occurred during monitoring run.
    Only logs if there are actual failures.

    Args:
        log_file: Path to log file
        account_id: AWS account ID
        api_failures: List of API failure dictionaries from ErrorTracker
        run_duration: Optional duration of the monitoring run in seconds
    """
    # Only log if there are actual failures
    if not api_failures or len(api_failures) == 0:
        return

    summary_data = {
        "api_failures": api_failures,
        "total_failures": len(api_failures)
    }

    if run_duration is not None:
        summary_data["run_duration_seconds"] = round(run_duration, 2)

    # Group failures by service for additional context
    failures_by_service = {}
    for failure in api_failures:
        service = failure.get('service', 'unknown')
        if service not in failures_by_service:
            failures_by_service[service] = 0
        failures_by_service[service] += 1

    summary_data["failures_by_service"] = failures_by_service

    # Group failures by region
    failures_by_region = {}
    for failure in api_failures:
        region = failure.get('region', 'unknown')
        if region not in failures_by_region:
            failures_by_region[region] = 0
        failures_by_region[region] += 1

    summary_data["failures_by_region"] = failures_by_region

    log_event(
        log_file=log_file,
        event_source="aws-security-guard.internal",
        event_name="MonitoringAPIFailure",
        account_id=account_id,
        region="global",
        response_elements=summary_data
    )
