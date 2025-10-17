"""
AWS Credentials Management Module

Handles AWS credentials from multiple sources:
- Configuration file (JSON)
- Environment variables
- AWS credentials file
"""

import boto3
import json
import os
from typing import Dict, List, Optional
from botocore.exceptions import ClientError


def load_config(config_path: Optional[str] = None) -> Dict:
    """Load configuration from file if provided"""
    if not config_path or not os.path.exists(config_path):
        return {}

    with open(config_path, 'r') as f:
        return json.load(f)


def get_base_session(config: Dict, profile_name: Optional[str] = None) -> boto3.Session:
    """
    Create base AWS session using credentials priority:
    1. AWS profile (if specified)
    2. Config file credentials
    3. Environment variables
    4. AWS credentials file

    Args:
        config: Configuration dictionary
        profile_name: Optional AWS profile name

    Returns:
        boto3.Session: Base AWS session
    """
    # Priority 1: AWS profile (if specified via command line)
    if profile_name:
        return boto3.Session(profile_name=profile_name)

    # Priority 2: Config file credentials
    if config.get('credentials'):
        creds = config['credentials']
        return boto3.Session(
            aws_access_key_id=creds.get('access_key_id'),
            aws_secret_access_key=creds.get('secret_access_key'),
            aws_session_token=creds.get('session_token')
        )

    # Priority 3 & 4: Environment variables or AWS credentials file
    # boto3 automatically handles these
    return boto3.Session()


def get_account_session(base_session: boto3.Session, account_id: str, role_arn: str) -> boto3.Session:
    """
    Create AWS session for a specific account using AssumeRole

    Args:
        base_session: Base boto3 session
        account_id: AWS account ID
        role_arn: ARN of role to assume

    Returns:
        boto3.Session: Session with assumed role credentials
    """
    sts_client = base_session.client('sts')

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'SecurityWatch-{account_id}'
        )

        credentials = response['Credentials']
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    except ClientError as e:
        raise Exception(f"Failed to assume role {role_arn}: {str(e)}")


def get_accounts(config: Dict) -> List[Dict]:
    """
    Get list of accounts to monitor from configuration

    Args:
        config: Configuration dictionary

    Returns:
        List of account configurations
    """
    return config.get('accounts', [])


def get_monitoring_config(config: Dict) -> Dict:
    """
    Get monitoring configuration settings

    Args:
        config: Configuration dictionary

    Returns:
        Dictionary with monitoring settings
    """
    return config.get('monitoring', {
        'interval_seconds': 120,
        'log_file': 'security-watch.log',
        'state_directory': 'state'
    })
