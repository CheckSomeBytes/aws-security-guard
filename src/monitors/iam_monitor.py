"""
IAM Monitoring Module

Monitors IAM role configuration changes for roles in CloudTrail ecosystem:
- Lambda execution roles
- Roles referenced in SQS/SNS access policies
- CloudTrail service roles
- Role deletion
- Policy attachment changes
- Inline policy changes
- Assume role policy changes
"""

import boto3
from typing import Dict, Any, List, Optional, Set
from botocore.exceptions import ClientError
import json


def get_current_state(
    session: boto3.Session,
    region: str,
    state_file_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Get current IAM role configuration state for roles in CloudTrail ecosystem

    Note: IAM is global, so region is not used but kept for consistency

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region (not used for IAM but kept for consistency)
        state_file_data: Complete state file data (to read Lambda, SQS, SNS, CloudTrail state)

    Returns:
        Dictionary containing current IAM role configurations
    """
    iam_client = session.client('iam')
    roles = {}

    # If no state file data provided, return empty state
    if not state_file_data:
        return {'iam_roles': roles}

    # Collect IAM role names/ARNs from various sources
    role_arns: Set[str] = set()
    role_sources: Dict[str, List[Dict[str, str]]] = {}  # Map role ARN to source list

    # Process all regions to collect roles
    for region_name, region_data in state_file_data.get('regions', {}).items():
        # Get Lambda state to discover execution roles
        lambda_state = region_data.get('lambda', {})
        for func_arn, func_config in lambda_state.get('lambda_functions', {}).items():
            role_arn = func_config.get('role')
            if role_arn:
                role_arns.add(role_arn)
                if role_arn not in role_sources:
                    role_sources[role_arn] = []
                role_sources[role_arn].append({
                    'type': 'lambda_execution_role',
                    'name': func_config.get('function_name', func_arn),
                    'region': region_name
                })

        # Get SQS state to discover roles in access policies
        sqs_state = region_data.get('sqs', {})
        for queue_url, queue_config in sqs_state.get('sqs_queues', {}).items():
            access_policy = queue_config.get('access_policy', {})
            for statement in access_policy.get('Statement', []):
                principal = statement.get('Principal', {})
                # Check for AWS principals (can be role ARNs)
                aws_principals = principal.get('AWS', [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for principal_arn in aws_principals:
                    if ':role/' in principal_arn:
                        role_arns.add(principal_arn)
                        if principal_arn not in role_sources:
                            role_sources[principal_arn] = []
                        role_sources[principal_arn].append({
                            'type': 'sqs_policy',
                            'name': queue_config.get('queue_name', queue_url),
                            'region': region_name
                        })

        # Get SNS state to discover roles in access policies
        sns_state = region_data.get('sns', {})
        for topic_arn, topic_config in sns_state.get('sns_topics', {}).items():
            access_policy = topic_config.get('access_policy', {})
            for statement in access_policy.get('Statement', []):
                principal = statement.get('Principal', {})
                aws_principals = principal.get('AWS', [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for principal_arn in aws_principals:
                    if ':role/' in principal_arn:
                        role_arns.add(principal_arn)
                        if principal_arn not in role_sources:
                            role_sources[principal_arn] = []
                        role_sources[principal_arn].append({
                            'type': 'sns_policy',
                            'name': topic_config.get('topic_name', topic_arn),
                            'region': region_name
                        })

        # Get CloudTrail state to discover service roles
        cloudtrail_state = region_data.get('cloudtrail', {})
        for trail_arn, trail_config in cloudtrail_state.get('cloudtrail_trails', {}).items():
            # CloudTrail uses a service role for S3 delivery
            cloud_watch_logs_role = trail_config.get('cloud_watch_logs_role_arn')
            if cloud_watch_logs_role and ':role/' in cloud_watch_logs_role:
                role_arns.add(cloud_watch_logs_role)
                if cloud_watch_logs_role not in role_sources:
                    role_sources[cloud_watch_logs_role] = []
                role_sources[cloud_watch_logs_role].append({
                    'type': 'cloudtrail_service_role',
                    'name': trail_config.get('trail_name', trail_arn),
                    'region': region_name
                })

    # Process each discovered role
    for role_arn in role_arns:
        try:
            # Extract role name from ARN
            # ARN format: arn:aws:iam::account-id:role/role-name or role/path/role-name
            role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn

            try:
                # Get role details
                role_response = iam_client.get_role(RoleName=role_name)
                role_data = role_response.get('Role', {})

                # Get attached policies
                attached_policies = []
                try:
                    paginator = iam_client.get_paginator('list_attached_role_policies')
                    for page in paginator.paginate(RoleName=role_name):
                        for policy in page.get('AttachedPolicies', []):
                            attached_policies.append({
                                'policy_name': policy.get('PolicyName'),
                                'policy_arn': policy.get('PolicyArn')
                            })
                except ClientError:
                    pass

                # Get inline policies
                inline_policies = {}
                try:
                    paginator = iam_client.get_paginator('list_role_policies')
                    for page in paginator.paginate(RoleName=role_name):
                        for policy_name in page.get('PolicyNames', []):
                            try:
                                policy_response = iam_client.get_role_policy(
                                    RoleName=role_name,
                                    PolicyName=policy_name
                                )
                                inline_policies[policy_name] = policy_response.get('PolicyDocument', {})
                            except ClientError:
                                pass
                except ClientError:
                    pass

                # Build role state
                roles[role_arn] = {
                    'arn': role_arn,
                    'role_name': role_data.get('RoleName', role_name),
                    'role_id': role_data.get('RoleId'),
                    'sources': role_sources.get(role_arn, []),
                    'assume_role_policy': role_data.get('AssumeRolePolicyDocument', {}),
                    'attached_policies': attached_policies,
                    'inline_policies': inline_policies,
                    'max_session_duration': role_data.get('MaxSessionDuration'),
                    'path': role_data.get('Path'),
                    'permissions_boundary': role_data.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn') if role_data.get('PermissionsBoundary') else None,
                    'accessible': True
                }

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchEntity':
                    # Role doesn't exist (may have been deleted)
                    continue
                elif error_code in ['AccessDenied', 'AccessDeniedException']:
                    # Cross-account role or insufficient permissions
                    roles[role_arn] = {
                        'arn': role_arn,
                        'role_name': role_name,
                        'sources': role_sources.get(role_arn, []),
                        'accessible': False,
                        'error': f'Inaccessible role: {error_code}'
                    }
                else:
                    print(f"Warning: Error processing role {role_arn}: {str(e)}")

        except Exception as e:
            print(f"Warning: Unexpected error processing role {role_arn}: {str(e)}")

    return {'iam_roles': roles}


def detect_changes(
    previous_state: Optional[Dict[str, Any]],
    current_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect changes between previous and current IAM role state

    Args:
        previous_state: Previous IAM role configurations
        current_state: Current IAM role configurations

    Returns:
        List of detected changes
    """
    changes = []

    if previous_state is None:
        return changes  # First run, no changes to report

    previous_roles = previous_state.get('iam_roles', {})
    current_roles = current_state.get('iam_roles', {})

    # Detect role deletions
    deleted_roles = set(previous_roles.keys()) - set(current_roles.keys())
    for role_arn in deleted_roles:
        prev_role = previous_roles[role_arn]
        changes.append({
            'event_name': 'DeleteRole',
            'iam_data': {
                'roleArn': role_arn,
                'roleName': prev_role.get('role_name'),
                'sources': prev_role.get('sources', [])
            }
        })

    # Detect changes in existing roles
    for role_arn in current_roles.keys():
        if role_arn not in previous_roles:
            # New role - don't log as change
            continue

        current_role = current_roles[role_arn]
        previous_role = previous_roles[role_arn]

        # Skip if role is not accessible
        if not current_role.get('accessible', True):
            continue

        # Check for assume role policy changes
        prev_assume_policy = previous_role.get('assume_role_policy', {})
        curr_assume_policy = current_role.get('assume_role_policy', {})

        if prev_assume_policy != curr_assume_policy:
            changes.append({
                'event_name': 'UpdateAssumeRolePolicy',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'previousPolicy': prev_assume_policy,
                    'currentPolicy': curr_assume_policy
                }
            })

        # Check for attached policy changes
        prev_attached = {p['policy_arn']: p for p in previous_role.get('attached_policies', [])}
        curr_attached = {p['policy_arn']: p for p in current_role.get('attached_policies', [])}

        # Detect detached policies
        detached_arns = set(prev_attached.keys()) - set(curr_attached.keys())
        if detached_arns:
            detached_policies = [prev_attached[arn] for arn in detached_arns]
            changes.append({
                'event_name': 'DetachRolePolicy',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'detachedPolicies': detached_policies
                }
            })

        # Detect attached policies
        attached_arns = set(curr_attached.keys()) - set(prev_attached.keys())
        if attached_arns:
            attached_policies = [curr_attached[arn] for arn in attached_arns]
            changes.append({
                'event_name': 'AttachRolePolicy',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'attachedPolicies': attached_policies
                }
            })

        # Check for inline policy changes
        prev_inline = previous_role.get('inline_policies', {})
        curr_inline = current_role.get('inline_policies', {})

        # Detect deleted inline policies
        deleted_inline = set(prev_inline.keys()) - set(curr_inline.keys())
        if deleted_inline:
            changes.append({
                'event_name': 'DeleteRoleInlinePolicy',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'deletedPolicies': list(deleted_inline)
                }
            })

        # Detect added inline policies
        added_inline = set(curr_inline.keys()) - set(prev_inline.keys())
        if added_inline:
            added_policies = {name: curr_inline[name] for name in added_inline}
            changes.append({
                'event_name': 'PutRoleInlinePolicy',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'addedPolicies': added_policies
                }
            })

        # Detect modified inline policies
        for policy_name in set(prev_inline.keys()) & set(curr_inline.keys()):
            if prev_inline[policy_name] != curr_inline[policy_name]:
                changes.append({
                    'event_name': 'UpdateRoleInlinePolicy',
                    'iam_data': {
                        'roleArn': role_arn,
                        'roleName': current_role.get('role_name'),
                        'sources': current_role.get('sources', []),
                        'policyName': policy_name,
                        'previousPolicy': prev_inline[policy_name],
                        'currentPolicy': curr_inline[policy_name]
                    }
                })

        # Check for permissions boundary changes
        prev_boundary = previous_role.get('permissions_boundary')
        curr_boundary = current_role.get('permissions_boundary')

        if prev_boundary != curr_boundary:
            changes.append({
                'event_name': 'UpdateRolePermissionsBoundary',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'previousBoundary': prev_boundary,
                    'currentBoundary': curr_boundary
                }
            })

    return changes
