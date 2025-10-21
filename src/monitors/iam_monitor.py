"""
IAM Monitoring Module

Monitors IAM role configuration changes for roles used in the CloudTrail ecosystem:
- Roles used by Lambda functions
- Service roles with monitored service principals (Lambda, S3, SNS, SQS, CloudTrail, etc.)
- Trust policy changes
- Attached managed policy changes
- Inline policy changes
- Role description and max session duration changes
"""

import boto3
from typing import Dict, Any, List, Optional, Set
from botocore.exceptions import ClientError
import json


def _normalize_policy_element(element: Any) -> Any:
    """
    Recursively normalize a policy element for comparison

    Handles:
    - Sorting lists/arrays
    - Sorting dictionary keys
    - Recursive normalization of nested structures

    Args:
        element: Policy element to normalize (dict, list, or primitive)

    Returns:
        Normalized element
    """
    if isinstance(element, dict):
        # Recursively normalize dictionary values and sort by keys
        return {k: _normalize_policy_element(v) for k, v in sorted(element.items())}
    elif isinstance(element, list):
        # Sort lists for consistent comparison
        # Convert to JSON string for sorting if elements are complex
        if element and isinstance(element[0], (dict, list)):
            return sorted(
                [_normalize_policy_element(item) for item in element],
                key=lambda x: json.dumps(x, sort_keys=True)
            )
        else:
            # Simple primitives can be sorted directly
            return sorted([_normalize_policy_element(item) for item in element])
    else:
        # Return primitives as-is
        return element


def _normalize_policy_document(policy_doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a policy document for comparison

    This performs deep normalization to handle:
    - Array ordering (e.g., ["a", "b"] vs ["b", "a"])
    - Dict key ordering (e.g., {"AWS": ..., "Service": ...} vs {"Service": ..., "AWS": ...})
    - Nested structure ordering

    Args:
        policy_doc: Policy document dictionary

    Returns:
        Normalized policy document
    """
    return _normalize_policy_element(policy_doc)


def get_current_state(
    session: boto3.Session,
    region: str,
    state_file_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Get current IAM role configuration state for roles in CloudTrail ecosystem

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region (IAM is global, but we use one region to avoid duplicates)
        state_file_data: Complete state file data (to discover IAM roles)

    Returns:
        Dictionary containing current IAM role configurations
    """
    # Only process IAM in us-east-1 to avoid duplicate monitoring across regions
    if region != 'us-east-1':
        return {'iam_roles': {}}

    iam_client = session.client('iam', region_name=region)
    roles = {}

    # If no state file data provided, return empty state
    if not state_file_data:
        return {'iam_roles': roles}

    # Collect IAM role ARNs from various sources across all regions
    role_arns: Set[str] = set()
    role_sources: Dict[str, List[Dict[str, str]]] = {}  # Map ARN to source list

    # Define monitored service principals
    MONITORED_SERVICES = {
        'lambda.amazonaws.com': 'Lambda',
        's3.amazonaws.com': 'S3',
        'sns.amazonaws.com': 'SNS',
        'sqs.amazonaws.com': 'SQS',
        'cloudtrail.amazonaws.com': 'CloudTrail',
        'events.amazonaws.com': 'EventBridge',
        'guardduty.amazonaws.com': 'GuardDuty'
    }

    # Scan all regions for Lambda functions with roles
    for region_name, region_data in state_file_data.get('regions', {}).items():
        # Get Lambda state to discover IAM roles from functions
        lambda_state = region_data.get('lambda', {})
        for func_arn, func_config in lambda_state.get('lambda_functions', {}).items():
            role_arn = func_config.get('role')
            if role_arn and role_arn.startswith('arn:aws:iam:'):
                role_arns.add(role_arn)
                if role_arn not in role_sources:
                    role_sources[role_arn] = []
                role_sources[role_arn].append({
                    'type': 'lambda_function',
                    'name': func_config.get('function_name', func_arn),
                    'region': region_name
                })

    # Scan for service roles with monitored service principals
    try:
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page.get('Roles', []):
                role_arn = role.get('Arn')
                role_name = role.get('RoleName')
                assume_role_policy = role.get('AssumeRolePolicyDocument', {})

                # Check if this role has a monitored service as a principal
                has_monitored_service = False
                service_principals = []

                for statement in assume_role_policy.get('Statement', []):
                    if statement.get('Effect') != 'Allow':
                        continue

                    principal = statement.get('Principal', {})
                    if isinstance(principal, dict):
                        services = principal.get('Service', [])
                        if isinstance(services, str):
                            services = [services]

                        for service in services:
                            if service in MONITORED_SERVICES:
                                has_monitored_service = True
                                service_principals.append(service)

                # If this role has a monitored service principal, track it
                if has_monitored_service:
                    role_arns.add(role_arn)
                    if role_arn not in role_sources:
                        role_sources[role_arn] = []

                    for service_principal in service_principals:
                        service_name = MONITORED_SERVICES.get(service_principal, service_principal)
                        role_sources[role_arn].append({
                            'type': 'service_role',
                            'service': service_name,
                            'principal': service_principal
                        })
    except ClientError as e:
        print(f"Warning: Could not list IAM roles for service role discovery: {str(e)}")

    # Process each discovered role
    for role_arn in role_arns:
        try:
            # Extract role name from ARN
            # ARN format: arn:aws:iam::account-id:role/role-name
            role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn.split(':')[-1]

            try:
                # Get role details
                role_response = iam_client.get_role(RoleName=role_name)
                role_data = role_response.get('Role', {})

                # Get trust policy (assume role policy document)
                trust_policy = role_data.get('AssumeRolePolicyDocument', {})

                # Get attached managed policies
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
                    inline_policy_names = []
                    paginator = iam_client.get_paginator('list_role_policies')
                    for page in paginator.paginate(RoleName=role_name):
                        inline_policy_names.extend(page.get('PolicyNames', []))

                    # Get each inline policy document
                    for policy_name in inline_policy_names:
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

                # Get role tags
                tags = {}
                try:
                    tag_response = iam_client.list_role_tags(RoleName=role_name)
                    for tag in tag_response.get('Tags', []):
                        tags[tag.get('Key')] = tag.get('Value')
                except ClientError:
                    pass

                # Build role state
                roles[role_arn] = {
                    'arn': role_arn,
                    'role_name': role_name,
                    'role_id': role_data.get('RoleId'),
                    'sources': role_sources.get(role_arn, []),
                    'trust_policy': trust_policy,
                    'attached_managed_policies': sorted(attached_policies, key=lambda x: x['policy_arn']),
                    'inline_policies': inline_policies,
                    'tags': tags,
                    'max_session_duration': role_data.get('MaxSessionDuration'),
                    'path': role_data.get('Path'),
                    'description': role_data.get('Description', ''),
                    'accessible': True
                }

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchEntity':
                    # Role doesn't exist (may have been deleted)
                    continue
                elif error_code in ['AccessDenied', 'AccessDeniedException']:
                    # Insufficient permissions to read role
                    roles[role_arn] = {
                        'arn': role_arn,
                        'role_name': role_name,
                        'sources': role_sources.get(role_arn, []),
                        'accessible': False,
                        'error': f'Insufficient permissions: {error_code}'
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

        # Check for trust policy changes
        prev_trust = _normalize_policy_document(previous_role.get('trust_policy', {}))
        curr_trust = _normalize_policy_document(current_role.get('trust_policy', {}))

        if prev_trust != curr_trust:
            changes.append({
                'event_name': 'UpdateAssumeRolePolicy',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'previousTrustPolicy': prev_trust,
                    'currentTrustPolicy': curr_trust
                }
            })

        # Check for attached managed policy changes
        prev_managed = {p['policy_arn']: p for p in previous_role.get('attached_managed_policies', [])}
        curr_managed = {p['policy_arn']: p for p in current_role.get('attached_managed_policies', [])}

        # Detect detached policies
        detached_policy_arns = set(prev_managed.keys()) - set(curr_managed.keys())
        if detached_policy_arns:
            detached_policies = [prev_managed[arn] for arn in detached_policy_arns]
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
        attached_policy_arns = set(curr_managed.keys()) - set(prev_managed.keys())
        if attached_policy_arns:
            attached_policies = [curr_managed[arn] for arn in attached_policy_arns]
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
        deleted_inline_names = set(prev_inline.keys()) - set(curr_inline.keys())
        for policy_name in deleted_inline_names:
            changes.append({
                'event_name': 'DeleteRolePolicy',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'policyName': policy_name,
                    'previousPolicy': prev_inline[policy_name]
                }
            })

        # Detect added inline policies
        added_inline_names = set(curr_inline.keys()) - set(prev_inline.keys())
        for policy_name in added_inline_names:
            changes.append({
                'event_name': 'PutRolePolicy',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'policyName': policy_name,
                    'currentPolicy': curr_inline[policy_name]
                }
            })

        # Detect modified inline policies
        for policy_name in set(prev_inline.keys()) & set(curr_inline.keys()):
            prev_policy = _normalize_policy_document(prev_inline[policy_name])
            curr_policy = _normalize_policy_document(curr_inline[policy_name])

            if prev_policy != curr_policy:
                changes.append({
                    'event_name': 'UpdateRolePolicy',
                    'iam_data': {
                        'roleArn': role_arn,
                        'roleName': current_role.get('role_name'),
                        'sources': current_role.get('sources', []),
                        'policyName': policy_name,
                        'previousPolicy': prev_policy,
                        'currentPolicy': curr_policy
                    }
                })

        # Check for max session duration changes
        prev_max_session = previous_role.get('max_session_duration')
        curr_max_session = current_role.get('max_session_duration')

        if prev_max_session != curr_max_session:
            changes.append({
                'event_name': 'UpdateRoleMaxSessionDuration',
                'iam_data': {
                    'roleArn': role_arn,
                    'roleName': current_role.get('role_name'),
                    'sources': current_role.get('sources', []),
                    'previousMaxSessionDuration': prev_max_session,
                    'currentMaxSessionDuration': curr_max_session
                }
            })

    return changes
