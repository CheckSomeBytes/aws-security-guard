"""
Lambda Monitoring Module

Monitors Lambda function configuration changes for functions in CloudTrail ecosystem:
- Functions triggered by S3 events (direct)
- Functions triggered by SNS subscriptions
- Functions triggered by SQS event source mappings
- Function deletion
- Code changes (CodeSha256)
- Configuration changes (runtime, memory, timeout, environment variables)
- Execution role changes
"""

import boto3
from typing import Dict, Any, List, Optional, Set
from botocore.exceptions import ClientError


def get_current_state(
    session: boto3.Session,
    region: str,
    state_file_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Get current Lambda function configuration state for functions in CloudTrail ecosystem

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region to monitor
        state_file_data: Complete state file data (to read S3, SNS, SQS state)

    Returns:
        Dictionary containing current Lambda function configurations
    """
    lambda_client = session.client('lambda', region_name=region)
    functions = {}

    # If no state file data provided, return empty state
    if not state_file_data:
        return {'lambda_functions': functions}

    # Collect Lambda function ARNs from various sources
    function_arns: Set[str] = set()
    function_sources: Dict[str, List[Dict[str, str]]] = {}  # Map ARN to source list

    # Get S3 state to discover Lambda functions from event notifications
    s3_state = state_file_data.get('regions', {}).get(region, {}).get('s3', {})
    for bucket_name, bucket_config in s3_state.get('s3_buckets', {}).items():
        for notification in bucket_config.get('event_notifications', []):
            if notification.get('destination_type') == 'Lambda':
                func_arn = notification.get('destination_arn')
                if func_arn:
                    function_arns.add(func_arn)
                    if func_arn not in function_sources:
                        function_sources[func_arn] = []
                    function_sources[func_arn].append({
                        'type': 's3_bucket',
                        'name': bucket_name
                    })

    # Get SNS state to discover Lambda functions from subscriptions
    sns_state = state_file_data.get('regions', {}).get(region, {}).get('sns', {})
    for topic_arn, topic_config in sns_state.get('sns_topics', {}).items():
        for subscription in topic_config.get('subscriptions', []):
            if subscription.get('protocol') == 'lambda':
                func_arn = subscription.get('endpoint')
                if func_arn:
                    function_arns.add(func_arn)
                    if func_arn not in function_sources:
                        function_sources[func_arn] = []
                    function_sources[func_arn].append({
                        'type': 'sns_topic',
                        'name': topic_config.get('topic_name', topic_arn)
                    })

    # Get SQS state to discover Lambda functions from event source mappings
    sqs_state = state_file_data.get('regions', {}).get(region, {}).get('sqs', {})
    for queue_url, queue_config in sqs_state.get('sqs_queues', {}).items():
        for mapping in queue_config.get('lambda_event_sources', []):
            func_arn = mapping.get('function_arn')
            if func_arn:
                function_arns.add(func_arn)
                if func_arn not in function_sources:
                    function_sources[func_arn] = []
                function_sources[func_arn].append({
                    'type': 'sqs_queue',
                    'name': queue_config.get('queue_name', queue_url)
                })

    # Process each discovered function
    for func_arn in function_arns:
        try:
            # Extract function name from ARN
            # ARN format: arn:aws:lambda:region:account-id:function:function-name
            function_name = func_arn.split(':')[-1] if ':' in func_arn else func_arn

            try:
                # Get function configuration
                response = lambda_client.get_function(FunctionName=func_arn)
                config = response.get('Configuration', {})
                code_info = response.get('Code', {})

                # Extract relevant configuration
                functions[func_arn] = {
                    'arn': func_arn,
                    'function_name': config.get('FunctionName', function_name),
                    'region': region,
                    'sources': function_sources.get(func_arn, []),
                    'runtime': config.get('Runtime'),
                    'handler': config.get('Handler'),
                    'code_sha256': config.get('CodeSha256'),
                    'code_size': config.get('CodeSize'),
                    'memory_size': config.get('MemorySize'),
                    'timeout': config.get('Timeout'),
                    'role': config.get('Role'),
                    'environment_variables': config.get('Environment', {}).get('Variables', {}),
                    'layers': [layer.get('Arn') for layer in config.get('Layers', [])],
                    'vpc_config': {
                        'subnet_ids': config.get('VpcConfig', {}).get('SubnetIds', []),
                        'security_group_ids': config.get('VpcConfig', {}).get('SecurityGroupIds', [])
                    } if config.get('VpcConfig', {}).get('SubnetIds') else {},
                    'dead_letter_config': config.get('DeadLetterConfig', {}),
                    'tracing_config': config.get('TracingConfig', {}).get('Mode'),
                    'accessible': True
                }

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    # Function doesn't exist (may have been deleted)
                    continue
                elif error_code in ['AccessDenied', 'AccessDeniedException']:
                    # Cross-account function or insufficient permissions
                    functions[func_arn] = {
                        'arn': func_arn,
                        'function_name': function_name,
                        'region': region,
                        'sources': function_sources.get(func_arn, []),
                        'accessible': False,
                        'error': f'Cross-account or inaccessible function: {error_code}'
                    }
                else:
                    print(f"Warning: Error processing function {func_arn}: {str(e)}")

        except Exception as e:
            print(f"Warning: Unexpected error processing function {func_arn}: {str(e)}")

    return {'lambda_functions': functions}


def detect_changes(
    previous_state: Optional[Dict[str, Any]],
    current_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect changes between previous and current Lambda function state

    Args:
        previous_state: Previous Lambda function configurations
        current_state: Current Lambda function configurations

    Returns:
        List of detected changes
    """
    changes = []

    if previous_state is None:
        return changes  # First run, no changes to report

    previous_functions = previous_state.get('lambda_functions', {})
    current_functions = current_state.get('lambda_functions', {})

    # Detect function deletions
    deleted_functions = set(previous_functions.keys()) - set(current_functions.keys())
    for func_arn in deleted_functions:
        prev_func = previous_functions[func_arn]
        changes.append({
            'event_name': 'DeleteFunction',
            'lambda_data': {
                'functionArn': func_arn,
                'functionName': prev_func.get('function_name'),
                'sources': prev_func.get('sources', [])
            }
        })

    # Detect changes in existing functions
    for func_arn in current_functions.keys():
        if func_arn not in previous_functions:
            # New function - don't log as change
            continue

        current_func = current_functions[func_arn]
        previous_func = previous_functions[func_arn]

        # Skip if function is not accessible
        if not current_func.get('accessible', True):
            continue

        # Check for code changes (CodeSha256)
        prev_code_sha = previous_func.get('code_sha256')
        curr_code_sha = current_func.get('code_sha256')

        if prev_code_sha != curr_code_sha:
            changes.append({
                'event_name': 'UpdateFunctionCode',
                'lambda_data': {
                    'functionArn': func_arn,
                    'functionName': current_func.get('function_name'),
                    'sources': current_func.get('sources', []),
                    'previousCodeSha256': prev_code_sha,
                    'currentCodeSha256': curr_code_sha,
                    'codeSize': current_func.get('code_size')
                }
            })

        # Check for runtime changes
        prev_runtime = previous_func.get('runtime')
        curr_runtime = current_func.get('runtime')

        if prev_runtime != curr_runtime:
            changes.append({
                'event_name': 'UpdateFunctionRuntime',
                'lambda_data': {
                    'functionArn': func_arn,
                    'functionName': current_func.get('function_name'),
                    'sources': current_func.get('sources', []),
                    'previousRuntime': prev_runtime,
                    'currentRuntime': curr_runtime
                }
            })

        # Check for memory/timeout changes
        prev_memory = previous_func.get('memory_size')
        curr_memory = current_func.get('memory_size')
        prev_timeout = previous_func.get('timeout')
        curr_timeout = current_func.get('timeout')

        if prev_memory != curr_memory or prev_timeout != curr_timeout:
            changes.append({
                'event_name': 'UpdateFunctionConfiguration',
                'lambda_data': {
                    'functionArn': func_arn,
                    'functionName': current_func.get('function_name'),
                    'sources': current_func.get('sources', []),
                    'previousMemorySize': prev_memory,
                    'currentMemorySize': curr_memory,
                    'previousTimeout': prev_timeout,
                    'currentTimeout': curr_timeout
                }
            })

        # Check for role changes
        prev_role = previous_func.get('role')
        curr_role = current_func.get('role')

        if prev_role != curr_role:
            changes.append({
                'event_name': 'UpdateFunctionRole',
                'lambda_data': {
                    'functionArn': func_arn,
                    'functionName': current_func.get('function_name'),
                    'sources': current_func.get('sources', []),
                    'previousRole': prev_role,
                    'currentRole': curr_role
                }
            })

        # Check for environment variable changes
        prev_env = previous_func.get('environment_variables', {})
        curr_env = current_func.get('environment_variables', {})

        if prev_env != curr_env:
            changes.append({
                'event_name': 'UpdateFunctionEnvironment',
                'lambda_data': {
                    'functionArn': func_arn,
                    'functionName': current_func.get('function_name'),
                    'sources': current_func.get('sources', []),
                    'previousEnvironment': prev_env,
                    'currentEnvironment': curr_env
                }
            })

        # Check for VPC configuration changes
        prev_vpc = previous_func.get('vpc_config', {})
        curr_vpc = current_func.get('vpc_config', {})

        if prev_vpc != curr_vpc:
            changes.append({
                'event_name': 'UpdateFunctionVpcConfig',
                'lambda_data': {
                    'functionArn': func_arn,
                    'functionName': current_func.get('function_name'),
                    'sources': current_func.get('sources', []),
                    'previousVpcConfig': prev_vpc,
                    'currentVpcConfig': curr_vpc
                }
            })

        # Check for layer changes
        prev_layers = previous_func.get('layers', [])
        curr_layers = current_func.get('layers', [])

        if set(prev_layers) != set(curr_layers):
            changes.append({
                'event_name': 'UpdateFunctionLayers',
                'lambda_data': {
                    'functionArn': func_arn,
                    'functionName': current_func.get('function_name'),
                    'sources': current_func.get('sources', []),
                    'previousLayers': prev_layers,
                    'currentLayers': curr_layers
                }
            })

    return changes
