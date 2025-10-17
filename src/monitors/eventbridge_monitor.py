"""
EventBridge Monitoring Module

Monitors EventBridge rule changes:
- Creation of rules
- Modification of rules
- Deletion of rules
"""

import boto3
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError


def get_current_state(session: boto3.Session, region: str) -> Dict[str, Any]:
    """
    Get current EventBridge rules state

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region to monitor

    Returns:
        Dictionary containing current EventBridge rule configurations
    """
    client = session.client('events', region_name=region)

    try:
        rules = {}

        # List all rules
        paginator = client.get_paginator('list_rules')
        for page in paginator.paginate():
            for rule in page.get('Rules', []):
                rule_name = rule['Name']

                try:
                    # Get rule details
                    rule_details = client.describe_rule(Name=rule_name)

                    # Get targets for the rule
                    targets_response = client.list_targets_by_rule(Rule=rule_name)
                    targets = targets_response.get('Targets', [])

                    # Get tags for the rule
                    try:
                        tags_response = client.list_tags_for_resource(
                            ResourceARN=rule['Arn']
                        )
                        tags = tags_response.get('Tags', [])
                    except ClientError:
                        tags = []

                    rules[rule_name] = {
                        'arn': rule['Arn'],
                        'state': rule_details.get('State'),
                        'description': rule_details.get('Description'),
                        'event_pattern': rule_details.get('EventPattern'),
                        'schedule_expression': rule_details.get('ScheduleExpression'),
                        'role_arn': rule_details.get('RoleArn'),
                        'managed_by': rule_details.get('ManagedBy'),
                        'event_bus_name': rule_details.get('EventBusName', 'default'),
                        'targets': targets,
                        'tags': tags
                    }

                except ClientError as e:
                    print(f"Warning: Failed to get details for rule {rule_name}: {str(e)}")
                    continue

        return rules

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            raise PermissionError(f"Access denied to EventBridge in {region}: {str(e)}")
        raise


def detect_changes(
    previous_state: Optional[Dict[str, Any]],
    current_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect changes between previous and current state

    Args:
        previous_state: Previous EventBridge rule configurations
        current_state: Current EventBridge rule configurations

    Returns:
        List of detected changes
    """
    changes = []

    if previous_state is None:
        return changes  # First run, no changes to report

    previous_rules = set(previous_state.keys())
    current_rules = set(current_state.keys())

    # Detect deleted rules
    deleted_rules = previous_rules - current_rules
    for rule_name in deleted_rules:
        changes.append({
            'event_name': 'DeleteRule',
            'rule_data': {
                'ruleName': rule_name,
                'ruleArn': previous_state[rule_name].get('arn'),
                'eventBusName': previous_state[rule_name].get('event_bus_name', 'default')
            }
        })

    # Note: PutRule (new rule creation) events are not monitored (removed per requirements)

    # Detect modified rules
    for rule_name in current_rules & previous_rules:
        current_rule = current_state[rule_name]
        previous_rule = previous_state[rule_name]

        # Check state change (enabled/disabled)
        if current_rule['state'] != previous_rule['state']:
            if previous_rule['state'] == 'ENABLED' and current_rule['state'] == 'DISABLED':
                changes.append({
                    'event_name': 'DisableRule',
                    'rule_data': {
                        'ruleName': rule_name,
                        'ruleArn': current_rule.get('arn'),
                        'eventBusName': current_rule.get('event_bus_name', 'default'),
                        'previousState': previous_rule['state'],
                        'currentState': current_rule['state']
                    }
                })
            # Note: EnableRule events are not monitored (removed per requirements)

        # Check event pattern or schedule expression change (rule logic)
        if (current_rule['event_pattern'] != previous_rule['event_pattern'] or
            current_rule['schedule_expression'] != previous_rule['schedule_expression']):
            changes.append({
                'event_name': 'ChangeRuleLogic',
                'rule_data': {
                    'ruleName': rule_name,
                    'ruleArn': current_rule.get('arn'),
                    'eventBusName': current_rule.get('event_bus_name', 'default'),
                    'previousEventPattern': previous_rule.get('event_pattern'),
                    'currentEventPattern': current_rule.get('event_pattern'),
                    'previousScheduleExpression': previous_rule.get('schedule_expression'),
                    'currentScheduleExpression': current_rule.get('schedule_expression')
                }
            })

        # Check event bus change
        if current_rule.get('event_bus_name', 'default') != previous_rule.get('event_bus_name', 'default'):
            changes.append({
                'event_name': 'ChangeRuleEventBus',
                'rule_data': {
                    'ruleName': rule_name,
                    'ruleArn': current_rule.get('arn'),
                    'previousEventBusName': previous_rule.get('event_bus_name', 'default'),
                    'currentEventBusName': current_rule.get('event_bus_name', 'default')
                }
            })

        # Check targets change
        if current_rule['targets'] != previous_rule['targets']:
            changes.append({
                'event_name': 'ChangeRuleTargets',
                'rule_data': {
                    'ruleName': rule_name,
                    'ruleArn': current_rule.get('arn'),
                    'eventBusName': current_rule.get('event_bus_name', 'default'),
                    'previousTargets': previous_rule.get('targets', []),
                    'currentTargets': current_rule.get('targets', []),
                    'previousTargetCount': len(previous_rule.get('targets', [])),
                    'currentTargetCount': len(current_rule.get('targets', []))
                }
            })

        # Note: UpdateRuleDescription events are not monitored (removed per requirements)

        # Check role ARN change
        if current_rule.get('role_arn') != previous_rule.get('role_arn'):
            changes.append({
                'event_name': 'ChangeRuleRole',
                'rule_data': {
                    'ruleName': rule_name,
                    'ruleArn': current_rule.get('arn'),
                    'eventBusName': current_rule.get('event_bus_name', 'default'),
                    'previousRoleArn': previous_rule.get('role_arn'),
                    'currentRoleArn': current_rule.get('role_arn')
                }
            })

    return changes
