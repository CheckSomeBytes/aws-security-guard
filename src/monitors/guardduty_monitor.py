"""
GuardDuty Monitoring Module

Monitors GuardDuty configuration changes:
- Creation, modification, and deletion of suppression rules
- Change to S3 destination
- Change to CloudWatch destination
- Deletion of GuardDuty detector
"""

import boto3
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError


def get_current_state(session: boto3.Session, region: str) -> Dict[str, Any]:
    """
    Get current GuardDuty configuration state

    Args:
        session: boto3 session with appropriate credentials
        region: AWS region to monitor

    Returns:
        Dictionary containing current GuardDuty configurations
    """
    client = session.client('guardduty', region_name=region)

    try:
        state = {
            'detectors': {},
            'suppression_rules': {}
        }

        # Get all detectors
        response = client.list_detectors()
        detector_ids = response.get('DetectorIds', [])

        for detector_id in detector_ids:
            try:
                # Get detector details
                detector_response = client.get_detector(DetectorId=detector_id)

                # Get publishing destinations
                destinations = []
                try:
                    dest_response = client.list_publishing_destinations(
                        DetectorId=detector_id
                    )
                    for dest in dest_response.get('Destinations', []):
                        dest_id = dest['DestinationId']
                        dest_details = client.describe_publishing_destination(
                            DetectorId=detector_id,
                            DestinationId=dest_id
                        )
                        destinations.append({
                            'id': dest_id,
                            'type': dest_details.get('DestinationType'),
                            'properties': dest_details.get('DestinationProperties', {})
                        })
                except ClientError:
                    destinations = []

                # Get data sources for suspension monitoring
                data_sources = detector_response.get('DataSources', {})

                state['detectors'][detector_id] = {
                    'status': detector_response.get('Status'),
                    'service_role': detector_response.get('ServiceRole'),
                    'finding_publishing_frequency': detector_response.get('FindingPublishingFrequency'),
                    'publishing_destinations': destinations,
                    'data_sources': data_sources
                }

                # Get suppression rules (filters)
                try:
                    filter_response = client.list_filters(DetectorId=detector_id)
                    filter_names = filter_response.get('FilterNames', [])

                    for filter_name in filter_names:
                        try:
                            filter_details = client.get_filter(
                                DetectorId=detector_id,
                                FilterName=filter_name
                            )

                            rule_key = f"{detector_id}:{filter_name}"
                            state['suppression_rules'][rule_key] = {
                                'detector_id': detector_id,
                                'name': filter_name,
                                'description': filter_details.get('Description'),
                                'action': filter_details.get('Action'),
                                'rank': filter_details.get('Rank'),
                                'finding_criteria': filter_details.get('FindingCriteria')
                            }
                        except ClientError as e:
                            print(f"Warning: Failed to get filter {filter_name}: {str(e)}")
                            continue

                except ClientError:
                    pass

            except ClientError as e:
                print(f"Warning: Failed to get detector {detector_id}: {str(e)}")
                continue

        return state

    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDeniedException', 'UnauthorizedException']:
            raise PermissionError(f"Access denied to GuardDuty in {region}: {str(e)}")
        raise


def detect_changes(
    previous_state: Optional[Dict[str, Any]],
    current_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect changes between previous and current state

    Args:
        previous_state: Previous GuardDuty configurations
        current_state: Current GuardDuty configurations

    Returns:
        List of detected changes
    """
    changes = []

    if previous_state is None:
        return changes  # First run, no changes to report

    # Detect detector deletions
    previous_detectors = set(previous_state.get('detectors', {}).keys())
    current_detectors = set(current_state.get('detectors', {}).keys())

    deleted_detectors = previous_detectors - current_detectors
    for detector_id in deleted_detectors:
        changes.append({
            'event_name': 'DeleteDetector',
            'guardduty_data': {
                'detectorId': detector_id
            }
        })

    # Detect detector modifications
    for detector_id in current_detectors:
        if detector_id not in previous_detectors:
            continue  # New detector, don't log

        current_detector = current_state['detectors'][detector_id]
        previous_detector = previous_state['detectors'][detector_id]

        # Check for detector suspension (status change)
        previous_status = previous_detector.get('status')
        current_status = current_detector.get('status')

        if previous_status == 'ENABLED' and current_status == 'DISABLED':
            changes.append({
                'event_name': 'SuspendDetector',
                'guardduty_data': {
                    'detectorId': detector_id,
                    'previousStatus': previous_status,
                    'currentStatus': current_status
                }
            })

        # Check for data source suspension
        previous_data_sources = previous_detector.get('data_sources', {})
        current_data_sources = current_detector.get('data_sources', {})

        if previous_data_sources != current_data_sources:
            changes.append({
                'event_name': 'UpdateDataSources',
                'guardduty_data': {
                    'detectorId': detector_id,
                    'previousDataSources': previous_data_sources,
                    'currentDataSources': current_data_sources
                }
            })

        # Check for publishing destination changes
        previous_destinations = previous_detector.get('publishing_destinations', [])
        current_destinations = current_detector.get('publishing_destinations', [])

        # Convert to comparable format
        prev_dest_set = {
            (d['type'], d['properties'].get('DestinationArn'))
            for d in previous_destinations
        }
        curr_dest_set = {
            (d['type'], d['properties'].get('DestinationArn'))
            for d in current_destinations
        }

        if prev_dest_set != curr_dest_set:
            for dest in current_destinations:
                dest_type = dest['type']
                dest_arn = dest['properties'].get('DestinationArn', '')

                # Check if this is a new or modified destination
                if (dest_type, dest_arn) not in prev_dest_set:
                    event_name = 'UpdatePublishingDestination'
                    if dest_type == 'S3':
                        event_name = 'UpdateS3PublishingDestination'

                    changes.append({
                        'event_name': event_name,
                        'guardduty_data': {
                            'detectorId': detector_id,
                            'destinationType': dest_type,
                            'destinationArn': dest_arn
                        }
                    })

    # Detect suppression rule changes
    previous_rules = set(previous_state.get('suppression_rules', {}).keys())
    current_rules = set(current_state.get('suppression_rules', {}).keys())

    # Note: DeleteFilter events are not monitored (removed per requirements)

    # New rules
    new_rules = current_rules - previous_rules
    for rule_key in new_rules:
        rule = current_state['suppression_rules'][rule_key]
        changes.append({
            'event_name': 'CreateFilter',
            'guardduty_data': {
                'detectorId': rule['detector_id'],
                'filterName': rule['name'],
                'description': rule['description'],
                'action': rule['action'],
                'findingCriteria': rule['finding_criteria']
            }
        })

    # Modified rules
    for rule_key in current_rules & previous_rules:
        current_rule = current_state['suppression_rules'][rule_key]
        previous_rule = previous_state['suppression_rules'][rule_key]

        # Check if rule details changed
        if (current_rule['finding_criteria'] != previous_rule['finding_criteria'] or
            current_rule['action'] != previous_rule['action'] or
            current_rule['description'] != previous_rule['description']):
            changes.append({
                'event_name': 'UpdateFilter',
                'guardduty_data': {
                    'detectorId': current_rule['detector_id'],
                    'filterName': current_rule['name'],
                    'description': current_rule['description'],
                    'action': current_rule['action'],
                    'findingCriteria': current_rule['finding_criteria']
                }
            })

    return changes
