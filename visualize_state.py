#!/usr/bin/env python3
"""
AWS Security Watch State Visualizer

Generates an interactive node-based diagram showing all resources being monitored
and their relationships. Updates automatically when the state file changes.

Optional Requirements (for graphical output):
    pip install graphviz watchdog

Usage:
    # Auto-detect state file (if only one account)
    python3 visualize_state.py

    # Specify account ID
    python3 visualize_state.py --account-id 123456789012

    # Watch mode - auto-update on state file changes
    python3 visualize_state.py --watch

    # Specify custom state file
    python3 visualize_state.py --state-file state/123456789012.json

    # Output to different format (png, svg, pdf) - requires graphviz
    python3 visualize_state.py --format svg
"""

import json
import os
import sys
import argparse
import time
import webbrowser
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime

try:
    import graphviz
    HAS_GRAPHVIZ = True
except ImportError:
    HAS_GRAPHVIZ = False
    # Create a dummy graphviz module for type hints
    class graphviz:
        class Digraph:
            pass


class StateVisualizer:
    """Visualizes AWS Security Watch state file as a node diagram"""

    # Color scheme for different resource types
    COLORS = {
        'cloudtrail': '#FF9900',      # AWS Orange
        's3': '#569A31',              # S3 Green
        'sqs': '#FF4F8B',             # SQS Pink
        'sns': '#D9A741',             # SNS Yellow
        'lambda': '#FF9900',          # Lambda Orange
        'iam': '#DD344C',             # IAM Red
        'guardduty': '#759C3E',       # GuardDuty Green
        'eventbridge': '#E7157B',     # EventBridge Magenta
        'region': '#232F3E'           # AWS Dark Blue
    }

    def __init__(self, state_file: str):
        """
        Initialize visualizer

        Args:
            state_file: Path to state.json file
        """
        self.state_file = state_file
        self.graph = None

    def load_state(self) -> Dict[str, Any]:
        """Load state from JSON file"""
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: State file not found: {self.state_file}")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in state file: {str(e)}")
            return {}

    def create_graph(self) -> graphviz.Digraph:
        """Create a new Graphviz graph"""
        graph = graphviz.Digraph(
            name='AWS Security Watch State',
            comment='Resource Monitoring Graph',
            format='png'
        )

        # Graph attributes - vertical layout (LR = Left to Right becomes vertical columns)
        graph.attr(
            rankdir='LR',  # Left to right for vertical tiers
            splines='polyline',  # Cleaner lines for vertical layout
            nodesep='0.8',
            ranksep='2.0',  # More spacing between tiers
            bgcolor='#FAFAFA',
            fontname='Arial',
            fontsize='12'
        )

        # Default node attributes
        graph.attr(
            'node',
            shape='box',
            style='filled,rounded',
            fontname='Arial',
            fontsize='10',
            margin='0.3,0.2',
            width='2.5',  # Fixed width for cleaner vertical alignment
            height='1.0'
        )

        # Default edge attributes
        graph.attr(
            'edge',
            fontname='Arial',
            fontsize='9',
            color='#666666'
        )

        return graph

    def add_cloudtrail_nodes(self, graph: graphviz.Digraph, region: str, trails: Dict[str, Any], state_data: Dict[str, Any] = None) -> Set[str]:
        """Add CloudTrail trail nodes"""
        node_ids = set()
        for trail_name, trail_config in trails.items():
            node_id = f"trail_{region}_{trail_name}"
            node_ids.add(node_id)

            # Create label with key info
            label = f"CloudTrail\\n{trail_name}"
            if trail_config.get('is_logging'):
                label += "\\n🟢 Logging"
            else:
                label += "\\n🔴 Stopped"

            # Create detailed tooltip data
            tooltip_parts = [
                f"<b>CloudTrail Trail: {trail_name}</b>",
                f"Region: {region}",
                f"ARN: {trail_config.get('arn', 'N/A')}",
                f"Status: {'🟢 Logging' if trail_config.get('is_logging') else '🔴 Stopped'}",
                f"Multi-region: {'Yes' if trail_config.get('is_multi_region') else 'No'}",
                f"S3 Bucket: {trail_config.get('s3_bucket', 'N/A')}",
            ]

            if trail_config.get('sns_topic_arn'):
                tooltip_parts.append(f"SNS Topic: {trail_config.get('sns_topic_arn')}")

            tooltip = "<br/>".join(tooltip_parts)

            graph.node(
                node_id,
                label=label,
                fillcolor=self.COLORS['cloudtrail'],
                fontcolor='white',
                tooltip=tooltip
            )

            # Link to S3 bucket
            s3_bucket = trail_config.get('s3_bucket')
            if s3_bucket:
                s3_node_id = f"s3_{s3_bucket}"
                graph.edge(node_id, s3_node_id, label='logs to', style='dashed')

        return node_ids

    def add_s3_nodes(self, graph: graphviz.Digraph, region: str, buckets: Dict[str, Any], state_data: Dict[str, Any] = None) -> Set[str]:
        """Add S3 bucket nodes"""
        node_ids = set()
        for bucket_name, bucket_config in buckets.items():
            node_id = f"s3_{bucket_name}"
            node_ids.add(node_id)

            # Create label
            label = f"S3 Bucket\\n{bucket_name}"

            # Add encryption info
            encryption = bucket_config.get('encryption', {})
            if encryption:
                label += "\\n🔒 Encrypted"

            # Add size info if significant
            size_bytes = bucket_config.get('bucket_size_bytes', 0)
            if size_bytes > 0:
                size_mb = size_bytes / (1024 * 1024)
                if size_mb < 1024:
                    label += f"\\n{size_mb:.1f} MB"
                else:
                    label += f"\\n{size_mb/1024:.1f} GB"

            # Create detailed tooltip
            tooltip_parts = [
                f"<b>S3 Bucket: {bucket_name}</b>",
                f"ARN: {bucket_config.get('arn', 'N/A')}",
                f"Region: {bucket_config.get('region', region)}",
            ]

            if encryption:
                algo = encryption.get('SSEAlgorithm', 'N/A')
                tooltip_parts.append(f"<b>Encryption:</b> {algo}")
                if encryption.get('KMSMasterKeyID'):
                    tooltip_parts.append(f"  KMS Key: {encryption.get('KMSMasterKeyID')}")

            if size_bytes > 0:
                size_mb = size_bytes / (1024 * 1024)
                size_str = f"{size_mb:.1f} MB" if size_mb < 1024 else f"{size_mb/1024:.2f} GB"
                tooltip_parts.append(f"Size: {size_str}")

            tooltip_parts.append(f"Versioning: {bucket_config.get('versioning', 'N/A')}")

            # Add event notifications
            notifications = bucket_config.get('event_notifications', [])
            if notifications:
                tooltip_parts.append(f"<b>Event Notifications ({len(notifications)}):</b>")
                for notif in notifications:
                    dest_type = notif.get('destination_type', 'Unknown')
                    dest_arn = notif.get('destination_arn', 'N/A')
                    dest_name = dest_arn.split(':')[-1] if ':' in dest_arn else dest_arn
                    events = ', '.join(notif.get('events', []))
                    tooltip_parts.append(f"  → {dest_type}: {dest_name}")
                    if events:
                        tooltip_parts.append(f"     Events: {events}")
                    filter_info = notif.get('filter', {})
                    if filter_info.get('prefix'):
                        tooltip_parts.append(f"     Prefix: {filter_info.get('prefix')}")
                    if filter_info.get('suffix'):
                        tooltip_parts.append(f"     Suffix: {filter_info.get('suffix')}")

            tooltip = "<br/>".join(tooltip_parts)

            graph.node(
                node_id,
                label=label,
                fillcolor=self.COLORS['s3'],
                fontcolor='white',
                tooltip=tooltip
            )

            # Link to SNS topics (event notifications)
            for notification in bucket_config.get('event_notifications', []):
                if notification.get('destination_type') == 'SNS':
                    sns_arn = notification.get('destination_arn')
                    if sns_arn:
                        sns_node_id = f"sns_{sns_arn}"
                        graph.edge(node_id, sns_node_id, label='notifies', color='#D9A741')

                elif notification.get('destination_type') == 'SQS':
                    sqs_arn = notification.get('destination_arn')
                    if sqs_arn:
                        sqs_node_id = f"sqs_{sqs_arn}"
                        graph.edge(node_id, sqs_node_id, label='notifies', color='#FF4F8B')

                elif notification.get('destination_type') == 'Lambda':
                    lambda_arn = notification.get('destination_arn')
                    if lambda_arn:
                        lambda_node_id = f"lambda_{lambda_arn}"
                        graph.edge(node_id, lambda_node_id, label='triggers', color='#FF9900')

        return node_ids

    def add_sqs_nodes(self, graph: graphviz.Digraph, region: str, queues: Dict[str, Any], state_data: Dict[str, Any] = None) -> Set[str]:
        """Add SQS queue nodes"""
        node_ids = set()
        for queue_url, queue_config in queues.items():
            queue_name = queue_config.get('queue_name', queue_url.split('/')[-1])
            queue_arn = queue_config.get('arn', queue_url)
            node_id = f"sqs_{queue_arn}"
            node_ids.add(node_id)

            # Create label
            label = f"SQS Queue\\n{queue_name}"

            # Add encryption info
            encryption = queue_config.get('encryption', {})
            if encryption.get('KmsMasterKeyId'):
                label += "\\n🔒 Encrypted"

            # Create detailed tooltip
            tooltip_parts = [
                f"<b>SQS Queue: {queue_name}</b>",
                f"ARN: {queue_arn}",
                f"Region: {region}",
            ]

            if encryption:
                if encryption.get('KmsMasterKeyId'):
                    tooltip_parts.append(f"<b>Encryption:</b>")
                    tooltip_parts.append(f"  KMS Key: {encryption.get('KmsMasterKeyId')}")
                    if encryption.get('KmsDataKeyReusePeriodSeconds'):
                        tooltip_parts.append(f"  Reuse Period: {encryption.get('KmsDataKeyReusePeriodSeconds')}s")

            # Access policy
            access_policy = queue_config.get('access_policy', {})
            if access_policy and access_policy.get('Statement'):
                statements = access_policy.get('Statement', [])
                tooltip_parts.append(f"<b>Access Policy ({len(statements)} statements):</b>")
                for i, stmt in enumerate(statements[:3]):  # Show first 3
                    effect = stmt.get('Effect', 'N/A')
                    principal = stmt.get('Principal', {})
                    if isinstance(principal, dict):
                        service = principal.get('Service', 'N/A')
                        tooltip_parts.append(f"  {i+1}. {effect} - Service: {service}")
                    else:
                        tooltip_parts.append(f"  {i+1}. {effect} - Principal: {principal}")
                if len(statements) > 3:
                    tooltip_parts.append(f"  ... and {len(statements)-3} more")

            # Lambda event sources
            lambda_sources = queue_config.get('lambda_event_sources', [])
            if lambda_sources:
                tooltip_parts.append(f"<b>Lambda Triggers ({len(lambda_sources)}):</b>")
                for mapping in lambda_sources:
                    func_arn = mapping.get('function_arn', 'N/A')
                    func_name = func_arn.split(':')[-1] if ':' in func_arn else func_arn
                    state = mapping.get('state', 'Unknown')
                    tooltip_parts.append(f"  → {func_name} ({state})")

            tooltip = "<br/>".join(tooltip_parts)

            graph.node(
                node_id,
                label=label,
                fillcolor=self.COLORS['sqs'],
                fontcolor='white',
                tooltip=tooltip
            )

        return node_ids

    def add_sns_nodes(self, graph: graphviz.Digraph, region: str, topics: Dict[str, Any], state_data: Dict[str, Any] = None) -> Set[str]:
        """Add SNS topic nodes"""
        node_ids = set()
        for topic_arn, topic_config in topics.items():
            node_id = f"sns_{topic_arn}"
            node_ids.add(node_id)

            # Skip if not accessible
            if not topic_config.get('accessible', True):
                continue

            topic_name = topic_config.get('topic_name', topic_arn.split(':')[-1])

            # Create label
            label = f"SNS Topic\\n{topic_name}"

            # Add encryption info
            encryption = topic_config.get('encryption', {})
            if encryption.get('KmsMasterKeyId'):
                label += "\\n🔒 Encrypted"

            # Create detailed tooltip
            tooltip_parts = [
                f"<b>SNS Topic: {topic_name}</b>",
                f"ARN: {topic_arn}",
                f"Region: {region}",
            ]

            if encryption:
                if encryption.get('KmsMasterKeyId'):
                    tooltip_parts.append(f"<b>Encryption:</b>")
                    tooltip_parts.append(f"  KMS Key: {encryption.get('KmsMasterKeyId')}")

            # Access policy
            access_policy = topic_config.get('access_policy', {})
            if access_policy and access_policy.get('Statement'):
                statements = access_policy.get('Statement', [])
                tooltip_parts.append(f"<b>Access Policy ({len(statements)} statements):</b>")
                for i, stmt in enumerate(statements[:3]):  # Show first 3
                    effect = stmt.get('Effect', 'N/A')
                    principal = stmt.get('Principal', {})
                    if isinstance(principal, dict):
                        service = principal.get('Service', '')
                        aws = principal.get('AWS', '')
                        if service:
                            tooltip_parts.append(f"  {i+1}. {effect} - Service: {service}")
                        elif aws:
                            tooltip_parts.append(f"  {i+1}. {effect} - AWS: {aws}")
                    else:
                        tooltip_parts.append(f"  {i+1}. {effect} - Principal: {principal}")
                if len(statements) > 3:
                    tooltip_parts.append(f"  ... and {len(statements)-3} more")

            # Subscriptions
            subscriptions = topic_config.get('subscriptions', [])
            if subscriptions:
                tooltip_parts.append(f"<b>Subscriptions ({len(subscriptions)}):</b>")
                for sub in subscriptions[:5]:  # Show first 5
                    protocol = sub.get('protocol', 'Unknown')
                    endpoint = sub.get('endpoint', 'N/A')
                    if ':' in endpoint:
                        endpoint = endpoint.split(':')[-1]  # Simplify ARN
                    tooltip_parts.append(f"  → {protocol}: {endpoint}")
                if len(subscriptions) > 5:
                    tooltip_parts.append(f"  ... and {len(subscriptions)-5} more")

            tooltip = "<br/>".join(tooltip_parts)

            graph.node(
                node_id,
                label=label,
                fillcolor=self.COLORS['sns'],
                fontcolor='white',
                tooltip=tooltip
            )

            # Link to SQS queues (subscriptions)
            for subscription in topic_config.get('subscriptions', []):
                if subscription.get('protocol') == 'sqs':
                    endpoint = subscription.get('endpoint')
                    if endpoint:
                        sqs_node_id = f"sqs_{endpoint}"
                        graph.edge(node_id, sqs_node_id, label='publishes to', color='#FF4F8B')

        return node_ids

    def add_lambda_nodes(self, graph: graphviz.Digraph, region: str, functions: Dict[str, Any], state_data: Dict[str, Any] = None) -> Set[str]:
        """Add Lambda function nodes"""
        node_ids = set()
        for func_arn, func_config in functions.items():
            node_id = f"lambda_{func_arn}"
            node_ids.add(node_id)

            func_name = func_config.get('function_name', func_arn.split(':')[-1])

            # Create label
            label = f"Lambda\\n{func_name}"
            runtime = func_config.get('runtime', '')
            if runtime:
                label += f"\\n{runtime}"

            # Create detailed tooltip
            tooltip_parts = [
                f"<b>Lambda Function: {func_name}</b>",
                f"ARN: {func_arn}",
                f"Region: {region}",
            ]

            if runtime:
                tooltip_parts.append(f"Runtime: {runtime}")

            handler = func_config.get('handler')
            if handler:
                tooltip_parts.append(f"Handler: {handler}")

            memory = func_config.get('memory_size')
            timeout = func_config.get('timeout')
            if memory:
                tooltip_parts.append(f"Memory: {memory} MB")
            if timeout:
                tooltip_parts.append(f"Timeout: {timeout}s")

            # Code info
            code_size = func_config.get('code_size')
            code_sha = func_config.get('code_sha256', '')
            if code_size:
                code_size_kb = code_size / 1024
                tooltip_parts.append(f"Code Size: {code_size_kb:.1f} KB")
            if code_sha:
                tooltip_parts.append(f"Code SHA256: {code_sha[:16]}...")

            # Environment variables
            env_vars = func_config.get('environment_variables', {})
            if env_vars:
                tooltip_parts.append(f"<b>Environment Variables ({len(env_vars)}):</b>")
                for key in list(env_vars.keys())[:5]:  # Show first 5 keys
                    tooltip_parts.append(f"  {key}")
                if len(env_vars) > 5:
                    tooltip_parts.append(f"  ... and {len(env_vars)-5} more")

            # VPC config
            vpc_config = func_config.get('vpc_config', {})
            if vpc_config:
                subnets = vpc_config.get('subnet_ids', [])
                sgs = vpc_config.get('security_group_ids', [])
                if subnets or sgs:
                    tooltip_parts.append(f"<b>VPC Configuration:</b>")
                    if subnets:
                        tooltip_parts.append(f"  Subnets: {len(subnets)}")
                    if sgs:
                        tooltip_parts.append(f"  Security Groups: {len(sgs)}")

            # Layers
            layers = func_config.get('layers', [])
            if layers:
                tooltip_parts.append(f"<b>Layers ({len(layers)}):</b>")
                for layer_arn in layers[:3]:
                    layer_name = layer_arn.split(':')[-2] if ':' in layer_arn else layer_arn
                    tooltip_parts.append(f"  {layer_name}")
                if len(layers) > 3:
                    tooltip_parts.append(f"  ... and {len(layers)-3} more")

            # Role
            role_arn = func_config.get('role')
            if role_arn:
                role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn.split(':')[-1]
                tooltip_parts.append(f"<b>Execution Role:</b> {role_name}")

            tooltip = "<br/>".join(tooltip_parts)

            graph.node(
                node_id,
                label=label,
                fillcolor=self.COLORS['lambda'],
                fontcolor='white',
                tooltip=tooltip
            )

            # Link to IAM role
            if role_arn:
                role_node_id = f"iam_{role_arn}"
                graph.edge(node_id, role_node_id, label='assumes', color='#DD344C', style='dashed')

        return node_ids

    def add_iam_nodes(self, graph: graphviz.Digraph, roles: Dict[str, Any], state_data: Dict[str, Any] = None) -> Set[str]:
        """Add IAM role nodes"""
        node_ids = set()
        for role_arn, role_config in roles.items():
            # Skip if not accessible
            if not role_config.get('accessible', True):
                continue

            node_id = f"iam_{role_arn}"
            node_ids.add(node_id)

            role_name = role_config.get('role_name', role_arn.split('/')[-1])

            # Create label
            label = f"IAM Role\\n{role_name}"

            # Add policy count
            managed_count = len(role_config.get('attached_managed_policies', []))
            inline_count = len(role_config.get('inline_policies', {}))
            if managed_count > 0 or inline_count > 0:
                label += f"\\n{managed_count} managed, {inline_count} inline"

            # Create detailed tooltip
            tooltip_parts = [
                f"<b>IAM Role: {role_name}</b>",
                f"ARN: {role_arn}",
                f"Role ID: {role_config.get('role_id', 'N/A')}",
            ]

            path = role_config.get('path', '/')
            if path != '/':
                tooltip_parts.append(f"Path: {path}")

            description = role_config.get('description', '')
            if description:
                tooltip_parts.append(f"Description: {description}")

            max_session = role_config.get('max_session_duration')
            if max_session:
                tooltip_parts.append(f"Max Session: {max_session//3600}h")

            # Trust policy
            trust_policy = role_config.get('trust_policy', {})
            if trust_policy and trust_policy.get('Statement'):
                statements = trust_policy.get('Statement', [])
                tooltip_parts.append(f"<b>Trust Policy ({len(statements)} statements):</b>")
                for i, stmt in enumerate(statements[:3]):
                    effect = stmt.get('Effect', 'N/A')
                    principal = stmt.get('Principal', {})
                    if isinstance(principal, dict):
                        service = principal.get('Service', '')
                        aws = principal.get('AWS', '')
                        if service:
                            if isinstance(service, list):
                                service = ', '.join(service[:2])
                            tooltip_parts.append(f"  {i+1}. {effect} - Service: {service}")
                        elif aws:
                            tooltip_parts.append(f"  {i+1}. {effect} - AWS: {aws}")
                    else:
                        tooltip_parts.append(f"  {i+1}. {effect} - Principal: {principal}")
                if len(statements) > 3:
                    tooltip_parts.append(f"  ... and {len(statements)-3} more")

            # Managed policies
            managed_policies = role_config.get('attached_managed_policies', [])
            if managed_policies:
                tooltip_parts.append(f"<b>Managed Policies ({len(managed_policies)}):</b>")
                for policy in managed_policies[:5]:
                    policy_name = policy.get('policy_name', 'Unknown')
                    tooltip_parts.append(f"  • {policy_name}")
                if len(managed_policies) > 5:
                    tooltip_parts.append(f"  ... and {len(managed_policies)-5} more")

            # Inline policies
            inline_policies = role_config.get('inline_policies', {})
            if inline_policies:
                tooltip_parts.append(f"<b>Inline Policies ({len(inline_policies)}):</b>")
                for i, policy_name in enumerate(list(inline_policies.keys())[:5]):
                    tooltip_parts.append(f"  • {policy_name}")
                if len(inline_policies) > 5:
                    tooltip_parts.append(f"  ... and {len(inline_policies)-5} more")

            # Tags
            tags = role_config.get('tags', {})
            if tags:
                tooltip_parts.append(f"<b>Tags ({len(tags)}):</b>")
                for i, (key, value) in enumerate(list(tags.items())[:3]):
                    tooltip_parts.append(f"  {key}: {value}")
                if len(tags) > 3:
                    tooltip_parts.append(f"  ... and {len(tags)-3} more")

            tooltip = "<br/>".join(tooltip_parts)

            graph.node(
                node_id,
                label=label,
                fillcolor=self.COLORS['iam'],
                fontcolor='white',
                tooltip=tooltip
            )

        return node_ids

    def add_guardduty_nodes(self, graph: graphviz.Digraph, region: str, gd_data: Dict[str, Any]) -> Set[str]:
        """Add GuardDuty nodes"""
        node_ids = set()

        for detector_id, detector_config in gd_data.get('detectors', {}).items():
            node_id = f"gd_{region}_{detector_id}"
            node_ids.add(node_id)

            # Create label
            status = "🟢 Enabled" if detector_config.get('status') == 'ENABLED' else "🔴 Disabled"
            label = f"GuardDuty\\nDetector\\n{status}"

            # Add filter count
            filter_count = len(detector_config.get('filters', {}))
            if filter_count > 0:
                label += f"\\n{filter_count} filters"

            graph.node(
                node_id,
                label=label,
                fillcolor=self.COLORS['guardduty'],
                fontcolor='white'
            )

        return node_ids

    def add_eventbridge_nodes(self, graph: graphviz.Digraph, region: str, rules: Dict[str, Any]) -> Set[str]:
        """Add EventBridge rule nodes"""
        node_ids = set()

        for rule_name, rule_config in rules.items():
            node_id = f"eb_{region}_{rule_name}"
            node_ids.add(node_id)

            # Create label
            state = rule_config.get('state', 'UNKNOWN')
            status = "🟢 Enabled" if state == 'ENABLED' else "🔴 Disabled"
            label = f"EventBridge\\n{rule_name}\\n{status}"

            graph.node(
                node_id,
                label=label,
                fillcolor=self.COLORS['eventbridge'],
                fontcolor='white'
            )

        return node_ids

    def generate_html_visualization(self, output_file: str = 'state_diagram') -> str:
        """
        Generate interactive HTML visualization with tooltips

        Args:
            output_file: Output filename (without extension)

        Returns:
            Path to generated HTML file
        """
        # First generate SVG
        self.graph.format = 'svg'
        svg_data = self.graph.pipe(format='svg').decode('utf-8')

        # Create interactive HTML wrapper
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Watch - Infrastructure Visualization</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        html, body {{
            margin: 0;
            padding: 0;
            height: 100%;
            overflow: hidden;
            font-family: Arial, sans-serif;
            background: #f5f5f5;
        }}
        .container {{
            display: flex;
            flex-direction: column;
            height: 100vh;
            background: white;
        }}
        .header {{
            padding: 15px 20px;
            background: #232F3E;
            color: white;
            border-bottom: 3px solid #FF9900;
        }}
        h1 {{
            margin: 0;
            font-size: 24px;
            color: white;
        }}
        .info {{
            background: #e7f3ff;
            padding: 10px 20px;
            border-left: 4px solid #0073bb;
            font-size: 14px;
        }}
        .controls {{
            padding: 10px 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #ddd;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .svg-container {{
            flex: 1;
            overflow: auto;
            background: white;
            position: relative;
        }}
        svg {{
            min-width: 100%;
            min-height: 100%;
            display: block;
        }}
        button {{
            padding: 8px 16px;
            background: #FF9900;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
        }}
        button:hover {{
            background: #EC7211;
        }}
        .tooltip {{
            position: fixed;
            background: rgba(0, 0, 0, 0.95);
            color: white;
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 13px;
            pointer-events: none;
            z-index: 10000;
            max-width: 400px;
            display: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            line-height: 1.5;
        }}
        .node:hover {{
            cursor: pointer;
            opacity: 0.8;
        }}
        .fullscreen-btn {{
            background: #0073bb;
        }}
        .fullscreen-btn:hover {{
            background: #005a94;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 AWS Security Watch - Infrastructure Map</h1>
        </div>
        <div class="info">
            <strong>Interactive Visualization</strong> - Hover over resources to see details. Ctrl+Scroll to zoom. Drag to pan.
        </div>
        <div class="controls">
            <button onclick="zoomIn()">🔍 Zoom In</button>
            <button onclick="zoomOut()">🔍 Zoom Out</button>
            <button onclick="resetZoom()">↺ Reset View</button>
            <button onclick="fitToScreen()">📐 Fit to Screen</button>
            <button onclick="toggleFullscreen()" class="fullscreen-btn">⛶ Fullscreen</button>
            <button onclick="downloadSVG()">💾 Download SVG</button>
        </div>
        <div class="svg-container" id="svgContainer">
            {svg_data}
        </div>
    </div>
    <div class="tooltip" id="tooltip"></div>

    <script>
        let scale = 1;
        const svgContainer = document.getElementById('svgContainer');
        const svg = svgContainer.querySelector('svg');
        const tooltip = document.getElementById('tooltip');

        // Zoom controls
        function zoomIn() {{
            scale *= 1.2;
            svg.style.transform = `scale(${{scale}})`;
            svg.style.transformOrigin = 'top left';
        }}

        function zoomOut() {{
            scale /= 1.2;
            svg.style.transform = `scale(${{scale}})`;
            svg.style.transformOrigin = 'top left';
        }}

        function resetZoom() {{
            scale = 1;
            svg.style.transform = 'scale(1)';
        }}

        function downloadSVG() {{
            const svgData = svg.outerHTML;
            const blob = new Blob([svgData], {{type: 'image/svg+xml'}});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'aws-security-watch-diagram.svg';
            a.click();
            URL.revokeObjectURL(url);
        }}

        // Add mouseover tooltips to all nodes
        const nodes = svg.querySelectorAll('.node');
        nodes.forEach(node => {{
            node.addEventListener('mouseenter', (e) => {{
                // Try to get tooltip from title element (Graphviz stores tooltip attribute as title)
                const title = node.querySelector('title');
                if (title && title.textContent) {{
                    const titleText = title.textContent.trim();
                    // Check if this is a tooltip (contains HTML) vs a node ID
                    if (titleText.includes('<b>') || titleText.includes('ARN:') || titleText.includes('Region:')) {{
                        tooltip.innerHTML = titleText;
                        tooltip.style.display = 'block';
                        return;
                    }}
                }}

                // Fallback: use text content
                const text = node.querySelector('text');
                if (text) {{
                    tooltip.innerHTML = text.textContent.replace(/\\\\n/g, '<br>');
                    tooltip.style.display = 'block';
                }}
            }});

            node.addEventListener('mousemove', (e) => {{
                tooltip.style.left = (e.pageX + 10) + 'px';
                tooltip.style.top = (e.pageY + 10) + 'px';
            }});

            node.addEventListener('mouseleave', () => {{
                tooltip.style.display = 'none';
            }});
        }});

        // Mouse wheel zoom
        svgContainer.addEventListener('wheel', (e) => {{
            if (e.ctrlKey) {{
                e.preventDefault();
                if (e.deltaY < 0) {{
                    zoomIn();
                }} else {{
                    zoomOut();
                }}
            }}
        }});
    </script>
</body>
</html>"""

        # Write HTML file
        html_path = f"{output_file}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"✓ Interactive visualization generated: {html_path}")
        return html_path

    def generate_visualization(self, output_file: str = 'state_diagram', format: str = 'png') -> str:
        """
        Generate visualization from state file

        Args:
            output_file: Output filename (without extension)
            format: Output format (png, svg, pdf)

        Returns:
            Path to generated file
        """
        state = self.load_state()
        if not state:
            print("Error: Could not load state file")
            return None

        # Create graph
        self.graph = self.create_graph()
        self.graph.format = format

        # Add title with timestamp
        last_updated = state.get('last_updated', 'Unknown')
        title = f"AWS Security Watch State\\nLast Updated: {last_updated}"
        self.graph.attr(label=title, labelloc='t', fontsize='14')

        # Track all nodes
        all_nodes = set()

        # Process each region
        regions = state.get('regions', {})
        for region_name, region_data in regions.items():
            # Create region subgraph
            with self.graph.subgraph(name=f'cluster_{region_name}') as region_graph:
                region_graph.attr(
                    label=f'Region: {region_name}',
                    style='filled',
                    color='lightgrey',
                    fillcolor='#E8E8E8'
                )

                # Add CloudTrail nodes
                if 'cloudtrail' in region_data:
                    trails = region_data['cloudtrail']
                    all_nodes.update(self.add_cloudtrail_nodes(region_graph, region_name, trails, state))

                # Add S3 nodes
                if 's3' in region_data:
                    buckets = region_data['s3'].get('s3_buckets', {})
                    all_nodes.update(self.add_s3_nodes(region_graph, region_name, buckets, state))

                # Add SQS nodes
                if 'sqs' in region_data:
                    queues = region_data['sqs'].get('sqs_queues', {})
                    all_nodes.update(self.add_sqs_nodes(region_graph, region_name, queues, state))

                # Add SNS nodes
                if 'sns' in region_data:
                    topics = region_data['sns'].get('sns_topics', {})
                    all_nodes.update(self.add_sns_nodes(region_graph, region_name, topics, state))

                # Add Lambda nodes
                if 'lambda' in region_data:
                    functions = region_data['lambda'].get('lambda_functions', {})
                    all_nodes.update(self.add_lambda_nodes(region_graph, region_name, functions, state))

                # Add GuardDuty nodes
                if 'guardduty' in region_data:
                    all_nodes.update(self.add_guardduty_nodes(region_graph, region_name, region_data['guardduty']))

                # Add EventBridge nodes
                if 'eventbridge' in region_data:
                    rules = region_data['eventbridge'].get('rules', {})
                    all_nodes.update(self.add_eventbridge_nodes(region_graph, region_name, rules))

        # Add IAM nodes (global, outside region clusters)
        if 'iam' in state:
            roles = state['iam'].get('iam_roles', {})
            all_nodes.update(self.add_iam_nodes(self.graph, roles, state))

        # Render the graph
        try:
            output_path = self.graph.render(output_file, cleanup=True)
            print(f"✓ Visualization generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"Error generating visualization: {str(e)}")
            return None


def open_file(filepath: str) -> bool:
    """
    Open a file with the default system application

    Args:
        filepath: Path to file to open

    Returns:
        True if successful, False otherwise
    """
    try:
        filepath = os.path.abspath(filepath)

        # Check if running on WSL
        is_wsl = 'microsoft' in platform.uname().release.lower() or 'WSL' in os.environ.get('WSL_DISTRO_NAME', '')

        if is_wsl:
            # Convert WSL path to Windows path for HTML files
            if filepath.startswith('/mnt/'):
                # Convert /mnt/c/... to C:\...
                parts = filepath.split('/')
                if len(parts) >= 3:
                    drive = parts[2].upper()
                    path_parts = parts[3:]
                    windows_path = f"{drive}:\\" + "\\".join(path_parts)
                    # Use Windows command to open
                    subprocess.run(['cmd.exe', '/c', 'start', '', windows_path], check=False)
                    return True
            # Fallback for non-/mnt paths
            subprocess.run(['cmd.exe', '/c', 'start', '', filepath], check=False)
            return True
        elif platform.system() == 'Windows':
            os.startfile(filepath)
        elif platform.system() == 'Darwin':  # macOS
            subprocess.run(['open', filepath], check=True)
        else:  # Linux
            # Try xdg-open first, then webbrowser for HTML
            try:
                subprocess.run(['xdg-open', filepath], check=True)
            except:
                if filepath.endswith('.html'):
                    webbrowser.open(f'file://{filepath}')

        return True
    except Exception as e:
        print(f"Note: Could not auto-open file: {str(e)}")
        print(f"Please open manually: {filepath}")
        return False


def watch_state_file(visualizer: StateVisualizer, output_file: str, format: str, interval: int = 5):
    """
    Watch state file for changes and regenerate visualization

    Args:
        visualizer: StateVisualizer instance
        output_file: Output filename
        format: Output format
        interval: Check interval in seconds
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("Error: watchdog module not found. Install with: pip install watchdog")
        print("Falling back to polling mode...")
        watch_state_file_polling(visualizer, output_file, format, interval)
        return

    class StateFileHandler(FileSystemEventHandler):
        def __init__(self, visualizer, output_file, format):
            self.visualizer = visualizer
            self.output_file = output_file
            self.format = format
            self.last_modified = 0

        def on_modified(self, event):
            if event.src_path.endswith('state.json'):
                # Debounce - only regenerate if >2 seconds since last change
                current_time = time.time()
                if current_time - self.last_modified > 2:
                    self.last_modified = current_time
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] State file changed, regenerating visualization...")
                    self.visualizer.generate_visualization(self.output_file, self.format)

    state_dir = os.path.dirname(os.path.abspath(visualizer.state_file))
    event_handler = StateFileHandler(visualizer, output_file, format)
    observer = Observer()
    observer.schedule(event_handler, state_dir, recursive=False)
    observer.start()

    print(f"👁  Watching {visualizer.state_file} for changes...")
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n✓ Stopped watching")
    observer.join()


def watch_state_file_polling(visualizer, output_file: str, format: str, interval: int = 5):
    """Fallback polling-based file watching"""
    last_mtime = 0

    print(f"👁  Watching {visualizer.state_file} for changes (polling every {interval}s)...")
    print("Press Ctrl+C to stop")

    try:
        while True:
            try:
                current_mtime = os.path.getmtime(visualizer.state_file)
                if current_mtime != last_mtime:
                    if last_mtime > 0:  # Skip first iteration
                        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] State file changed, regenerating visualization...")
                        if HAS_GRAPHVIZ:
                            visualizer.generate_visualization(output_file, format)
                        else:
                            visualizer.generate_text_visualization()
                    last_mtime = current_mtime
            except FileNotFoundError:
                print(f"Warning: State file not found: {visualizer.state_file}")

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n✓ Stopped watching")


class TextVisualizer:
    """Text-based state visualizer (no graphviz required)"""

    # Unicode box drawing characters
    BOX = {
        'tl': '┌', 'tr': '┐', 'bl': '└', 'br': '┘',
        'h': '─', 'v': '│', 'cross': '┼',
        'arrow': '→', 'dot': '•'
    }

    # Icons for resource types
    ICONS = {
        'cloudtrail': '📋',
        's3': '🪣',
        'sqs': '📬',
        'sns': '📢',
        'lambda': 'λ',
        'iam': '🔐',
        'guardduty': '🛡️',
        'eventbridge': '⚡'
    }

    def __init__(self, state_file: str):
        self.state_file = state_file

    def load_state(self) -> Dict[str, Any]:
        """Load state from JSON file"""
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: State file not found: {self.state_file}")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in state file: {str(e)}")
            return {}

    def print_header(self, title: str, width: int = 80):
        """Print a formatted header"""
        print()
        print(self.BOX['tl'] + self.BOX['h'] * (width - 2) + self.BOX['tr'])
        padding = (width - len(title) - 2) // 2
        print(self.BOX['v'] + ' ' * padding + title + ' ' * (width - padding - len(title) - 2) + self.BOX['v'])
        print(self.BOX['bl'] + self.BOX['h'] * (width - 2) + self.BOX['br'])
        print()

    def print_section(self, title: str, width: int = 80):
        """Print a section header"""
        print(f"\n{self.BOX['h'] * 3} {title} {self.BOX['h'] * (width - len(title) - 6)}")

    def print_resource(self, icon: str, resource_type: str, name: str, details: List[str] = None, indent: int = 0):
        """Print a resource with details"""
        prefix = '  ' * indent
        print(f"{prefix}{icon} {resource_type}: {name}")
        if details:
            for detail in details:
                print(f"{prefix}   {self.BOX['dot']} {detail}")

    def print_relationship(self, source: str, target: str, relationship: str, indent: int = 0):
        """Print a relationship between resources"""
        prefix = '  ' * indent
        print(f"{prefix}   {self.BOX['arrow']} {relationship} {self.BOX['arrow']} {target}")

    def generate_text_visualization(self) -> None:
        """Generate text-based visualization"""
        state = self.load_state()
        if not state:
            print("Error: Could not load state file")
            return

        # Print header
        last_updated = state.get('last_updated', 'Unknown')
        self.print_header(f"AWS Security Watch State - Updated: {last_updated}")

        # Track total counts
        totals = {
            'cloudtrail': 0,
            's3': 0,
            'sqs': 0,
            'sns': 0,
            'lambda': 0,
            'iam': 0,
            'guardduty': 0,
            'eventbridge': 0
        }

        # Process each region
        regions = state.get('regions', {})
        for region_name, region_data in sorted(regions.items()):
            self.print_section(f"Region: {region_name}")

            # CloudTrail
            if 'cloudtrail' in region_data:
                trails = region_data['cloudtrail']
                for trail_name, trail_config in sorted(trails.items()):
                    totals['cloudtrail'] += 1
                    status = "🟢 Logging" if trail_config.get('is_logging') else "🔴 Stopped"
                    s3_bucket = trail_config.get('s3_bucket', 'N/A')
                    details = [
                        f"Status: {status}",
                        f"Multi-region: {'Yes' if trail_config.get('is_multi_region') else 'No'}"
                    ]
                    self.print_resource(self.ICONS['cloudtrail'], 'CloudTrail', trail_name, details, indent=1)
                    self.print_relationship(trail_name, s3_bucket, 'logs to', indent=1)

            # S3 Buckets
            if 's3' in region_data:
                buckets = region_data['s3'].get('s3_buckets', {})
                for bucket_name, bucket_config in sorted(buckets.items()):
                    totals['s3'] += 1
                    details = []

                    # Encryption
                    if bucket_config.get('encryption', {}).get('Rules'):
                        details.append("🔒 Encrypted")

                    # Size
                    size_bytes = bucket_config.get('total_size_bytes', 0)
                    if size_bytes > 0:
                        size_mb = size_bytes / (1024 * 1024)
                        if size_mb < 1024:
                            details.append(f"Size: {size_mb:.1f} MB")
                        else:
                            details.append(f"Size: {size_mb/1024:.1f} GB")

                    # Object count
                    obj_count = bucket_config.get('object_count', 0)
                    if obj_count > 0:
                        details.append(f"Objects: {obj_count}")

                    self.print_resource(self.ICONS['s3'], 'S3 Bucket', bucket_name, details, indent=1)

                    # Event notifications
                    for notification in bucket_config.get('event_notifications', []):
                        dest_type = notification.get('destination_type')
                        dest_arn = notification.get('destination_arn', 'N/A')
                        if dest_type:
                            dest_name = dest_arn.split(':')[-1] if ':' in dest_arn else dest_arn
                            self.print_relationship(bucket_name, f"{dest_type}: {dest_name}", 'notifies', indent=1)

            # SQS Queues
            if 'sqs' in region_data:
                queues = region_data['sqs'].get('sqs_queues', {})
                for queue_url, queue_config in sorted(queues.items()):
                    totals['sqs'] += 1
                    queue_name = queue_config.get('queue_name', queue_url.split('/')[-1])
                    details = []

                    if queue_config.get('encryption', {}).get('KmsMasterKeyId'):
                        details.append("🔒 Encrypted")

                    retention = queue_config.get('message_retention_period')
                    if retention:
                        details.append(f"Retention: {int(retention)//3600}h")

                    self.print_resource(self.ICONS['sqs'], 'SQS Queue', queue_name, details, indent=1)

            # SNS Topics
            if 'sns' in region_data:
                topics = region_data['sns'].get('sns_topics', {})
                for topic_arn, topic_config in sorted(topics.items()):
                    if not topic_config.get('accessible', True):
                        continue

                    totals['sns'] += 1
                    topic_name = topic_config.get('topic_name', topic_arn.split(':')[-1])
                    details = []

                    if topic_config.get('encryption', {}).get('KmsMasterKeyId'):
                        details.append("🔒 Encrypted")

                    sub_count = len(topic_config.get('subscriptions', []))
                    if sub_count > 0:
                        details.append(f"Subscriptions: {sub_count}")

                    self.print_resource(self.ICONS['sns'], 'SNS Topic', topic_name, details, indent=1)

            # Lambda Functions
            if 'lambda' in region_data:
                functions = region_data['lambda'].get('lambda_functions', {})
                for func_arn, func_config in sorted(functions.items()):
                    totals['lambda'] += 1
                    func_name = func_config.get('function_name', func_arn.split(':')[-1])
                    details = []

                    runtime = func_config.get('runtime')
                    if runtime:
                        details.append(f"Runtime: {runtime}")

                    memory = func_config.get('memory_size')
                    if memory:
                        details.append(f"Memory: {memory} MB")

                    self.print_resource(self.ICONS['lambda'], 'Lambda', func_name, details, indent=1)

                    role_arn = func_config.get('role')
                    if role_arn:
                        role_name = role_arn.split('/')[-1]
                        self.print_relationship(func_name, f"IAM: {role_name}", 'assumes', indent=1)

            # GuardDuty
            if 'guardduty' in region_data:
                gd_data = region_data['guardduty']
                for detector_id, detector_config in sorted(gd_data.get('detectors', {}).items()):
                    totals['guardduty'] += 1
                    status = detector_config.get('status', 'UNKNOWN')
                    status_icon = "🟢" if status == 'ENABLED' else "🔴"
                    details = [
                        f"{status_icon} {status}",
                        f"Filters: {len(detector_config.get('filters', {}))}"
                    ]
                    self.print_resource(self.ICONS['guardduty'], 'GuardDuty', detector_id[:8] + '...', details, indent=1)

            # EventBridge
            if 'eventbridge' in region_data:
                rules = region_data['eventbridge'].get('rules', {})
                for rule_name, rule_config in sorted(rules.items()):
                    totals['eventbridge'] += 1
                    state_val = rule_config.get('state', 'UNKNOWN')
                    status_icon = "🟢" if state_val == 'ENABLED' else "🔴"
                    details = [f"{status_icon} {state_val}"]
                    self.print_resource(self.ICONS['eventbridge'], 'EventBridge', rule_name, details, indent=1)

        # IAM Roles (global)
        if 'iam' in state:
            self.print_section("IAM Roles (Global)")
            roles = state['iam'].get('iam_roles', {})
            for role_arn, role_config in sorted(roles.items()):
                if not role_config.get('accessible', True):
                    continue

                totals['iam'] += 1
                role_name = role_config.get('role_name', role_arn.split('/')[-1])
                managed_count = len(role_config.get('attached_managed_policies', []))
                inline_count = len(role_config.get('inline_policies', {}))
                details = [
                    f"Managed policies: {managed_count}",
                    f"Inline policies: {inline_count}"
                ]
                self.print_resource(self.ICONS['iam'], 'IAM Role', role_name, details, indent=1)

        # Print summary
        print()
        self.print_section("Summary")
        print()
        for resource_type, count in sorted(totals.items()):
            if count > 0:
                icon = self.ICONS.get(resource_type, self.BOX['dot'])
                print(f"  {icon} {resource_type.replace('_', ' ').title()}: {count}")

        total = sum(totals.values())
        print(f"\n  Total resources monitored: {total}")
        print()


def main():
    parser = argparse.ArgumentParser(description='AWS Security Watch State Visualizer')
    parser.add_argument(
        '--state-file',
        type=str,
        default=None,
        help='Path to state file (default: auto-detect from state directory)'
    )
    parser.add_argument(
        '--state-dir',
        type=str,
        default='state',
        help='State directory containing account JSON files (default: state)'
    )
    parser.add_argument(
        '--account-id',
        type=str,
        default=None,
        help='AWS Account ID (auto-detected if only one state file exists)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='state_diagram',
        help='Output filename without extension (default: state_diagram)'
    )
    parser.add_argument(
        '--format',
        type=str,
        choices=['png', 'svg', 'pdf', 'html'],
        default='html',
        help='Output format (default: html for interactive visualization)'
    )
    parser.add_argument(
        '--watch',
        action='store_true',
        help='Watch state file and auto-regenerate on changes'
    )
    parser.add_argument(
        '--open',
        action='store_true',
        default=True,
        help='Automatically open visualization in browser/viewer (default: true)'
    )
    parser.add_argument(
        '--no-open',
        action='store_true',
        help='Do not automatically open the visualization'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=5,
        help='Watch interval in seconds (default: 5)'
    )

    args = parser.parse_args()

    # Determine state file path
    state_file = args.state_file

    if not state_file:
        # Auto-detect from state directory
        state_dir = Path(args.state_dir)

        if not state_dir.exists():
            print(f"Error: State directory not found: {args.state_dir}")
            print(f"Run the monitoring script first or specify --state-file")
            return

        # Find JSON files in state directory
        json_files = list(state_dir.glob('*.json'))

        if not json_files:
            print(f"Error: No state files found in {args.state_dir}")
            print(f"Run the monitoring script first or specify --state-file")
            return

        if args.account_id:
            # Use specified account ID
            state_file = state_dir / f"{args.account_id}.json"
            if not state_file.exists():
                print(f"Error: State file not found for account {args.account_id}")
                print(f"Available accounts: {', '.join([f.stem for f in json_files])}")
                return
        elif len(json_files) == 1:
            # Only one state file, use it
            state_file = json_files[0]
            print(f"Auto-detected state file: {state_file}")
        else:
            # Multiple state files, need user to specify
            print(f"Error: Multiple account state files found in {args.state_dir}:")
            for f in json_files:
                print(f"  - {f.stem}")
            print(f"\nSpecify which account to visualize:")
            print(f"  --account-id <account_id>")
            print(f"  or --state-file <path>")
            return

        state_file = str(state_file)

    # Check if state file exists
    if not os.path.exists(state_file):
        print(f"Error: State file not found: {state_file}")
        return

    # Check if graphviz is available
    if not HAS_GRAPHVIZ:
        print("=" * 70)
        print("NOTE: Using text-based visualization (graphviz not found)")
        print("=" * 70)
        print("\nFor graphical diagrams (PNG/SVG/PDF), install both:")
        print("\n1. Python graphviz module:")
        print("   pip install graphviz")
        print("\n2. Graphviz software:")
        print("   • Ubuntu/Debian: sudo apt-get install graphviz")
        print("   • macOS: brew install graphviz")
        print("   • Windows: https://graphviz.org/download/")
        print("\nProceeding with text-based visualization...")
        print("=" * 70)
        print()

        # Use text visualizer
        visualizer = TextVisualizer(state_file)
        visualizer.generate_text_visualization()

        if args.watch:
            # Watch for changes
            watch_state_file_polling(visualizer, args.output, args.format, args.interval)
        return

    # Create graphviz visualizer
    visualizer = StateVisualizer(state_file)

    # Build the graph first
    state_data = visualizer.load_state()
    if not state_data:
        print("Error: Could not load state file")
        return

    visualizer.graph = visualizer.create_graph()

    # Add title
    last_updated = state_data.get('last_updated', 'Unknown')
    title = f"AWS Security Watch State\\nLast Updated: {last_updated}"
    visualizer.graph.attr(label=title, labelloc='t', fontsize='14')

    # Process state and add nodes (simplified version - full logic moved to generate_visualization)
    regions = state_data.get('regions', {})
    for region_name, region_data in sorted(regions.items()):
        with visualizer.graph.subgraph(name=f'cluster_{region_name}') as region_graph:
            region_graph.attr(label=f'Region: {region_name}', style='filled', color='lightgrey', fillcolor='#E8E8E8')

            if 'cloudtrail' in region_data:
                visualizer.add_cloudtrail_nodes(region_graph, region_name, region_data['cloudtrail'], state_data)
            if 's3' in region_data:
                visualizer.add_s3_nodes(region_graph, region_name, region_data['s3'].get('s3_buckets', {}), state_data)
            if 'sqs' in region_data:
                visualizer.add_sqs_nodes(region_graph, region_name, region_data['sqs'].get('sqs_queues', {}), state_data)
            if 'sns' in region_data:
                visualizer.add_sns_nodes(region_graph, region_name, region_data['sns'].get('sns_topics', {}), state_data)
            if 'lambda' in region_data:
                visualizer.add_lambda_nodes(region_graph, region_name, region_data['lambda'].get('lambda_functions', {}), state_data)
            if 'guardduty' in region_data:
                visualizer.add_guardduty_nodes(region_graph, region_name, region_data['guardduty'])
            if 'eventbridge' in region_data:
                visualizer.add_eventbridge_nodes(region_graph, region_name, region_data['eventbridge'].get('rules', {}))

    if 'iam' in state_data:
        visualizer.add_iam_nodes(visualizer.graph, state_data['iam'].get('iam_roles', {}), state_data)

    # Generate output based on format
    print(f"Generating {args.format.upper()} visualization from {state_file}...")
    try:
        if args.format == 'html':
            output_path = visualizer.generate_html_visualization(args.output)
        else:
            output_path = visualizer.generate_visualization(args.output, args.format)
    except Exception as e:
        error_msg = str(e)
        if 'failed to execute' in error_msg.lower() or 'command not found' in error_msg.lower() or 'dot' in error_msg.lower():
            print("\n" + "=" * 70)
            print("ERROR: Graphviz software not found!")
            print("=" * 70)
            print("\nThe Python 'graphviz' module is installed, but the Graphviz")
            print("software (which includes the 'dot' command) is not found.")
            print("\nInstall Graphviz software:")
            print("   • Ubuntu/Debian: sudo apt-get install graphviz")
            print("   • macOS: brew install graphviz")
            print("   • Windows: Download from https://graphviz.org/download/")
            print("\nOr use text-based visualization (no installation needed):")
            print("   The script will automatically use text mode if you uninstall")
            print("   the Python graphviz module: pip uninstall graphviz")
            print("=" * 70)
            return
        else:
            print(f"Error generating visualization: {error_msg}")
            return

    # Auto-open the visualization (unless --no-open specified)
    should_open = args.open and not args.no_open
    if output_path and should_open:
        print(f"\nOpening visualization in browser/viewer...")
        open_file(output_path)

    if output_path and args.watch:
        # Watch for changes
        watch_state_file(visualizer, args.output, args.format, args.interval)


if __name__ == '__main__':
    main()
