#!/usr/bin/env python3
"""
AWS Security Guard - Web GUI

Read-only web front end for aws-security-guard.py. It reads the same state
directory (to draw the log pipeline) and log file (to list alerts) that the
monitor writes, so it can run alongside the monitor without touching AWS.

Usage:
    python web/server.py [--port 54100] [--state-dir state] [--log-file security-watch.log]
"""

import argparse
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
import state_manager  # noqa: E402  (stdlib-only module shared with the monitor)

STATIC_DIR = Path(__file__).parent / 'static'
LIVE = 'current'

# Fields that change on nearly every scan; shown but not treated as a config change
VOLATILE_FIELDS = {'bucket_size_bytes'}

# Pipeline stage (diagram column) for each resource type
STAGES = {
    'trail': 0, 'detector': 0, 'rule': 0,
    'bucket': 1,
    'topic': 2, 'queue': 2,
    'function': 3,
    'role': 4,
}

SEVERITY = {
    'critical': {
        'StopLogging', 'DeleteTrail', 'UpdateTrailS3Bucket', 'DeleteDetector',
        'SuspendDetector', 'DeleteBucket', 'S3BucketSizeReduction', 'CreateFilter',
    },
    'high': {
        'UpdateEventSelectors', 'UpdateDataSources', 'UpdatePublishingDestination',
        'UpdateFilter', 'DeleteRule', 'DisableRule', 'ChangeRuleTargets', 'ChangeRuleLogic',
        'ChangeRuleRole', 'ChangeRuleEventBus', 'UpdateBucketNotificationDestination',
        'DeleteQueue', 'UpdateQueuePolicy', 'DeleteQueueLambdaTrigger', 'DeleteTopic',
        'UpdateTopicPolicy', 'DeleteTopicSubscription', 'UpdateTopicSubscription',
        'DeleteFunction', 'UpdateFunctionCode', 'UpdateFunctionRole', 'DeleteRole',
        'UpdateAssumeRolePolicy', 'AttachRolePolicy', 'PutRolePolicy', 'UpdateRolePolicy',
    },
    'error': {'PermissionError', 'MonitoringAPIFailure'},
}


def severity_for(event_name):
    for level, names in SEVERITY.items():
        if event_name in names:
            return level
    return 'medium'


def arn_type(arn):
    """Guess a node type from an ARN so unmonitored targets still get the right icon."""
    service = arn.split(':')[2] if arn.startswith('arn:') and arn.count(':') >= 5 else ''
    return {
        'lambda': 'function', 'sns': 'topic', 'sqs': 'queue', 's3': 'bucket',
        'iam': 'role', 'cloudtrail': 'trail', 'events': 'rule',
    }.get(service, 'external')


def arn_name(arn):
    return re.split(r'[:/]', arn.rstrip('/'))[-1] if arn else arn


class PipelineGraph:
    """Builds diagram nodes/edges from one account's state file."""

    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, node_id, node_type, name, region, details, keys=()):
        if node_id in self.nodes:
            return
        self.nodes[node_id] = {
            'id': node_id,
            'type': node_type,
            'name': name,
            'region': region,
            'stage': STAGES[node_type],
            'external': False,
            'details': details,
            # Every string an alert might use to refer to this resource
            'keys': sorted({k for k in (node_id, name, *keys) if k}),
        }

    def add_edge(self, source, target, label):
        if source and target and source != target:
            self.edges.append({'source': source, 'target': target, 'label': label})

    def finish(self):
        # Targets that the monitor references but does not track (e.g. an
        # EventBridge rule pointing at a Lambda outside the CloudTrail ecosystem)
        for edge in self.edges:
            target = edge['target']
            if target not in self.nodes:
                node_type = arn_type(target)
                region = target.split(':')[3] if target.startswith('arn:') else ''
                self.nodes[target] = {
                    'id': target,
                    'type': node_type,
                    'name': arn_name(target),
                    'region': region or 'global',
                    'stage': STAGES.get(node_type, 3),
                    'external': True,
                    'details': {'arn': target},
                    'keys': [target, arn_name(target)],
                }
        return {'nodes': list(self.nodes.values()), 'edges': self.edges}


def build_graph(state):
    g = PipelineGraph()
    regions = state.get('regions', {})

    for region, services in regions.items():
        for name, trail in (services.get('cloudtrail') or {}).items():
            g.add_node(trail.get('arn') or name, 'trail', name, trail.get('home_region', region), trail)

        for rule_name, rule in (services.get('eventbridge') or {}).items():
            g.add_node(rule.get('arn') or f'{region}:{rule_name}', 'rule', rule_name, region, rule)

        guardduty = services.get('guardduty') or {}
        for detector_id, detector in (guardduty.get('detectors') or {}).items():
            filters = {k: v for k, v in (guardduty.get('suppression_rules') or {}).items()
                       if isinstance(v, dict) and v.get('detector_id', detector_id) == detector_id}
            g.add_node(f'guardduty:{region}:{detector_id}', 'detector', f'GuardDuty {region}', region,
                       {**detector, 'detector_id': detector_id, 'suppression_rules': filters},
                       keys=[detector_id, *(f.get('name') for f in filters.values())])

        for bucket_name, bucket in ((services.get('s3') or {}).get('s3_buckets') or {}).items():
            g.add_node(bucket.get('arn') or f'arn:aws:s3:::{bucket_name}', 'bucket', bucket_name,
                       bucket.get('region', region), bucket)

        for queue_url, queue in ((services.get('sqs') or {}).get('sqs_queues') or {}).items():
            g.add_node(queue.get('arn') or queue_url, 'queue', queue.get('queue_name', arn_name(queue_url)),
                       queue.get('region', region), {**queue, 'url': queue_url}, keys=[queue_url])

        for topic_arn, topic in ((services.get('sns') or {}).get('sns_topics') or {}).items():
            g.add_node(topic.get('arn') or topic_arn, 'topic', topic.get('topic_name', arn_name(topic_arn)),
                       topic.get('region', region), topic)

        for func_arn, func in ((services.get('lambda') or {}).get('lambda_functions') or {}).items():
            g.add_node(func.get('arn') or func_arn, 'function', func.get('function_name', arn_name(func_arn)),
                       func.get('region', region), func)

        for role_arn, role in ((services.get('iam') or {}).get('iam_roles') or {}).items():
            g.add_node(role.get('arn') or role_arn, 'role', role.get('role_name', arn_name(role_arn)),
                       'global', role, keys=[role.get('role_id')])

    # Edges are added after all nodes exist so lookups by name work
    by_type_name = {(n['type'], n['name']): n['id'] for n in g.nodes.values()}

    for node in list(g.nodes.values()):
        d = node['details']
        if node['type'] == 'trail' and d.get('s3_bucket'):
            bucket_id = by_type_name.get(('bucket', d['s3_bucket']), f"arn:aws:s3:::{d['s3_bucket']}")
            g.add_edge(node['id'], bucket_id, 'delivers logs')
        elif node['type'] == 'detector':
            for dest in d.get('publishing_destinations') or []:
                dest_arn = (dest.get('properties') or {}).get('DestinationArn', '')
                if dest_arn.startswith('arn:aws:s3:::'):
                    dest_arn = 'arn:aws:s3:::' + dest_arn.split(':::')[1].split('/')[0]
                g.add_edge(node['id'], dest_arn, 'exports findings')
        elif node['type'] == 'rule':
            for target in d.get('targets') or []:
                g.add_edge(node['id'], target.get('Arn'), 'rule target')
        elif node['type'] == 'bucket':
            for notif in d.get('event_notifications') or []:
                g.add_edge(node['id'], notif.get('destination_arn'), 'object events')
        elif node['type'] == 'topic':
            for sub in d.get('subscriptions') or []:
                if (sub.get('endpoint') or '').startswith('arn:'):
                    g.add_edge(node['id'], sub['endpoint'], f"{sub.get('protocol', '')} subscription".strip())
        elif node['type'] == 'queue':
            for mapping in d.get('lambda_event_sources') or []:
                g.add_edge(node['id'], mapping.get('function_arn'), 'triggers')
        elif node['type'] == 'function' and d.get('role'):
            g.add_edge(node['id'], d['role'], 'executes as')

    return g.finish()


def read_alerts(log_file):
    """Parse the JSON-lines log. Unparseable lines are skipped, not fatal."""
    alerts = []
    path = Path(log_file)
    if not path.exists():
        return alerts
    with open(path, 'r', errors='replace') as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            event['raw'] = line  # the log entry exactly as written, before GUI-added fields
            event.setdefault('eventID', f'line-{line_no}')
            event['severity'] = severity_for(event.get('eventName', ''))
            event['resource'] = primary_resource(event.get('responseElements') or {})
            alerts.append(event)
    return alerts


RESOURCE_KEYS = ('trailName', 'bucketName', 'queueName', 'topicName', 'functionName',
                 'roleName', 'ruleName', 'filterName', 'detectorId')


def primary_resource(elements):
    for key in RESOURCE_KEYS:
        if elements.get(key):
            return str(elements[key])
    for key, value in elements.items():
        if isinstance(value, str) and re.search(r'(name|Name|Arn|arn|Id)$', key):
            return value
    return ''


def strings_in(value, depth=0):
    if depth > 4:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings_in(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            yield from strings_in(v, depth + 1)


def attach_alerts(graph, alerts, account_id):
    """Tag each node with the IDs of alerts that mention it."""
    key_to_nodes = {}
    for node in graph['nodes']:
        node['alertIds'] = []
        for key in node['keys']:
            key_to_nodes.setdefault(key, []).append(node)
    for alert in alerts:
        if str(alert.get('recipientAccountId')) != account_id:
            continue
        hit = set()
        for s in strings_in(alert.get('responseElements') or {}):
            for node in key_to_nodes.get(s, []):
                if node['id'] not in hit:
                    hit.add(node['id'])
                    node['alertIds'].append(alert['eventID'])
    return graph


def edge_key(edge):
    return (edge['source'], edge['target'], edge['label'])


def comparable(details):
    return json.dumps({k: v for k, v in details.items() if k not in VOLATILE_FIELDS},
                      sort_keys=True, default=str)


def diff_graphs(previous, current):
    """
    Mark each node/edge of `current` as added or changed relative to
    `previous`, and append what was removed so it can be drawn as a ghost.
    Returns the number of changed resources.
    """
    prev_nodes = {n['id']: n for n in previous['nodes']}
    cur_ids = {n['id'] for n in current['nodes']}
    count = 0

    for node in current['nodes']:
        old = prev_nodes.get(node['id'])
        node['change'] = None
        if old is None:
            # A referenced-only target has no config of its own to be "new"
            if not node['external']:
                node['change'] = 'added'
        elif comparable(old['details']) != comparable(node['details']):
            node['change'] = 'changed'
            keys = set(old['details']) | set(node['details'])
            node['changedFields'] = sorted(
                k for k in keys - VOLATILE_FIELDS
                if json.dumps(old['details'].get(k), sort_keys=True, default=str)
                != json.dumps(node['details'].get(k), sort_keys=True, default=str))
        count += node['change'] is not None

    for node_id, old in prev_nodes.items():
        if node_id not in cur_ids:
            current['nodes'].append({**old, 'change': 'removed', 'alertIds': []})
            count += not old['external']

    prev_edges = {edge_key(e) for e in previous['edges']}
    cur_edges = {edge_key(e) for e in current['edges']}
    for edge in current['edges']:
        edge['change'] = None if edge_key(edge) in prev_edges else 'added'
    for edge in previous['edges']:
        if edge_key(edge) not in cur_edges:
            current['edges'].append({**edge, 'change': 'removed'})
    return count


def snapshot_time(path):
    stamp = path.name.split('.')[0]
    return datetime.strptime(stamp, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc).timestamp()


_graph_cache = {}


def cached_graph(path, loader):
    """Snapshots never change once written, so their graphs are cached by path+mtime."""
    key = (str(path), path.stat().st_mtime)
    if key not in _graph_cache:
        _graph_cache[key] = json.dumps(build_graph(loader(path)))
    return json.loads(_graph_cache[key])


def load_live(path):
    with open(path) as f:
        return json.load(f)


def list_versions(state_dir, account_id):
    """
    Versions oldest first: every history snapshot, plus the live state file
    when it differs from the newest snapshot (e.g. history started later).
    Each version is (id, time, path, loader).
    """
    versions = [(p.name.split('.')[0], snapshot_time(p), p, state_manager.load_history_snapshot)
                for p in state_manager.list_history_snapshots(state_dir, account_id)]
    live = state_manager.get_state_file_path(state_dir, account_id)
    if live.exists():
        live_state = load_live(live)
        if not versions or json.dumps(state_manager.load_history_snapshot(versions[-1][2]), sort_keys=True, default=str) \
                != json.dumps(live_state, sort_keys=True, default=str):
            versions.append((LIVE, live.stat().st_mtime, live, load_live))
        else:
            # The newest snapshot is the live state; label it as such
            vid, _, path, loader = versions[-1]
            versions[-1] = (vid, live.stat().st_mtime, path, loader)
    return versions


class Handler(SimpleHTTPRequestHandler):
    state_dir = 'state'
    log_file = 'security-watch.log'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt, *args):
        pass  # keep the console quiet; the monitor owns stdout

    def send_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        routes = {
            '/api/status': self.api_status,
            '/api/graph': self.api_graph,
            '/api/history': self.api_history,
            '/api/alerts': self.api_alerts,
        }
        if url.path in routes:
            try:
                routes[url.path](query)
            except Exception as e:  # surface errors to the UI rather than dropping the socket
                self.send_json({'error': str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        super().do_GET()

    def accounts(self):
        state_path = Path(self.state_dir)
        if not state_path.is_dir():
            return []
        return sorted(
            ({'accountId': p.stem, 'updated': p.stat().st_mtime}
             for p in state_path.glob('*.json') if re.fullmatch(r'\d{12}', p.stem)),
            key=lambda a: a['accountId'])

    def api_status(self, query):
        log_path = Path(self.log_file)
        self.send_json({
            'stateDir': str(Path(self.state_dir).resolve()),
            'logFile': str(log_path.resolve()),
            'logExists': log_path.exists(),
            'logUpdated': log_path.stat().st_mtime if log_path.exists() else None,
            'accounts': self.accounts(),
        })

    def account_param(self, query):
        account_id = (query.get('account') or [''])[0]
        if not re.fullmatch(r'\d{12}', account_id):
            self.send_json({'error': 'account must be a 12-digit account ID'}, HTTPStatus.BAD_REQUEST)
            return None
        return account_id

    def api_history(self, query):
        account_id = self.account_param(query)
        if not account_id:
            return
        versions = list_versions(self.state_dir, account_id)
        result, previous = [], None
        for vid, when, path, loader in versions:
            graph = cached_graph(path, loader)
            changes = diff_graphs(previous, graph) if previous else None
            result.append({'id': vid, 'time': when, 'live': False, 'changes': changes})
            previous = cached_graph(path, loader)
        if result:
            result[-1]['live'] = True
        result.reverse()  # newest first for the picker
        self.send_json({'versions': result})

    def api_graph(self, query):
        account_id = self.account_param(query)
        if not account_id:
            return
        wanted = (query.get('version') or [''])[0]
        versions = list_versions(self.state_dir, account_id)
        if not versions:
            self.send_json({'error': f'No state file for account {account_id}'}, HTTPStatus.NOT_FOUND)
            return
        index = len(versions) - 1
        if wanted:
            ids = [v[0] for v in versions]
            if wanted not in ids:
                self.send_json({'error': f'Unknown version {wanted}'}, HTTPStatus.NOT_FOUND)
                return
            index = ids.index(wanted)

        vid, when, path, loader = versions[index]
        graph = cached_graph(path, loader)
        if index > 0:
            _, prev_time, prev_path, prev_loader = versions[index - 1]
            graph['changeCount'] = diff_graphs(cached_graph(prev_path, prev_loader), graph)
            graph['previousTime'] = prev_time
        # Past versions only count alerts that had happened by then
        alerts = read_alerts(self.log_file)
        if index < len(versions) - 1:
            cutoff = datetime.fromtimestamp(when, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            alerts = [a for a in alerts if a.get('eventTime', '') <= cutoff]
        graph = attach_alerts(graph, alerts, account_id)
        graph.update({
            'version': vid,
            'updated': when,
            'live': index == len(versions) - 1,
            'regions': sorted({n['region'] for n in graph['nodes']
                               if n['region'] not in ('global', '') and not n['external']}),
        })
        self.send_json(graph)

    def api_alerts(self, query):
        alerts = read_alerts(self.log_file)
        alerts.sort(key=lambda a: a.get('eventTime', ''), reverse=True)
        self.send_json({'alerts': alerts, 'total': len(alerts)})


DEFAULT_PORT = 54100


def create_server(host, port, state_dir, log_file):
    """Bind the GUI server. Raises OSError if the port is unavailable."""
    Handler.state_dir = state_dir
    Handler.log_file = log_file
    return ThreadingHTTPServer((host, port), Handler)


def start_in_background(host, port, state_dir, log_file):
    """Serve the GUI from a daemon thread (used by aws-security-guard.py --web)."""
    server = create_server(host, port, state_dir, log_file)
    threading.Thread(target=server.serve_forever, name='web-gui', daemon=True).start()
    return server


def main():
    parser = argparse.ArgumentParser(description='Web GUI for AWS Security Guard')
    parser.add_argument('--host', default='0.0.0.0', help='Interface to bind (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f'Port to listen on (default: {DEFAULT_PORT})')
    parser.add_argument('--config', help='Monitor config file; its log_file/state_directory are used as defaults')
    parser.add_argument('--state-dir', help='State directory written by the monitor (default: state)')
    parser.add_argument('--log-file', help='Log file written by the monitor (default: security-watch.log)')
    args = parser.parse_args()

    monitoring = {}
    if args.config:
        with open(args.config) as f:
            monitoring = json.load(f).get('monitoring', {})

    server = create_server(args.host, args.port,
                           args.state_dir or monitoring.get('state_directory', 'state'),
                           args.log_file or monitoring.get('log_file', 'security-watch.log'))
    print(f'AWS Security Guard GUI on http://{args.host}:{args.port}')
    print(f'  state dir: {os.path.abspath(Handler.state_dir)}')
    print(f'  log file:  {os.path.abspath(Handler.log_file)}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
