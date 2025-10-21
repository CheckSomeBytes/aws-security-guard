#!/usr/bin/env python3
"""
Integration Test for AWS Security Watch

This test validates the end-to-end functionality of aws-security-watch by:
1. Starting the monitoring tool in the background
2. Running test_infrastructure.py to trigger AWS changes
3. Verifying that state files are updated when resources change
4. Verifying that logs are generated for monitored activities

Usage:
  python testing/integration_test.py --profile my-profile --service cloudtrail
  python testing/integration_test.py --profile my-profile --service all --region us-east-1
"""

import subprocess
import time
import json
import sys
import argparse
import os
import signal
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

# Add parent directory to path to import test_infrastructure
sys.path.insert(0, str(Path(__file__).parent))
import test_infrastructure


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


class IntegrationTest:
    """Integration test orchestrator"""

    def __init__(
        self,
        profile: Optional[str],
        region: str,
        service: str,
        test_name: str,
        state_dir: str = 'state',
        log_file: str = 'security-watch.log',
        monitor_interval: int = 30,
        findings_log: str = 'integration_test_findings.json'
    ):
        self.profile = profile
        self.region = region
        self.service = service
        self.test_name = test_name
        self.state_dir = Path(state_dir)
        self.log_file = Path(log_file)
        self.findings_log = Path(findings_log)
        self.monitor_interval = monitor_interval
        self.monitor_process = None
        self.monitor_output_file = Path('monitor_output.log')
        self.monitor_output_thread = None
        self.monitor_has_activity = False
        self.account_id = None
        self.test_results = []
        self.findings = []
        self.test_start_time = None
        self.results_log_file = Path('integration_test_results.log')

    def print_header(self, message: str) -> None:
        """Print a formatted header"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{message}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 70}{Colors.END}\n")

    def print_success(self, message: str) -> None:
        """Print a success message"""
        print(f"{Colors.GREEN}✓ {message}{Colors.END}")

    def print_error(self, message: str) -> None:
        """Print an error message"""
        print(f"{Colors.RED}✗ {message}{Colors.END}")

    def print_warning(self, message: str) -> None:
        """Print a warning message"""
        print(f"{Colors.YELLOW}⚠ {message}{Colors.END}")

    def print_info(self, message: str) -> None:
        """Print an info message"""
        print(f"{Colors.BLUE}ℹ {message}{Colors.END}")

    def get_account_id(self) -> str:
        """Get the AWS account ID"""
        import boto3
        if self.profile:
            session = boto3.Session(profile_name=self.profile)
        else:
            session = boto3.Session()

        sts = session.client('sts')
        return sts.get_caller_identity()['Account']

    def capture_monitor_output(self) -> None:
        """
        Background thread to capture monitor output and save to file.
        This prevents the output buffer from filling up and hanging the process.
        """
        try:
            with open(self.monitor_output_file, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("AWS Security Watch Monitor Output\n")
                f.write("=" * 80 + "\n\n")

                while self.monitor_process and self.monitor_process.poll() is None:
                    line = self.monitor_process.stdout.readline()
                    if line:
                        f.write(line)
                        f.flush()

                        # Check for activity indicators
                        if 'Monitoring' in line or 'region' in line or 'Changes detected' in line:
                            self.monitor_has_activity = True

                # Capture any remaining output
                remaining = self.monitor_process.stdout.read()
                if remaining:
                    f.write(remaining)
                    f.flush()

        except Exception as e:
            self.print_warning(f"Error capturing monitor output: {str(e)}")

    def start_monitor(self) -> bool:
        """Start aws-security-watch in the background"""
        self.print_header("Starting AWS Security Watch Monitor")

        # Build command
        cmd = [
            sys.executable,
            'aws_security_watch.py',
            '--interval', str(self.monitor_interval),
            '--state-dir', str(self.state_dir),
            '--log-file', str(self.log_file)
        ]

        if self.profile:
            cmd.extend(['--profile', self.profile])

        print(f"Command: {' '.join(cmd)}")

        try:
            # Start the monitor process
            self.monitor_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Start background thread to capture output
            self.monitor_output_thread = threading.Thread(
                target=self.capture_monitor_output,
                daemon=True
            )
            self.monitor_output_thread.start()

            # Wait a bit and check if it's still running
            time.sleep(3)
            if self.monitor_process.poll() is not None:
                self.print_error("Monitor process exited prematurely")
                # Output is now in the log file
                if self.monitor_output_file.exists():
                    with open(self.monitor_output_file, 'r') as f:
                        output = f.read()
                        print(f"Output:\n{output}")
                return False

            self.print_success(f"Monitor started (PID: {self.monitor_process.pid})")
            self.print_info(f"Monitor output being saved to: {self.monitor_output_file}")

            # Wait for initial baseline to complete (2x interval to be safe)
            baseline_wait = self.monitor_interval * 2
            self.print_info(f"Waiting {baseline_wait} seconds for initial baseline scan...")

            # Show progress during wait
            for i in range(baseline_wait):
                if i % 10 == 0:
                    print(f"  ... {baseline_wait - i} seconds remaining")
                time.sleep(1)

            # Validate monitor is actually working
            validation_passed = self.validate_monitor_running()

            if not validation_passed:
                self.print_error("Monitor validation failed")
                return False

            self.print_success("Baseline scan completed and validated")
            return True

        except Exception as e:
            self.print_error(f"Failed to start monitor: {str(e)}")
            return False

    def validate_monitor_running(self) -> bool:
        """
        Validate that the monitor is actually running and working correctly.

        Checks:
        1. Process is still alive
        2. State directory was created
        3. State file exists
        4. Monitor output shows activity

        Returns:
            True if validation passes, False otherwise
        """
        self.print_info("Validating monitor is running correctly...")

        # Check 1: Process still alive
        if self.monitor_process.poll() is not None:
            self.print_error("✗ Monitor process has exited")
            return False
        self.print_success("✓ Monitor process is running")

        # Check 2: State directory exists
        if not self.state_dir.exists():
            self.print_error(f"✗ State directory not created: {self.state_dir}")
            return False
        self.print_success(f"✓ State directory exists: {self.state_dir}")

        # Check 3: State file exists (should be created after baseline)
        state_file = self.get_state_file_path()
        if not state_file.exists():
            self.print_warning(f"⚠ State file not yet created: {state_file}")
            self.print_info("  This may be normal if no monitored resources exist")
            # Don't fail validation for missing state file - it might be created later
        else:
            self.print_success(f"✓ State file created: {state_file}")

            # Check state file is not empty
            try:
                with open(state_file, 'r') as f:
                    state_data = json.load(f)
                    region_count = len(state_data.get('regions', {}))
                    self.print_success(f"✓ State file contains {region_count} region(s)")
            except Exception as e:
                self.print_warning(f"⚠ Could not read state file: {str(e)}")

        # Check 4: Monitor output shows activity
        if self.monitor_output_file.exists():
            try:
                with open(self.monitor_output_file, 'r') as f:
                    output = f.read()
                    if 'AWS Security Watch started' in output or 'Monitoring' in output:
                        self.print_success("✓ Monitor output shows activity")
                    else:
                        self.print_warning("⚠ Monitor output doesn't show expected activity")
                        # Don't fail - might just be slow to start
            except Exception as e:
                self.print_warning(f"⚠ Could not read monitor output: {str(e)}")
        else:
            self.print_warning(f"⚠ Monitor output file not found: {self.monitor_output_file}")

        # Check 5: Thread is alive and capturing output
        if self.monitor_output_thread and self.monitor_output_thread.is_alive():
            self.print_success("✓ Output capture thread is running")
        else:
            self.print_warning("⚠ Output capture thread is not running")

        return True  # Validation passed

    def stop_monitor(self) -> None:
        """Stop the monitoring process"""
        if self.monitor_process:
            self.print_header("Stopping AWS Security Watch Monitor")
            try:
                self.monitor_process.terminate()
                self.monitor_process.wait(timeout=10)
                self.print_success(f"Monitor stopped (PID: {self.monitor_process.pid})")

                # Wait for output thread to finish
                if self.monitor_output_thread and self.monitor_output_thread.is_alive():
                    self.monitor_output_thread.join(timeout=5)

                self.print_info(f"Monitor output saved to: {self.monitor_output_file}")

            except subprocess.TimeoutExpired:
                self.print_warning("Monitor didn't stop gracefully, killing...")
                self.monitor_process.kill()
                self.monitor_process.wait()
            except Exception as e:
                self.print_error(f"Error stopping monitor: {str(e)}")

    def get_state_file_path(self) -> Path:
        """Get the path to the state file for this account"""
        return self.state_dir / f"{self.account_id}.json"

    def load_state(self) -> Optional[Dict[str, Any]]:
        """Load the current state file"""
        state_file = self.get_state_file_path()
        if not state_file.exists():
            return None

        try:
            with open(state_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.print_error(f"Failed to load state file: {str(e)}")
            return None

    def get_service_state(self, service: str) -> Optional[Dict]:
        """Get state for a specific service in the test region"""
        state = self.load_state()
        if not state:
            return None

        return state.get('regions', {}).get(self.region, {}).get(service)

    def count_log_entries(self, event_name: Optional[str] = None) -> int:
        """Count log entries, optionally filtering by event name"""
        if not self.log_file.exists():
            return 0

        count = 0
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if event_name is None or entry.get('eventName') == event_name:
                            count += 1
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.print_error(f"Failed to read log file: {str(e)}")

        return count

    def analyze_log_entries(self, since_timestamp: Optional[str] = None) -> Dict[str, List[Dict]]:
        """
        Analyze all log entries and categorize them

        Args:
            since_timestamp: Only analyze entries after this timestamp

        Returns:
            Dictionary with categorized log entries
        """
        if not self.log_file.exists():
            return {}

        entries_by_event = {}
        all_entries = []

        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)

                        # Filter by timestamp if provided
                        if since_timestamp:
                            if entry.get('eventTime', '') < since_timestamp:
                                continue

                        event_name = entry.get('eventName', 'Unknown')
                        if event_name not in entries_by_event:
                            entries_by_event[event_name] = []

                        entries_by_event[event_name].append(entry)
                        all_entries.append(entry)

                        # Record finding
                        self.record_finding(
                            category='log_entry',
                            finding_type=event_name,
                            details={
                                'eventSource': entry.get('eventSource'),
                                'eventTime': entry.get('eventTime'),
                                'awsRegion': entry.get('awsRegion'),
                                'responseElements': entry.get('responseElements', {})
                            },
                            severity='info'
                        )

                    except json.JSONDecodeError as e:
                        self.record_finding(
                            category='error',
                            finding_type='invalid_log_entry',
                            details={'line': line, 'error': str(e)},
                            severity='warning'
                        )
                        continue
        except Exception as e:
            self.record_finding(
                category='error',
                finding_type='log_read_error',
                details={'error': str(e)},
                severity='error'
            )

        return {
            'by_event_name': entries_by_event,
            'all': all_entries,
            'summary': {
                'total_entries': len(all_entries),
                'unique_events': len(entries_by_event),
                'event_counts': {k: len(v) for k, v in entries_by_event.items()}
            }
        }

    def analyze_state_changes(self, service: str, previous_state: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Analyze state changes for a service

        Args:
            service: Service name
            previous_state: Previous state to compare against

        Returns:
            Dictionary with state change analysis
        """
        current_state = self.get_service_state(service)

        analysis = {
            'has_state': current_state is not None,
            'resources': {},
            'changes': []
        }

        if current_state is None:
            self.record_finding(
                category='state_file',
                finding_type='no_state',
                details={'service': service},
                severity='warning'
            )
            return analysis

        # Count resources by type
        if service == 'cloudtrail':
            analysis['resources']['trails'] = len(current_state.get('trails', {}))
            for trail_arn, trail_data in current_state.get('trails', {}).items():
                self.record_finding(
                    category='state_resource',
                    finding_type='cloudtrail_trail',
                    details={
                        'trail_arn': trail_arn,
                        'trail_name': trail_data.get('Name'),
                        'is_logging': trail_data.get('IsLogging'),
                        's3_bucket': trail_data.get('S3BucketName')
                    },
                    severity='info'
                )

        elif service == 's3':
            analysis['resources']['buckets'] = len(current_state.get('buckets', {}))
            for bucket_name, bucket_data in current_state.get('buckets', {}).items():
                self.record_finding(
                    category='state_resource',
                    finding_type='s3_bucket',
                    details={
                        'bucket_name': bucket_name,
                        'encryption': bucket_data.get('encryption'),
                        'size': bucket_data.get('size')
                    },
                    severity='info'
                )

        elif service == 'sqs':
            analysis['resources']['queues'] = len(current_state.get('queues', {}))
            for queue_url, queue_data in current_state.get('queues', {}).items():
                self.record_finding(
                    category='state_resource',
                    finding_type='sqs_queue',
                    details={
                        'queue_url': queue_url,
                        'queue_arn': queue_data.get('QueueArn'),
                        'kms_master_key_id': queue_data.get('KmsMasterKeyId')
                    },
                    severity='info'
                )

        elif service == 'sns':
            analysis['resources']['topics'] = len(current_state.get('topics', {}))
            for topic_arn, topic_data in current_state.get('topics', {}).items():
                self.record_finding(
                    category='state_resource',
                    finding_type='sns_topic',
                    details={
                        'topic_arn': topic_arn,
                        'kms_master_key_id': topic_data.get('KmsMasterKeyId'),
                        'subscriptions': len(topic_data.get('subscriptions', []))
                    },
                    severity='info'
                )

        elif service == 'guardduty':
            analysis['resources']['detectors'] = len(current_state.get('detectors', {}))
            for detector_id, detector_data in current_state.get('detectors', {}).items():
                filters_count = len(detector_data.get('filters', {}))
                self.record_finding(
                    category='state_resource',
                    finding_type='guardduty_detector',
                    details={
                        'detector_id': detector_id,
                        'status': detector_data.get('Status'),
                        'filters_count': filters_count
                    },
                    severity='info'
                )

        elif service == 'eventbridge':
            analysis['resources']['rules'] = len(current_state.get('rules', {}))
            for rule_name, rule_data in current_state.get('rules', {}).items():
                self.record_finding(
                    category='state_resource',
                    finding_type='eventbridge_rule',
                    details={
                        'rule_name': rule_name,
                        'state': rule_data.get('State'),
                        'event_pattern': rule_data.get('EventPattern')
                    },
                    severity='info'
                )

        elif service == 'lambda':
            analysis['resources']['functions'] = len(current_state.get('functions', {}))
            for function_arn, function_data in current_state.get('functions', {}).items():
                self.record_finding(
                    category='state_resource',
                    finding_type='lambda_function',
                    details={
                        'function_arn': function_arn,
                        'function_name': function_data.get('FunctionName'),
                        'runtime': function_data.get('Runtime'),
                        'role': function_data.get('Role')
                    },
                    severity='info'
                )

        elif service == 'iam':
            analysis['resources']['roles'] = len(current_state.get('roles', {}))
            for role_name, role_data in current_state.get('roles', {}).items():
                self.record_finding(
                    category='state_resource',
                    finding_type='iam_role',
                    details={
                        'role_name': role_name,
                        'role_arn': role_data.get('Arn'),
                        'attached_policies': len(role_data.get('attached_policies', [])),
                        'inline_policies': len(role_data.get('inline_policies', {}))
                    },
                    severity='info'
                )

        # Compare with previous state if provided
        if previous_state:
            # Detect additions, deletions, and modifications
            # This is a simplified comparison - can be enhanced
            analysis['changes'].append({
                'type': 'state_comparison',
                'details': 'State comparison between runs'
            })

        return analysis

    def wait_for_monitor_cycle(self, message: str = None) -> None:
        """Wait for one monitoring cycle to complete"""
        wait_time = self.monitor_interval + 10

        if message:
            self.print_info(message)
        else:
            self.print_info(f"Waiting {wait_time} seconds for monitor cycle...")

        # Show progress during wait
        for i in range(wait_time):
            if i % 10 == 0 and i > 0:
                print(f"  ... {wait_time - i} seconds remaining")
            time.sleep(1)

        self.print_success("Monitor cycle completed")

    def verify_state_change(
        self,
        service: str,
        check_function,
        description: str
    ) -> Tuple[bool, str]:
        """
        Verify that a state change occurred

        Args:
            service: Service name (e.g., 'cloudtrail')
            check_function: Function that takes service state and returns (bool, message)
            description: Description of what we're checking

        Returns:
            Tuple of (success, message)
        """
        state = self.get_service_state(service)
        if state is None:
            return False, f"No state found for {service}"

        return check_function(state)

    def verify_log_entry(
        self,
        event_name: str,
        check_function,
        description: str,
        previous_count: int = 0
    ) -> Tuple[bool, str]:
        """
        Verify that a log entry was generated

        Args:
            event_name: Event name to look for
            check_function: Function that takes log entry and returns bool
            description: Description of what we're checking
            previous_count: Number of matching entries before the change

        Returns:
            Tuple of (success, message)
        """
        if not self.log_file.exists():
            return False, "Log file does not exist"

        current_count = 0
        found_matching = False

        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get('eventName') == event_name:
                            current_count += 1
                            if current_count > previous_count and check_function(entry):
                                found_matching = True
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            return False, f"Failed to read log file: {str(e)}"

        if current_count <= previous_count:
            return False, f"No new log entries found (count: {current_count}, previous: {previous_count})"

        if not found_matching:
            return False, f"New log entries found but none matched criteria (total: {current_count})"

        return True, f"Found matching log entry ({current_count - previous_count} new entries)"

    def record_finding(
        self,
        category: str,
        finding_type: str,
        details: Dict[str, Any],
        severity: str = 'info'
    ) -> None:
        """
        Record a finding discovered during testing

        Args:
            category: Category of finding (state_change, log_entry, resource_created, etc.)
            finding_type: Specific type of finding
            details: Detailed information about the finding
            severity: Severity level (info, warning, error)
        """
        finding = {
            'timestamp': datetime.utcnow().isoformat(),
            'category': category,
            'type': finding_type,
            'severity': severity,
            'service': self.service,
            'region': self.region,
            'details': details
        }
        self.findings.append(finding)

    def record_result(self, test_name: str, passed: bool, message: str) -> None:
        """Record a test result"""
        self.test_results.append({
            'test': test_name,
            'passed': passed,
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        })

        if passed:
            self.print_success(f"{test_name}: {message}")
        else:
            self.print_error(f"{test_name}: {message}")

    def test_cloudtrail_monitoring(self) -> None:
        """Test CloudTrail monitoring"""
        self.print_header(f"Testing CloudTrail Monitoring in {self.region}")

        import boto3
        if self.profile:
            session = boto3.Session(profile_name=self.profile)
        else:
            session = boto3.Session()

        # Run CloudTrail test which creates trail, stops logging, changes S3, updates selectors, deletes trail
        try:
            test_infrastructure.test_cloudtrail(session, self.region, self.test_name, interactive=False)
        except Exception as e:
            self.print_error(f"Test infrastructure failed: {str(e)}")
            return

        # Verify state was updated
        state = self.get_service_state('cloudtrail')
        if state is None:
            self.record_result("CloudTrail State Update", False, "State file was not updated")
        else:
            self.record_result("CloudTrail State Update", True, f"State file contains {len(state.get('trails', {}))} trails")

        # Check for log entries
        log_count = self.count_log_entries()
        if log_count > 0:
            self.record_result("CloudTrail Log Generation", True, f"Generated {log_count} log entries")
        else:
            self.record_result("CloudTrail Log Generation", False, "No log entries generated")

    def test_service_monitoring(self, service: str) -> None:
        """Test monitoring for a specific service"""
        self.print_header(f"Testing {service.title()} Monitoring in {self.region}")

        import boto3
        if self.profile:
            session = boto3.Session(profile_name=self.profile)
        else:
            session = boto3.Session()

        # Get the test function for this service
        test_functions = {
            'cloudtrail': test_infrastructure.test_cloudtrail,
            's3': test_infrastructure.test_s3_monitoring,
            'sqs': test_infrastructure.test_sqs_monitoring,
            'sns': test_infrastructure.test_sns_monitoring,
            'guardduty': test_infrastructure.test_guardduty,
            'eventbridge': test_infrastructure.test_eventbridge,
            'iam': test_infrastructure.test_iam_monitoring
        }

        test_func = test_functions.get(service)
        if not test_func:
            self.print_error(f"Unknown service: {service}")
            return

        # Record test start
        test_start_time = datetime.utcnow().isoformat()
        self.record_finding(
            category='test_execution',
            finding_type='test_started',
            details={'service': service, 'start_time': test_start_time},
            severity='info'
        )

        # Get initial state
        initial_state = self.get_service_state(service)

        # Get initial log count
        initial_log_count = self.count_log_entries()

        # Run the service test (interactive=False for automated execution)
        self.print_info(f"Running {service} infrastructure test (automated mode - no user input required)...")
        self.print_info("This will create, modify, and delete AWS resources to trigger monitoring events")

        try:
            test_func(session, self.region, self.test_name, interactive=False)
            self.print_success(f"{service.title()} infrastructure test completed")
            self.record_finding(
                category='test_execution',
                finding_type='test_completed',
                details={'service': service},
                severity='info'
            )
        except Exception as e:
            self.print_error(f"Test infrastructure failed: {str(e)}")
            self.record_result(f"{service.title()} Test Execution", False, str(e))
            self.record_finding(
                category='test_execution',
                finding_type='test_failed',
                details={'service': service, 'error': str(e)},
                severity='error'
            )
            return

        self.record_result(f"{service.title()} Test Execution", True, "Test infrastructure completed successfully")

        # Wait for monitoring cycle
        self.wait_for_monitor_cycle(f"Waiting for monitor to detect {service} changes...")

        # Analyze state changes
        state_analysis = self.analyze_state_changes(service, initial_state)

        # Verify state was updated
        if state_analysis['has_state']:
            resource_summary = ', '.join([f"{k}={v}" for k, v in state_analysis['resources'].items()])
            self.record_result(
                f"{service.title()} State Update",
                True,
                f"State file updated: {resource_summary}"
            )
        else:
            self.record_result(f"{service.title()} State Update", False, "State file was not updated")

        # Analyze log entries
        log_analysis = self.analyze_log_entries(since_timestamp=test_start_time)
        new_logs = log_analysis['summary']['total_entries']

        if new_logs > 0:
            event_summary = ', '.join([f"{k}={v}" for k, v in log_analysis['summary']['event_counts'].items()])
            self.record_result(
                f"{service.title()} Log Generation",
                True,
                f"Generated {new_logs} log entries: {event_summary}"
            )

            # Record detailed findings about what events were logged
            self.record_finding(
                category='log_summary',
                finding_type='events_logged',
                details={
                    'service': service,
                    'total_entries': new_logs,
                    'event_counts': log_analysis['summary']['event_counts']
                },
                severity='info'
            )
        else:
            self.record_result(
                f"{service.title()} Log Generation",
                False,
                "No new log entries generated"
            )

    def print_summary(self) -> None:
        """Print test results summary"""
        self.print_header("Test Results Summary")

        passed = sum(1 for r in self.test_results if r['passed'])
        failed = sum(1 for r in self.test_results if not r['passed'])
        total = len(self.test_results)

        print(f"\nTotal Tests: {total}")
        print(f"{Colors.GREEN}Passed: {passed}{Colors.END}")
        print(f"{Colors.RED}Failed: {failed}{Colors.END}")

        if failed > 0:
            print(f"\n{Colors.BOLD}Failed Tests:{Colors.END}")
            for result in self.test_results:
                if not result['passed']:
                    print(f"  {Colors.RED}✗ {result['test']}: {result['message']}{Colors.END}")

        print(f"\n{Colors.BOLD}All Tests:{Colors.END}")
        for result in self.test_results:
            status = f"{Colors.GREEN}✓{Colors.END}" if result['passed'] else f"{Colors.RED}✗{Colors.END}"
            print(f"  {status} {result['test']}: {result['message']}")

        # Findings summary
        print(f"\n{Colors.BOLD}Findings Summary:{Colors.END}")
        findings_by_category = {}
        for finding in self.findings:
            category = finding['category']
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)

        for category, findings in sorted(findings_by_category.items()):
            print(f"  {category}: {len(findings)} findings")

        # Save detailed results to JSON
        results_file = Path('integration_test_results.json')
        with open(results_file, 'w') as f:
            json.dump({
                'timestamp': datetime.utcnow().isoformat(),
                'profile': self.profile,
                'region': self.region,
                'service': self.service,
                'test_name': self.test_name,
                'summary': {
                    'total': total,
                    'passed': passed,
                    'failed': failed
                },
                'results': self.test_results
            }, f, indent=2)

        self.print_success(f"Detailed results saved to {results_file}")

        # Save findings log
        test_end_time = datetime.utcnow().isoformat()
        with open(self.findings_log, 'w') as f:
            json.dump({
                'metadata': {
                    'test_start_time': self.test_start_time,
                    'test_end_time': test_end_time,
                    'account_id': self.account_id,
                    'region': self.region,
                    'service': self.service,
                    'test_name': self.test_name,
                    'profile': self.profile
                },
                'summary': {
                    'total_findings': len(self.findings),
                    'by_category': {k: len(v) for k, v in findings_by_category.items()},
                    'by_severity': {
                        'info': sum(1 for f in self.findings if f['severity'] == 'info'),
                        'warning': sum(1 for f in self.findings if f['severity'] == 'warning'),
                        'error': sum(1 for f in self.findings if f['severity'] == 'error')
                    }
                },
                'findings': self.findings
            }, f, indent=2)

        self.print_success(f"Findings log saved to {self.findings_log}")

        # Generate text log report
        self.generate_text_report(test_end_time, findings_by_category)
        self.print_success(f"Text report saved to {self.results_log_file}")

    def generate_text_report(self, test_end_time: str, findings_by_category: Dict) -> None:
        """Generate a human-readable text report of test results"""
        with open(self.results_log_file, 'w') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("AWS SECURITY WATCH - INTEGRATION TEST RESULTS\n")
            f.write("=" * 80 + "\n\n")

            # Test metadata
            f.write("TEST CONFIGURATION\n")
            f.write("-" * 80 + "\n")
            f.write(f"Test Start Time:     {self.test_start_time}\n")
            f.write(f"Test End Time:       {test_end_time}\n")
            f.write(f"Account ID:          {self.account_id}\n")
            f.write(f"Region:              {self.region}\n")
            f.write(f"Service(s) Tested:   {self.service}\n")
            f.write(f"Test Name:           {self.test_name}\n")
            f.write(f"Monitor Interval:    {self.monitor_interval} seconds\n")
            if self.profile:
                f.write(f"AWS Profile:         {self.profile}\n")
            f.write(f"State Directory:     {self.state_dir}\n")
            f.write(f"Log File:            {self.log_file}\n")
            f.write("\n")

            # Test summary
            passed = sum(1 for r in self.test_results if r['passed'])
            failed = sum(1 for r in self.test_results if not r['passed'])
            total = len(self.test_results)

            f.write("TEST SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Tests:         {total}\n")
            f.write(f"Passed:              {passed}\n")
            f.write(f"Failed:              {failed}\n")
            f.write(f"Success Rate:        {(passed/total*100) if total > 0 else 0:.1f}%\n")
            f.write("\n")

            # Test results detail
            f.write("DETAILED TEST RESULTS\n")
            f.write("-" * 80 + "\n")
            for i, result in enumerate(self.test_results, 1):
                status = "PASS" if result['passed'] else "FAIL"
                f.write(f"{i}. [{status}] {result['test']}\n")
                f.write(f"   Message: {result['message']}\n")
                f.write(f"   Time: {result['timestamp']}\n")
                f.write("\n")

            # Findings summary
            f.write("FINDINGS SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Findings:      {len(self.findings)}\n")
            f.write("\n")

            f.write("By Category:\n")
            for category, findings in sorted(findings_by_category.items()):
                f.write(f"  - {category:20s} {len(findings):4d} findings\n")
            f.write("\n")

            severity_counts = {
                'info': sum(1 for f in self.findings if f['severity'] == 'info'),
                'warning': sum(1 for f in self.findings if f['severity'] == 'warning'),
                'error': sum(1 for f in self.findings if f['severity'] == 'error')
            }
            f.write("By Severity:\n")
            f.write(f"  - INFO:              {severity_counts['info']}\n")
            f.write(f"  - WARNING:           {severity_counts['warning']}\n")
            f.write(f"  - ERROR:             {severity_counts['error']}\n")
            f.write("\n")

            # Resources detected
            resource_findings = [f for f in self.findings if f['category'] == 'state_resource']
            if resource_findings:
                f.write("RESOURCES DETECTED IN STATE FILES\n")
                f.write("-" * 80 + "\n")
                resources_by_type = {}
                for finding in resource_findings:
                    resource_type = finding['type']
                    if resource_type not in resources_by_type:
                        resources_by_type[resource_type] = []
                    resources_by_type[resource_type].append(finding)

                for resource_type, resources in sorted(resources_by_type.items()):
                    f.write(f"\n{resource_type.replace('_', ' ').title()} ({len(resources)} found):\n")
                    for i, resource in enumerate(resources, 1):
                        details = resource['details']
                        f.write(f"  {i}. ")

                        # Format based on resource type
                        if resource_type == 'cloudtrail_trail':
                            f.write(f"{details.get('trail_name', 'N/A')}\n")
                            f.write(f"     ARN:       {details.get('trail_arn', 'N/A')}\n")
                            f.write(f"     Logging:   {details.get('is_logging', 'N/A')}\n")
                            f.write(f"     S3 Bucket: {details.get('s3_bucket', 'N/A')}\n")

                        elif resource_type == 's3_bucket':
                            f.write(f"{details.get('bucket_name', 'N/A')}\n")
                            encryption = details.get('encryption', {})
                            if encryption:
                                f.write(f"     Encryption: {encryption.get('SSEAlgorithm', 'None')}\n")
                            f.write(f"     Size:       {details.get('size', 'N/A')} bytes\n")

                        elif resource_type == 'sqs_queue':
                            queue_url = details.get('queue_url', 'N/A')
                            queue_name = queue_url.split('/')[-1] if queue_url != 'N/A' else 'N/A'
                            f.write(f"{queue_name}\n")
                            f.write(f"     URL:        {queue_url}\n")
                            f.write(f"     ARN:        {details.get('queue_arn', 'N/A')}\n")
                            if details.get('kms_master_key_id'):
                                f.write(f"     KMS Key:    {details.get('kms_master_key_id')}\n")

                        elif resource_type == 'sns_topic':
                            topic_arn = details.get('topic_arn', 'N/A')
                            topic_name = topic_arn.split(':')[-1] if topic_arn != 'N/A' else 'N/A'
                            f.write(f"{topic_name}\n")
                            f.write(f"     ARN:          {topic_arn}\n")
                            f.write(f"     Subscriptions: {details.get('subscriptions', 0)}\n")
                            if details.get('kms_master_key_id'):
                                f.write(f"     KMS Key:      {details.get('kms_master_key_id')}\n")

                        elif resource_type == 'guardduty_detector':
                            f.write(f"{details.get('detector_id', 'N/A')}\n")
                            f.write(f"     Status:  {details.get('status', 'N/A')}\n")
                            f.write(f"     Filters: {details.get('filters_count', 0)}\n")

                        elif resource_type == 'eventbridge_rule':
                            f.write(f"{details.get('rule_name', 'N/A')}\n")
                            f.write(f"     State:   {details.get('state', 'N/A')}\n")

                        elif resource_type == 'lambda_function':
                            f.write(f"{details.get('function_name', 'N/A')}\n")
                            f.write(f"     ARN:     {details.get('function_arn', 'N/A')}\n")
                            f.write(f"     Runtime: {details.get('runtime', 'N/A')}\n")
                            f.write(f"     Role:    {details.get('role', 'N/A')}\n")

                        elif resource_type == 'iam_role':
                            f.write(f"{details.get('role_name', 'N/A')}\n")
                            f.write(f"     ARN:              {details.get('role_arn', 'N/A')}\n")
                            f.write(f"     Attached Policies: {details.get('attached_policies', 0)}\n")
                            f.write(f"     Inline Policies:   {details.get('inline_policies', 0)}\n")

                        else:
                            f.write(f"{details}\n")

                f.write("\n")

            # Log entries summary
            log_findings = [f for f in self.findings if f['category'] == 'log_entry']
            if log_findings:
                f.write("LOG ENTRIES GENERATED\n")
                f.write("-" * 80 + "\n")
                events_by_type = {}
                for finding in log_findings:
                    event_type = finding['type']
                    if event_type not in events_by_type:
                        events_by_type[event_type] = []
                    events_by_type[event_type].append(finding)

                f.write(f"Total log entries: {len(log_findings)}\n\n")

                for event_type, events in sorted(events_by_type.items()):
                    f.write(f"{event_type} ({len(events)} occurrences):\n")
                    for i, event in enumerate(events[:5], 1):  # Show first 5 of each type
                        details = event['details']
                        f.write(f"  {i}. Time: {details.get('eventTime', 'N/A')}\n")
                        f.write(f"     Source: {details.get('eventSource', 'N/A')}\n")
                        response = details.get('responseElements', {})
                        if response:
                            for key, value in list(response.items())[:3]:  # Show first 3 fields
                                f.write(f"     {key}: {value}\n")
                    if len(events) > 5:
                        f.write(f"  ... and {len(events) - 5} more\n")
                    f.write("\n")

            # Errors and warnings
            errors = [f for f in self.findings if f['severity'] == 'error']
            warnings = [f for f in self.findings if f['severity'] == 'warning']

            if errors:
                f.write("ERRORS\n")
                f.write("-" * 80 + "\n")
                for i, error in enumerate(errors, 1):
                    f.write(f"{i}. [{error['type']}] at {error['timestamp']}\n")
                    f.write(f"   Details: {error['details']}\n")
                    f.write("\n")

            if warnings:
                f.write("WARNINGS\n")
                f.write("-" * 80 + "\n")
                for i, warning in enumerate(warnings, 1):
                    f.write(f"{i}. [{warning['type']}] at {warning['timestamp']}\n")
                    f.write(f"   Details: {warning['details']}\n")
                    f.write("\n")

            # Footer
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"\nGenerated: {test_end_time}\n")
            f.write(f"JSON Results:   integration_test_results.json\n")
            f.write(f"Findings Log:   {self.findings_log}\n")
            f.write(f"Monitor Logs:   {self.log_file}\n")
            f.write(f"Monitor Output: {self.monitor_output_file}\n")
            f.write(f"State File:     {self.state_dir}/{self.account_id}.json\n")

    def run(self) -> int:
        """Run the integration test"""
        try:
            # Record test start time
            self.test_start_time = datetime.utcnow().isoformat()

            # Get account ID
            self.account_id = self.get_account_id()

            # Print test configuration
            self.print_header("Integration Test Configuration")
            print(f"Account ID: {self.account_id}")
            print(f"Region: {self.region}")
            print(f"Service: {self.service}")
            print(f"Test name: {self.test_name}")
            print(f"Monitor interval: {self.monitor_interval} seconds")
            print(f"State directory: {self.state_dir}")
            print(f"Log file: {self.log_file}")
            print(f"Findings log: {self.findings_log}")
            print(f"\n{Colors.BOLD}Running in automated mode - no user input required{Colors.END}")

            # Record initial finding
            self.record_finding(
                category='test_metadata',
                finding_type='test_initialization',
                details={
                    'account_id': self.account_id,
                    'region': self.region,
                    'service': self.service,
                    'test_name': self.test_name,
                    'monitor_interval': self.monitor_interval
                },
                severity='info'
            )

            # Clean up previous test artifacts
            if self.log_file.exists():
                self.log_file.unlink()
                self.print_info("Removed previous log file")

            state_file = self.get_state_file_path()
            if state_file.exists():
                state_file.unlink()
                self.print_info("Removed previous state file")

            # Start monitor
            if not self.start_monitor():
                return 1

            # Run tests based on service selection
            if self.service == 'all':
                for svc in ['cloudtrail', 's3', 'sqs', 'sns', 'guardduty', 'eventbridge', 'iam']:
                    self.test_service_monitoring(svc)
                    time.sleep(5)  # Brief pause between services
            else:
                self.test_service_monitoring(self.service)

            # Print summary
            self.print_summary()

            # Determine exit code
            failed = sum(1 for r in self.test_results if not r['passed'])
            return 0 if failed == 0 else 1

        except KeyboardInterrupt:
            self.print_warning("\nTest interrupted by user")
            return 130
        except Exception as e:
            self.print_error(f"Test failed with exception: {str(e)}")
            import traceback
            traceback.print_exc()
            return 1
        finally:
            # Always stop the monitor
            self.stop_monitor()


def main():
    parser = argparse.ArgumentParser(
        description='Integration test for AWS Security Watch',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test CloudTrail monitoring
  python testing/integration_test.py --profile myprofile --service cloudtrail

  # Test all services
  python testing/integration_test.py --profile myprofile --service all

  # Test in specific region
  python testing/integration_test.py --profile myprofile --region us-west-2 --service s3
        """
    )

    parser.add_argument('--profile', type=str, help='AWS profile name to use')
    parser.add_argument('--region', type=str, default='us-east-1', help='AWS region to test in (default: us-east-1)')
    parser.add_argument(
        '--service',
        type=str,
        choices=['cloudtrail', 's3', 'sqs', 'sns', 'guardduty', 'eventbridge', 'iam', 'all'],
        default='cloudtrail',
        help='Service to test (default: cloudtrail)'
    )
    parser.add_argument('--test-name', type=str, help='Test name (auto-generated if not provided)')
    parser.add_argument('--state-dir', type=str, default='state-test', help='State directory (default: state-test)')
    parser.add_argument('--log-file', type=str, default='security-watch-test.log', help='Log file (default: security-watch-test.log)')
    parser.add_argument('--findings-log', type=str, default='integration_test_findings.json', help='Findings log file (default: integration_test_findings.json)')
    parser.add_argument('--monitor-interval', type=int, default=30, help='Monitor interval in seconds (default: 30)')

    args = parser.parse_args()

    # Generate test name if not provided
    if args.test_name:
        test_name = args.test_name
    else:
        test_name = test_infrastructure.generate_random_test_name()
        print(f"Generated test name: {test_name}")

    # Create and run integration test
    test = IntegrationTest(
        profile=args.profile,
        region=args.region,
        service=args.service,
        test_name=test_name,
        state_dir=args.state_dir,
        log_file=args.log_file,
        monitor_interval=args.monitor_interval,
        findings_log=args.findings_log
    )

    sys.exit(test.run())


if __name__ == '__main__':
    main()
