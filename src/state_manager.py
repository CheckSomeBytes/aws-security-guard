"""
State Management Module

Handles persistent storage and retrieval of AWS resource configurations
to enable change detection between monitoring cycles.
"""

import gzip
import json
import tempfile
import shutil
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pathlib import Path

HISTORY_DIRNAME = 'history'


def ensure_state_directory(state_directory: str) -> Path:
    """
    Ensure state directory exists

    Args:
        state_directory: Directory to store state files

    Returns:
        Path object for state directory
    """
    path = Path(state_directory)
    path.mkdir(exist_ok=True)
    return path


def get_state_file_path(state_directory: str, account_id: str) -> Path:
    """
    Get path to state file for a specific account

    Args:
        state_directory: Directory containing state files
        account_id: AWS account ID

    Returns:
        Path to state file
    """
    return Path(state_directory) / f"{account_id}.json"


def load_state(state_directory: str, account_id: str) -> Optional[Dict[str, Any]]:
    """
    Load previous state for an account

    Args:
        state_directory: Directory containing state files
        account_id: AWS account ID

    Returns:
        Dictionary containing previous state, or None if no state exists
    """
    state_file = get_state_file_path(state_directory, account_id)

    if not state_file.exists():
        return None

    try:
        with open(state_file, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Failed to load state for account {account_id}: {str(e)}")
        return None


def save_state(state_directory: str, account_id: str, state: Dict[str, Any]) -> None:
    """
    Save current state for an account atomically

    Args:
        state_directory: Directory to store state files
        account_id: AWS account ID
        state: Dictionary containing current state
    """
    ensure_state_directory(state_directory)
    state_file = get_state_file_path(state_directory, account_id)
    tmp_path = None

    try:
        # Write to temp file first
        with tempfile.NamedTemporaryFile(
            mode='w',
            dir=state_directory,
            delete=False,
            suffix='.tmp',
            prefix=f'{account_id}_'
        ) as tmp_file:
            json.dump(state, tmp_file, indent=2, default=str)
            tmp_path = tmp_file.name

        # Atomic rename
        shutil.move(tmp_path, state_file)

    except Exception as e:
        print(f"Error: Failed to save state for account {account_id}: {str(e)}")
        # Clean up temp file if it exists
        if tmp_path:
            try:
                Path(tmp_path).unlink()
            except:
                pass
        return

    save_history_snapshot(state_directory, account_id, state)


def get_history_directory(state_directory: str, account_id: str) -> Path:
    """Directory holding timestamped snapshots of an account's state"""
    return Path(state_directory) / HISTORY_DIRNAME / account_id


def list_history_snapshots(state_directory: str, account_id: str) -> List[Path]:
    """Snapshot files for an account, oldest first"""
    history_dir = get_history_directory(state_directory, account_id)
    if not history_dir.is_dir():
        return []
    return sorted(history_dir.glob('*.json.gz'))


def load_history_snapshot(path: Path) -> Dict[str, Any]:
    with gzip.open(path, 'rt') as f:
        return json.load(f)


def save_history_snapshot(state_directory: str, account_id: str, state: Dict[str, Any]) -> None:
    """
    Keep a timestamped, gzipped copy of the state so earlier versions of the
    pipeline can be reviewed. Skipped when identical to the latest snapshot.
    History is best-effort: failures never affect monitoring.

    Args:
        state_directory: Directory to store state files
        account_id: AWS account ID
        state: Dictionary containing current state
    """
    try:
        serialized = json.dumps(state, sort_keys=True, default=str)
        snapshots = list_history_snapshots(state_directory, account_id)
        if snapshots:
            latest = json.dumps(load_history_snapshot(snapshots[-1]), sort_keys=True, default=str)
            if latest == serialized:
                return

        history_dir = get_history_directory(state_directory, account_id)
        history_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        snapshot_file = history_dir / f'{timestamp}.json.gz'
        tmp_file = history_dir / f'.{timestamp}.tmp'
        with gzip.open(tmp_file, 'wt') as f:
            f.write(serialized)
        shutil.move(str(tmp_file), snapshot_file)
    except Exception as e:
        print(f"Warning: Failed to save state history for account {account_id}: {str(e)}")


def get_service_state(state_directory: str, account_id: str, service: str, region: str) -> Optional[Dict]:
    """
    Get state for a specific service in a specific region

    Args:
        state_directory: Directory containing state files
        account_id: AWS account ID
        service: Service name (e.g., 'cloudtrail', 'guardduty')
        region: AWS region

    Returns:
        Dictionary containing service state, or None if not found
    """
    state = load_state(state_directory, account_id)
    if not state:
        return None

    service_state = state.get('regions', {}).get(region, {}).get(service)

    # Validate that service_state is a dict (not a list or other type)
    # This can happen if state was created by test code or an older version
    if service_state is not None and not isinstance(service_state, dict):
        print(f"Warning: Invalid state type for {service} in {region} (expected dict, got {type(service_state).__name__}). Ignoring previous state.")
        return None

    # Additional validation for nested structures
    # Check if nested values are lists when they should be dicts
    if service_state:
        if service == 'guardduty':
            # GuardDuty expects {'detectors': {}, 'suppression_rules': {}}
            if 'detectors' in service_state and not isinstance(service_state['detectors'], dict):
                print(f"Warning: Invalid guardduty.detectors type in {region} (expected dict, got {type(service_state['detectors']).__name__}). Ignoring previous state.")
                return None
            if 'suppression_rules' in service_state and not isinstance(service_state['suppression_rules'], dict):
                print(f"Warning: Invalid guardduty.suppression_rules type in {region} (expected dict, got {type(service_state['suppression_rules']).__name__}). Ignoring previous state.")
                return None
        else:
            # For cloudtrail, eventbridge, s3, sqs, sns, lambda, iam:
            # Check that all values are dicts (not lists)
            for key, value in service_state.items():
                if not isinstance(value, dict):
                    print(f"Warning: Invalid {service}.{key} type in {region} (expected dict, got {type(value).__name__}). Ignoring previous state.")
                    return None

    return service_state


def update_service_state(
    state_directory: str,
    account_id: str,
    service: str,
    region: str,
    service_state: Dict[str, Any]
) -> None:
    """
    Update state for a specific service in a specific region

    Args:
        state_directory: Directory containing state files
        account_id: AWS account ID
        service: Service name
        region: AWS region
        service_state: Current service configuration
    """
    state = load_state(state_directory, account_id) or {}

    # Initialize nested structure if needed
    if 'regions' not in state:
        state['regions'] = {}
    if region not in state['regions']:
        state['regions'][region] = {}

    # Update service state
    state['regions'][region][service] = service_state

    # Save updated state
    save_state(state_directory, account_id, state)


def is_first_run(state_directory: str, account_id: str) -> bool:
    """
    Check if this is the first run for an account (no previous state)

    Args:
        state_directory: Directory containing state files
        account_id: AWS account ID

    Returns:
        True if first run, False otherwise
    """
    return not get_state_file_path(state_directory, account_id).exists()
