"""
State Management Module

Handles persistent storage and retrieval of AWS resource configurations
to enable change detection between monitoring cycles.
"""

import json
import tempfile
import shutil
from typing import Dict, Any, Optional
from pathlib import Path


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

    return state.get('regions', {}).get(region, {}).get(service)


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
