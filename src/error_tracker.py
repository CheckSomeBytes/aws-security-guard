"""
Error tracking for AWS Security Watch monitoring runs.

Collects API call failures and access denied errors during monitoring,
providing a centralized mechanism for error reporting.
"""

from typing import Dict, List, Any, Optional
from threading import Lock
from datetime import datetime


class ErrorTracker:
    """
    Thread-safe error tracker for monitoring runs.

    Collects API call failures across all services and regions,
    allowing for summary reporting at the end of a monitoring run.
    """

    def __init__(self):
        """Initialize the error tracker."""
        self._errors: List[Dict[str, Any]] = []
        self._lock = Lock()

    def add_error(
        self,
        service: str,
        region: str,
        error_code: str,
        error_message: str,
        api_call: Optional[str] = None
    ) -> None:
        """
        Add an API call failure to the tracker.

        Args:
            service: AWS service name (e.g., 'cloudtrail', 's3', 'iam')
            region: AWS region where the error occurred
            error_code: Error code from AWS (e.g., 'AccessDenied', 'UnauthorizedOperation')
            error_message: Detailed error message
            api_call: Optional API call that failed (e.g., 'get_trail', 'list_buckets')
        """
        with self._lock:
            error_entry = {
                'service': service,
                'region': region,
                'error_code': error_code,
                'error_message': error_message,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }

            if api_call:
                error_entry['api_call'] = api_call

            self._errors.append(error_entry)

    def get_errors(self) -> List[Dict[str, Any]]:
        """
        Get all collected errors.

        Returns:
            List of error dictionaries with service, region, error_code, error_message, and timestamp
        """
        with self._lock:
            return self._errors.copy()

    def get_error_count(self) -> int:
        """
        Get the total number of errors tracked.

        Returns:
            Number of errors
        """
        with self._lock:
            return len(self._errors)

    def has_errors(self) -> bool:
        """
        Check if any errors have been tracked.

        Returns:
            True if errors exist, False otherwise
        """
        with self._lock:
            return len(self._errors) > 0

    def get_errors_by_service(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get errors grouped by service.

        Returns:
            Dictionary mapping service names to lists of error entries
        """
        with self._lock:
            errors_by_service: Dict[str, List[Dict[str, Any]]] = {}
            for error in self._errors:
                service = error['service']
                if service not in errors_by_service:
                    errors_by_service[service] = []
                errors_by_service[service].append(error)
            return errors_by_service

    def get_errors_by_region(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get errors grouped by region.

        Returns:
            Dictionary mapping regions to lists of error entries
        """
        with self._lock:
            errors_by_region: Dict[str, List[Dict[str, Any]]] = {}
            for error in self._errors:
                region = error['region']
                if region not in errors_by_region:
                    errors_by_region[region] = []
                errors_by_region[region].append(error)
            return errors_by_region

    def clear(self) -> None:
        """Clear all tracked errors."""
        with self._lock:
            self._errors.clear()

    def __repr__(self) -> str:
        """String representation of the error tracker."""
        return f"ErrorTracker(errors={self.get_error_count()})"
