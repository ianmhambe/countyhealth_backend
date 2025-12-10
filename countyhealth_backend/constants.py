"""
Constants and configuration for CountyHealth Backend.

Production-ready configuration with environment variable support.
"""
import os
from typing import Final

import frappe


def _get_env(key: str, default: str = "") -> str:
    """Get environment variable with fallback to site config."""
    # First check environment variables
    value = os.environ.get(key)
    if value:
        return value
    # Then check Frappe site config
    try:
        return frappe.conf.get(key.lower(), default)
    except Exception:
        return default


def _get_env_int(key: str, default: int) -> int:
    """Get integer environment variable."""
    try:
        return int(_get_env(key, str(default)))
    except (ValueError, TypeError):
        return default


# =============================================================================
# SESSION CONFIGURATION
# =============================================================================
SESSION_PREFIX: Final[str] = "countyhealth_session_"
SESSION_EXPIRY_SECONDS: Final[int] = _get_env_int("COUNTYHEALTH_SESSION_EXPIRY", 3600)  # 1 hour

# =============================================================================
# RATE LIMITING
# =============================================================================
LOGIN_ATTEMPTS_PREFIX: Final[str] = "countyhealth_login_attempts_"
MAX_LOGIN_ATTEMPTS: Final[int] = _get_env_int("COUNTYHEALTH_MAX_LOGIN_ATTEMPTS", 5)
LOGIN_LOCKOUT_SECONDS: Final[int] = _get_env_int("COUNTYHEALTH_LOGIN_LOCKOUT", 300)  # 5 minutes

# =============================================================================
# PAGINATION
# =============================================================================
DEFAULT_PAGE_SIZE: Final[int] = 50
MAX_PAGE_SIZE: Final[int] = 100

# =============================================================================
# SUPER ADMIN CONFIGURATION
# IMPORTANT: Set these via environment variables in production!
# =============================================================================
SUPER_ADMIN_USERNAME: Final[str] = _get_env("COUNTYHEALTH_ADMIN_USERNAME", "superadmin")
SUPER_ADMIN_PASSWORD: Final[str] = _get_env("COUNTYHEALTH_ADMIN_PASSWORD", "")
SUPER_ADMIN_COUNTY_ID: Final[str] = "super"
SUPER_ADMIN_COUNTY_NAME: Final[str] = "All Counties"

# =============================================================================
# VALIDATION CONSTRAINTS
# =============================================================================
MIN_COUNTY_ID_LENGTH: Final[int] = 2
MAX_COUNTY_ID_LENGTH: Final[int] = 100
MIN_COUNTY_NAME_LENGTH: Final[int] = 2
MAX_COUNTY_NAME_LENGTH: Final[int] = 100
MIN_USERNAME_LENGTH: Final[int] = 3
MAX_USERNAME_LENGTH: Final[int] = 50
MIN_PASSWORD_LENGTH: Final[int] = 8  # Increased for security
MAX_PASSWORD_LENGTH: Final[int] = 128
MAX_URL_LENGTH: Final[int] = 500

# Password complexity requirements
PASSWORD_REQUIRE_UPPERCASE: Final[bool] = True
PASSWORD_REQUIRE_LOWERCASE: Final[bool] = True
PASSWORD_REQUIRE_DIGIT: Final[bool] = True
PASSWORD_REQUIRE_SPECIAL: Final[bool] = False  # Optional

# =============================================================================
# RESERVED USERNAMES
# =============================================================================
RESERVED_USERNAMES: Final[frozenset] = frozenset([
    "admin",
    "superadmin",
    "root",
    "administrator",
    "system",
    "guest",
    "anonymous",
    "null",
    "undefined",
])

# =============================================================================
# REGEX PATTERNS
# =============================================================================
COUNTY_ID_PATTERN: Final[str] = r'^[a-zA-Z0-9][a-zA-Z0-9-_]*$'  # Must start with alphanumeric
USERNAME_PATTERN: Final[str] = r'^[a-z][a-z0-9_]*$'  # Must start with letter

# =============================================================================
# DOCTYPE NAMES
# =============================================================================
COUNTY_DASHBOARD_DOCTYPE: Final[str] = "CountyDashboard"

# =============================================================================
# ERROR MESSAGES (Consistent, non-revealing)
# =============================================================================
ERROR_INVALID_CREDENTIALS: Final[str] = "Invalid username or password"
ERROR_NOT_AUTHENTICATED: Final[str] = "Authentication required"
ERROR_NOT_AUTHORIZED: Final[str] = "You do not have permission to perform this action"
ERROR_RATE_LIMITED: Final[str] = "Too many attempts. Please try again later."
ERROR_COUNTY_NOT_FOUND: Final[str] = "County not found"
ERROR_VALIDATION_FAILED: Final[str] = "Validation failed"
