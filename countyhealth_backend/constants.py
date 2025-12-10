"""
Constants and configuration for CountyHealth Backend.

Production-ready configuration with environment variable support.
"""
import os
from typing import Final, Optional

# Note: frappe is imported lazily to avoid import-time issues


def _get_env(key: str, default: str = "") -> str:
    """Get environment variable with fallback to site config."""
    # First check environment variables
    value = os.environ.get(key)
    if value:
        return value
    # Then check Frappe site config (lazy import)
    try:
        import frappe
        if frappe.conf:
            return frappe.conf.get(key.lower(), default)
    except Exception:
        pass
    return default


def _get_env_int(key: str, default: int) -> int:
    """Get integer environment variable."""
    try:
        return int(_get_env(key, str(default)))
    except (ValueError, TypeError):
        return default


def get_super_admin_username() -> str:
    """Get super admin username (lazy loaded)."""
    return _get_env("COUNTYHEALTH_ADMIN_USERNAME", "superadmin")


def get_super_admin_password() -> str:
    """Get super admin password (lazy loaded)."""
    return _get_env("COUNTYHEALTH_ADMIN_PASSWORD", "")


# =============================================================================
# SESSION CONFIGURATION
# =============================================================================
SESSION_PREFIX: Final[str] = "countyhealth_session_"
SESSION_EXPIRY_SECONDS: Final[int] = 3600  # 1 hour default, can be overridden

def get_session_expiry() -> int:
    """Get session expiry in seconds (lazy loaded)."""
    return _get_env_int("COUNTYHEALTH_SESSION_EXPIRY", 3600)

# =============================================================================
# RATE LIMITING
# =============================================================================
LOGIN_ATTEMPTS_PREFIX: Final[str] = "countyhealth_login_attempts_"
MAX_LOGIN_ATTEMPTS: Final[int] = 5  # Default
LOGIN_LOCKOUT_SECONDS: Final[int] = 300  # 5 minutes default

def get_max_login_attempts() -> int:
    """Get max login attempts (lazy loaded)."""
    return _get_env_int("COUNTYHEALTH_MAX_LOGIN_ATTEMPTS", 5)

def get_login_lockout_seconds() -> int:
    """Get login lockout duration (lazy loaded)."""
    return _get_env_int("COUNTYHEALTH_LOGIN_LOCKOUT", 300)

# =============================================================================
# PAGINATION
# =============================================================================
DEFAULT_PAGE_SIZE: Final[int] = 50
MAX_PAGE_SIZE: Final[int] = 100

# =============================================================================
# SUPER ADMIN CONFIGURATION (Static constants, values loaded via functions)
# =============================================================================
SUPER_ADMIN_USERNAME: Final[str] = "superadmin"  # Default, use get_super_admin_username()
SUPER_ADMIN_PASSWORD: Final[str] = ""  # Default empty, use get_super_admin_password()
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
