"""
Security utilities for CountyHealth Backend.
Handles authentication verification, rate limiting, and security logging.

Production-ready with comprehensive security measures.
"""
import hashlib
import hmac
import secrets
from typing import Dict, Any, Optional

import frappe
from frappe import _
from frappe.utils import now_datetime

from .session import SessionManager
from .constants import (
    LOGIN_ATTEMPTS_PREFIX,
    MAX_LOGIN_ATTEMPTS,
    LOGIN_LOCKOUT_SECONDS,
    ERROR_NOT_AUTHENTICATED,
    ERROR_NOT_AUTHORIZED,
    ERROR_RATE_LIMITED,
)


class SecurityLogger:
    """Handles security-related event logging with structured data."""
    
    @staticmethod
    def log(event_type: str, details: Dict[str, Any], level: str = "info") -> None:
        """
        Log a security-related event.
        
        Args:
            event_type: Type of security event (e.g., 'login_failed', 'unauthorized_access')
            details: Additional context about the event
            level: Log level ('info', 'warning', 'error')
        """
        try:
            # Get request context safely
            request_info = {}
            if frappe.request:
                request_info = {
                    "ip": frappe.local.request_ip if hasattr(frappe.local, 'request_ip') else 'unknown',
                    "user_agent": frappe.request.headers.get('User-Agent', 'unknown')[:200],
                }
            
            log_data = {
                "event": event_type,
                "timestamp": str(now_datetime()),
                "request": request_info,
                "details": details
            }
            
            # Use appropriate logging method based on severity
            if level == "error" or event_type in ('sql_injection_attempt', 'unauthorized_access_attempt'):
                frappe.log_error(
                    title=f"Security Alert: {event_type}",
                    message=frappe.as_json(log_data)
                )
            else:
                # For info/warning, use logger if available, else error log
                frappe.log_error(
                    title=f"Security Event: {event_type}",
                    message=frappe.as_json(log_data)
                )
        except Exception:
            # Silently fail - logging should not break functionality
            pass
    
    @classmethod
    def log_login_attempt(cls, username: str, success: bool, reason: str = None) -> None:
        """Log a login attempt."""
        cls.log(
            "login_attempt",
            {
                "username": username,
                "success": success,
                "reason": reason
            },
            level="info" if success else "warning"
        )


class RateLimiter:
    """Handles rate limiting for login attempts."""
    
    @staticmethod
    def _get_key(identifier: str) -> str:
        """Generate cache key for rate limiting."""
        return f"{LOGIN_ATTEMPTS_PREFIX}{identifier}"
    
    @classmethod
    def get_attempts(cls, identifier: str) -> int:
        """
        Get current number of attempts for an identifier.
        
        Args:
            identifier: Unique identifier (e.g., username, IP)
            
        Returns:
            Number of attempts recorded
        """
        attempts = frappe.cache().get(cls._get_key(identifier))
        return int(attempts) if attempts else 0
    
    @classmethod
    def increment(cls, identifier: str) -> int:
        """
        Increment attempt counter.
        
        Args:
            identifier: Unique identifier
            
        Returns:
            New attempt count
        """
        key = cls._get_key(identifier)
        current = cls.get_attempts(identifier)
        new_count = current + 1
        frappe.cache().setex(key, LOGIN_LOCKOUT_SECONDS, new_count)
        return new_count
    
    @classmethod
    def reset(cls, identifier: str) -> None:
        """
        Reset attempt counter.
        
        Args:
            identifier: Unique identifier to reset
        """
        frappe.cache().delete_value(cls._get_key(identifier))
    
    @classmethod
    def is_blocked(cls, identifier: str) -> bool:
        """
        Check if identifier is blocked due to too many attempts.
        
        Args:
            identifier: Unique identifier to check
            
        Returns:
            True if blocked, False otherwise
        """
        return cls.get_attempts(identifier) >= MAX_LOGIN_ATTEMPTS
    
    @classmethod
    def check_and_throw(cls, identifier: str) -> None:
        """
        Check rate limit and throw exception if exceeded.
        
        Args:
            identifier: Unique identifier to check
            
        Raises:
            Exception: If rate limit exceeded
        """
        if cls.is_blocked(identifier):
            SecurityLogger.log("rate_limit_exceeded", {"identifier": identifier}, level="warning")
            frappe.throw(_(ERROR_RATE_LIMITED))


class PasswordHasher:
    """Secure password hashing using PBKDF2."""
    
    # Use a strong iteration count (adjust based on server capacity)
    ITERATIONS = 100000
    ALGORITHM = 'sha256'
    SALT_LENGTH = 32
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash a password with a random salt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password in format: algorithm$iterations$salt$hash
        """
        salt = secrets.token_hex(cls.SALT_LENGTH)
        hash_bytes = hashlib.pbkdf2_hmac(
            cls.ALGORITHM,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            cls.ITERATIONS
        )
        hash_hex = hash_bytes.hex()
        
        return f"{cls.ALGORITHM}${cls.ITERATIONS}${salt}${hash_hex}"
    
    @classmethod
    def verify_password(cls, password: str, hashed: str) -> bool:
        """
        Verify a password against a hash.
        
        Args:
            password: Plain text password to verify
            hashed: Stored hash to verify against
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            # Handle legacy plain-text passwords (for migration)
            if '$' not in hashed:
                # Plain text comparison (legacy) - timing-safe
                return hmac.compare_digest(password, hashed)
            
            parts = hashed.split('$')
            if len(parts) != 4:
                return False
            
            algorithm, iterations, salt, stored_hash = parts
            iterations = int(iterations)
            
            # Compute hash with same parameters
            hash_bytes = hashlib.pbkdf2_hmac(
                algorithm,
                password.encode('utf-8'),
                salt.encode('utf-8'),
                iterations
            )
            computed_hash = hash_bytes.hex()
            
            # Timing-safe comparison
            return hmac.compare_digest(computed_hash, stored_hash)
            
        except (ValueError, TypeError):
            return False


class AuthVerifier:
    """Handles authentication verification."""
    
    @staticmethod
    def get_session(token: str) -> Optional[Dict[str, Any]]:
        """
        Get session data for a token.
        
        Args:
            token: Session token
            
        Returns:
            Session data if valid, None otherwise
        """
        return SessionManager.get(token)
    
    @staticmethod
    def verify_authenticated(token: str) -> Dict[str, Any]:
        """
        Verify token is authenticated and return session.
        
        Args:
            token: Session token to verify
            
        Returns:
            Session data dict
            
        Raises:
            frappe.AuthenticationError: If not authenticated
        """
        session = SessionManager.get(token)
        if not session:
            frappe.throw(_(ERROR_NOT_AUTHENTICATED), frappe.AuthenticationError)
        return session
    
    @staticmethod
    def verify_super_admin(token: str) -> Dict[str, Any]:
        """
        Verify token belongs to a super admin.
        
        Args:
            token: Session token to verify
            
        Returns:
            Session data dict
            
        Raises:
            frappe.AuthenticationError: If not authenticated
            frappe.PermissionError: If not a super admin
        """
        session = SessionManager.get(token)
        
        if not session:
            frappe.throw(_(ERROR_NOT_AUTHENTICATED), frappe.AuthenticationError)
        
        if not session.get("is_super_user"):
            SecurityLogger.log("unauthorized_access_attempt", {
                "user": session.get("user"),
                "action": "admin_access_denied"
            }, level="warning")
            frappe.throw(_(ERROR_NOT_AUTHORIZED), frappe.PermissionError)
        
        return session


# Convenience function aliases for backward compatibility
def verify_super_admin(token: str) -> Dict[str, Any]:
    """Verify if the token belongs to a super admin."""
    return AuthVerifier.verify_super_admin(token)


def log_security_event(event_type: str, details: Dict[str, Any]) -> None:
    """Log security-related events."""
    SecurityLogger.log(event_type, details)


def hash_password(password: str) -> str:
    """Hash a password securely."""
    return PasswordHasher.hash_password(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    return PasswordHasher.verify_password(password, hashed)
