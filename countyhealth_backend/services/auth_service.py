"""
Authentication service for CountyHealth Backend.
Handles login/logout operations for super admins and county users.

Production-ready with secure password handling and comprehensive logging.
"""
from typing import Dict, Any

import frappe
from frappe import _

from ..constants import (
    SUPER_ADMIN_COUNTY_ID,
    SUPER_ADMIN_COUNTY_NAME,
    COUNTY_DASHBOARD_DOCTYPE,
    ERROR_INVALID_CREDENTIALS,
    get_super_admin_username,
    get_super_admin_password,
)
from ..session import SessionManager
from ..security import RateLimiter, SecurityLogger, PasswordHasher
from ..validators import sanitize_input, validate_token


class AuthService:
    """Handles authentication operations with security best practices."""
    
    @staticmethod
    def _generate_token() -> str:
        """Generate a cryptographically secure session token."""
        return SessionManager.generate_token()
    
    @staticmethod
    def _create_session_data(
        user: str,
        is_super_user: bool,
        county_id: str,
        county_name: str,
        dashboard_url: str = None
    ) -> Dict[str, Any]:
        """Create session data dictionary."""
        return {
            "user": user,
            "is_super_user": is_super_user,
            "county_id": county_id,
            "county_name": county_name,
            "dashboard_url": dashboard_url
        }
    
    @classmethod
    def login_super_admin(cls, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate super admin user.
        
        Args:
            username: Super admin username
            password: Super admin password
            
        Returns:
            Login response with token and user info
        """
        # Verify super admin credentials are configured
        admin_password = get_super_admin_password()
        if not admin_password:
            SecurityLogger.log("super_admin_login_blocked", {
                "reason": "credentials_not_configured"
            }, level="error")
            frappe.throw(_(ERROR_INVALID_CREDENTIALS))
        
        token = cls._generate_token()
        session_data = cls._create_session_data(
            user=username,
            is_super_user=True,
            county_id=SUPER_ADMIN_COUNTY_ID,
            county_name=SUPER_ADMIN_COUNTY_NAME
        )
        
        SessionManager.create(token, session_data)
        SecurityLogger.log_login_attempt(username, success=True)
        
        return {
            "status": "success",
            "token": token,
            "is_super_user": True,
            "county_id": SUPER_ADMIN_COUNTY_ID,
            "county_name": SUPER_ADMIN_COUNTY_NAME,
            "dashboard_url": None
        }
    
    @classmethod
    def login_county(cls, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate county user.
        
        Args:
            username: County login username
            password: County login password
            
        Returns:
            Login response with token and county info
            
        Raises:
            Exception: If credentials are invalid
        """
        # Find county by username
        counties = frappe.get_all(
            COUNTY_DASHBOARD_DOCTYPE,
            filters={"login_username": username},
            fields=["name", "county_name", "dashboard_url"]
        )
        
        if not counties:
            RateLimiter.increment(username)
            SecurityLogger.log_login_attempt(username, success=False, reason="user_not_found")
            frappe.throw(_(ERROR_INVALID_CREDENTIALS))
        
        county = counties[0]
        
        county_doc = frappe.get_doc(COUNTY_DASHBOARD_DOCTYPE, county.name)
        stored_password = county_doc.get_password("login_password")
        
        # Frappe's get_password() returns the decrypted password
        # Use timing-safe comparison to prevent timing attacks
        import hmac
        if not stored_password or not hmac.compare_digest(password, stored_password):
            RateLimiter.increment(username)
            SecurityLogger.log_login_attempt(username, success=False, reason="invalid_password")
            frappe.throw(_(ERROR_INVALID_CREDENTIALS))
        
        # Successful login
        token = cls._generate_token()
        session_data = cls._create_session_data(
            user=username,
            is_super_user=False,
            county_id=county.name,
            county_name=county.county_name,
            dashboard_url=county.dashboard_url
        )
        
        SessionManager.create(token, session_data)
        RateLimiter.reset(username)
        SecurityLogger.log_login_attempt(username, success=True)
        
        return {
            "status": "success",
            "token": token,
            "is_super_user": False,
            "county_id": county.name,
            "county_name": county.county_name,
            "dashboard_url": county.dashboard_url
        }
    
    @classmethod
    def login(cls, username: str, password: str) -> Dict[str, Any]:
        """
        Main login method - routes to appropriate handler.
        
        Args:
            username: Login username
            password: Login password
            
        Returns:
            Login response with token and user info
        """
        # Sanitize and normalize username
        username = sanitize_input(username)
        if username:
            username = username.lower()
        
        # Validate inputs
        if not username or not password:
            frappe.throw(_(ERROR_INVALID_CREDENTIALS))
        
        # Check rate limit
        RateLimiter.check_and_throw(username)
        
        # Check for super admin (timing-safe comparison for password)
        import hmac
        admin_username = get_super_admin_username()
        admin_password = get_super_admin_password()
        
        if username == admin_username:
            if admin_password and hmac.compare_digest(password, admin_password):
                RateLimiter.reset(username)
                return cls.login_super_admin(username, password)
            else:
                RateLimiter.increment(username)
                SecurityLogger.log_login_attempt(username, success=False, reason="invalid_password")
                frappe.throw(_(ERROR_INVALID_CREDENTIALS))
        
        # Regular county login
        return cls.login_county(username, password)
    
    @classmethod
    def logout(cls, token: str) -> Dict[str, Any]:
        """
        Logout user by invalidating session.
        
        Args:
            token: Session token to invalidate
            
        Returns:
            Logout response
        """
        session = SessionManager.get(token)
        if session:
            SecurityLogger.log("logout", {"user": session.get("user")})
            SessionManager.delete(token)
        
        return {"status": "success"}
