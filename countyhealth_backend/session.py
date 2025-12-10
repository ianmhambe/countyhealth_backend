"""
Session management for CountyHealth Backend.
Handles token-based session storage and retrieval using Redis cache.

Production-ready with secure token generation and proper serialization.
"""
import secrets
import uuid
from typing import Optional, Dict, Any

import frappe

from .constants import SESSION_PREFIX, SESSION_EXPIRY_SECONDS


class SessionManager:
    """Manages user sessions using Redis cache with security best practices."""
    
    @staticmethod
    def _get_key(token: str) -> str:
        """Generate cache key for a session token."""
        return f"{SESSION_PREFIX}{token}"
    
    @staticmethod
    def generate_token() -> str:
        """
        Generate a cryptographically secure session token.
        
        Uses UUID4 which is based on random numbers, providing
        122 bits of randomness.
        
        Returns:
            Secure random token string
        """
        return str(uuid.uuid4())
    
    @classmethod
    def create(cls, token: str, data: Dict[str, Any]) -> None:
        """
        Store session data in cache.
        
        Args:
            token: Unique session token
            data: Session data to store (user info, permissions, etc.)
        """
        if not token:
            raise ValueError("Token cannot be empty")
        
        key = cls._get_key(token)
        # Add creation timestamp for audit
        data['_created'] = str(frappe.utils.now_datetime())
        frappe.cache().setex(key, SESSION_EXPIRY_SECONDS, frappe.as_json(data))
    
    @classmethod
    def get(cls, token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve session data from cache.
        
        Args:
            token: Session token to look up
            
        Returns:
            Session data dict if found, None otherwise
        """
        if not token:
            return None
            
        key = cls._get_key(token)
        data = frappe.cache().get(key)
        
        if not data:
            return None
            
        # Handle bytes from Redis
        if isinstance(data, bytes):
            data = data.decode('utf-8')
            
        try:
            return frappe.parse_json(data)
        except Exception:
            # Invalid JSON - possibly corrupted session
            cls.delete(token)
            return None
    
    @classmethod
    def refresh(cls, token: str) -> bool:
        """
        Refresh session expiry time.
        
        Args:
            token: Session token to refresh
            
        Returns:
            True if session was refreshed, False if not found
        """
        session = cls.get(token)
        if session:
            cls.create(token, session)
            return True
        return False
    
    @classmethod
    def delete(cls, token: str) -> None:
        """
        Delete a session from cache.
        
        Args:
            token: Session token to delete
        """
        key = cls._get_key(token)
        frappe.cache().delete_value(key)
    
    @classmethod
    def exists(cls, token: str) -> bool:
        """
        Check if a session exists.
        
        Args:
            token: Session token to check
            
        Returns:
            True if session exists, False otherwise
        """
        return cls.get(token) is not None


# Backward-compatible function aliases
def session_set(token: str, data: Dict[str, Any]) -> None:
    """Store session data in cache as JSON string."""
    SessionManager.create(token, data)


def session_get(token: str) -> Optional[Dict[str, Any]]:
    """Retrieve and parse session data from cache."""
    return SessionManager.get(token)


def session_delete(token: str) -> None:
    """Delete session from cache."""
    SessionManager.delete(token)
