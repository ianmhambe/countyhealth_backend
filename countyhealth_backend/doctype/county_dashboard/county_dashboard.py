"""
CountyDashboard DocType Controller.

Handles validation, security, and lifecycle events for county dashboard records.
"""
import re
from typing import Optional

import frappe
from frappe import _
from frappe.model.document import Document

from countyhealth_backend.constants import (
    MIN_COUNTY_NAME_LENGTH,
    MAX_COUNTY_NAME_LENGTH,
    MIN_USERNAME_LENGTH,
    MAX_USERNAME_LENGTH,
    MIN_PASSWORD_LENGTH,
    MAX_URL_LENGTH,
    RESERVED_USERNAMES,
    USERNAME_PATTERN,
)
from countyhealth_backend.security import SecurityLogger


class CountyDashboard(Document):
    """
    Controller for CountyDashboard DocType.
    
    Manages county dashboard configurations including login credentials
    and dashboard URLs with proper validation and security measures.
    """
    
    def validate(self) -> None:
        """Run validations before save."""
        self._validate_county_name()
        self._validate_username()
        self._validate_password()
        self._validate_dashboard_url()
        self._normalize_fields()
    
    def before_save(self) -> None:
        """Process data before saving to database."""
        # Note: Frappe's Password fieldtype handles encryption automatically
        # No manual password hashing needed
        pass
    
    def after_insert(self) -> None:
        """Log creation event."""
        SecurityLogger.log("county_created_via_doctype", {
            "county_id": self.name,
            "county_name": self.county_name,
            "created_by": frappe.session.user
        })
    
    def on_update(self) -> None:
        """Log update event."""
        SecurityLogger.log("county_updated_via_doctype", {
            "county_id": self.name,
            "county_name": self.county_name,
            "modified_by": frappe.session.user
        })
    
    def on_trash(self) -> None:
        """Log deletion event."""
        SecurityLogger.log("county_deleted_via_doctype", {
            "county_id": self.name,
            "county_name": self.county_name,
            "deleted_by": frappe.session.user
        }, level="warning")
    
    def _validate_county_name(self) -> None:
        """Validate county name field."""
        if not self.county_name:
            frappe.throw(_("County Name is required"))
        
        name = self.county_name.strip()
        
        if len(name) < MIN_COUNTY_NAME_LENGTH:
            frappe.throw(_(f"County Name must be at least {MIN_COUNTY_NAME_LENGTH} characters"))
        
        if len(name) > MAX_COUNTY_NAME_LENGTH:
            frappe.throw(_(f"County Name must not exceed {MAX_COUNTY_NAME_LENGTH} characters"))
    
    def _validate_username(self) -> None:
        """Validate login username field."""
        if not self.login_username:
            frappe.throw(_("Login Username is required"))
        
        username = self.login_username.strip().lower()
        
        if len(username) < MIN_USERNAME_LENGTH:
            frappe.throw(_(f"Username must be at least {MIN_USERNAME_LENGTH} characters"))
        
        if len(username) > MAX_USERNAME_LENGTH:
            frappe.throw(_(f"Username must not exceed {MAX_USERNAME_LENGTH} characters"))
        
        if not re.match(USERNAME_PATTERN, username):
            frappe.throw(_("Username can only contain lowercase letters, numbers, and underscores, and must start with a letter"))
        
        if username in RESERVED_USERNAMES:
            frappe.throw(_("This username is reserved and cannot be used"))
    
    def _validate_password(self) -> None:
        """Validate password field (only for new/changed passwords)."""
        # Skip validation if password is already hashed (existing record)
        if self._is_password_hashed():
            return
        
        if not self.login_password:
            frappe.throw(_("Login Password is required"))
        
        password = self.login_password
        
        if len(password) < MIN_PASSWORD_LENGTH:
            frappe.throw(_(f"Password must be at least {MIN_PASSWORD_LENGTH} characters"))
    
    def _validate_dashboard_url(self) -> None:
        """Validate dashboard URL field."""
        if not self.dashboard_url:
            frappe.throw(_("Dashboard URL is required"))
        
        url = self.dashboard_url.strip()
        
        if not url.startswith(("http://", "https://")):
            frappe.throw(_("Dashboard URL must start with http:// or https://"))
        
        if len(url) > MAX_URL_LENGTH:
            frappe.throw(_(f"Dashboard URL must not exceed {MAX_URL_LENGTH} characters"))
    
    def _normalize_fields(self) -> None:
        """Normalize field values before save."""
        if self.county_name:
            self.county_name = self.county_name.strip()
        
        if self.login_username:
            self.login_username = self.login_username.strip().lower()
        
        if self.dashboard_url:
            self.dashboard_url = self.dashboard_url.strip()
