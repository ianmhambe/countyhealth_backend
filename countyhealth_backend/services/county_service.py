"""
County service for CountyHealth Backend.
Handles CRUD operations for county dashboards.

Production-ready with comprehensive validation and error handling.
"""
from typing import Dict, Any, Optional

import frappe
from frappe import _

from ..constants import (
    COUNTY_DASHBOARD_DOCTYPE,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    ERROR_NOT_AUTHENTICATED,
    ERROR_COUNTY_NOT_FOUND,
)
from ..session import SessionManager
from ..security import AuthVerifier, SecurityLogger, PasswordHasher
from ..validators import validate_county_data, sanitize_input, sanitize_url


class CountyService:
    """Handles county CRUD operations."""
    
    @staticmethod
    def get_all(
        token: str,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE
    ) -> Dict[str, Any]:
        """
        Get all counties with pagination and search.
        
        Args:
            token: Admin session token
            search: Optional search term for filtering
            page: Page number (1-indexed)
            page_size: Number of results per page
            
        Returns:
            Paginated list of counties
        """
        AuthVerifier.verify_super_admin(token)
        
        # Build filters
        filters = {}
        or_filters = {}
        if search:
            search = sanitize_input(search)
            # Use or_filters for OR conditions
            or_filters = {
                "county_name": ["like", f"%{search}%"],
                "login_username": ["like", f"%{search}%"]
            }
        
        # Sanitize pagination
        page = max(1, int(page) if page else 1)
        page_size = min(max(1, int(page_size) if page_size else DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE)
        start = (page - 1) * page_size
        
        # Fetch counties - only request fields that exist in the table
        try:
            counties = frappe.get_all(
                COUNTY_DASHBOARD_DOCTYPE,
                filters=filters,
                or_filters=or_filters if or_filters else None,
                fields=["name as county_id", "county_name", "login_username", "dashboard_url", "modified"],
                order_by="county_name asc",
                start=start,
                page_length=page_size
            )
        except Exception as e:
            frappe.log_error(f"get_all_counties error: {str(e)}", "CountyService.get_all")
            counties = []
        
        try:
            total = frappe.db.count(COUNTY_DASHBOARD_DOCTYPE, filters or {})
        except Exception:
            total = len(counties)
        
        return {
            "counties": counties,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size
        }
    
    @staticmethod
    def get_dashboard(token: str, county_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get dashboard information for a county.
        
        Args:
            token: Session token
            county_id: Optional county ID (uses session county if not provided)
            
        Returns:
            County dashboard info
        """
        session = SessionManager.get(token)
        if not session:
            frappe.throw(_(ERROR_NOT_AUTHENTICATED), frappe.AuthenticationError)
        
        target_id = county_id or session.get("county_id")
        
        if not target_id or target_id == "super":
            frappe.throw(_("Please select a county"))
        
        # Sanitize county_id to prevent injection
        target_id = sanitize_input(target_id)
        
        county = frappe.db.get_value(
            COUNTY_DASHBOARD_DOCTYPE,
            target_id,
            ["name as county_id", "county_name", "dashboard_url"],
            as_dict=True
        )
        
        if not county:
            frappe.throw(_(ERROR_COUNTY_NOT_FOUND))
        
        return county
    
    @staticmethod
    def get_details(token: str, county_id: str) -> Dict[str, Any]:
        """
        Get detailed county information for editing.
        
        Args:
            token: Admin session token
            county_id: County identifier
            
        Returns:
            Detailed county information
        """
        AuthVerifier.verify_super_admin(token)
        
        # Sanitize input
        county_id = sanitize_input(county_id)
        
        if not frappe.db.exists(COUNTY_DASHBOARD_DOCTYPE, county_id):
            frappe.throw(_(ERROR_COUNTY_NOT_FOUND))
        
        county = frappe.get_doc(COUNTY_DASHBOARD_DOCTYPE, county_id)
        
        return {
            "county_id": county.name,
            "county_name": county.county_name,
            "login_username": county.login_username,
            "dashboard_url": county.dashboard_url,
            "is_active": county.get("is_active", 1),
            "last_login": county.get("last_login"),
            "created": county.creation,
            "modified": county.modified
        }
    
    @staticmethod
    def create(
        token: str,
        name: str,
        county_name: str,
        login_username: str,
        login_password: str,
        dashboard_url: str
    ) -> Dict[str, Any]:
        """
        Create a new county.
        
        Args:
            token: Admin session token
            name: Unique county identifier
            county_name: Display name for the county
            login_username: Username for county login
            login_password: Password for county login
            dashboard_url: URL for county dashboard
            
        Returns:
            Created county information
        """
        session = AuthVerifier.verify_super_admin(token)
        
        # Sanitize inputs
        name = sanitize_input(name)
        county_name = sanitize_input(county_name)
        login_username = sanitize_input(login_username)
        if login_username:
            login_username = login_username.lower()
        dashboard_url = sanitize_url(dashboard_url)
        
        # Validate data
        validate_county_data({
            "name": name,
            "county_name": county_name,
            "login_username": login_username,
            "login_password": login_password,
            "dashboard_url": dashboard_url
        })
        
        # Check for duplicates
        if frappe.db.exists(COUNTY_DASHBOARD_DOCTYPE, name):
            frappe.throw(_("A county with this ID already exists"))
        
        if frappe.db.exists(COUNTY_DASHBOARD_DOCTYPE, {"county_name": county_name}):
            frappe.throw(_("A county with this name already exists"))
        
        if frappe.db.exists(COUNTY_DASHBOARD_DOCTYPE, {"login_username": login_username}):
            frappe.throw(_("This username is already taken"))
        
        # Create county document
        # Note: Frappe's Password field handles encryption, so we pass plain password
        doc = frappe.get_doc({
            "doctype": COUNTY_DASHBOARD_DOCTYPE,
            "name": name,
            "county_name": county_name,
            "login_username": login_username,
            "login_password": login_password,  # Frappe encrypts this
            "dashboard_url": dashboard_url
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
        
        SecurityLogger.log("county_created", {
            "admin": session.get("user"),
            "county_name": county_name,
            "county_id": doc.name
        })
        
        return {
            "status": "success",
            "message": "County created successfully",
            "county": {
                "county_id": doc.name,
                "county_name": doc.county_name,
                "login_username": doc.login_username,
                "dashboard_url": doc.dashboard_url
            }
        }
    
    @staticmethod
    def update(
        token: str,
        county_id: str,
        county_name: Optional[str] = None,
        login_username: Optional[str] = None,
        login_password: Optional[str] = None,
        dashboard_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update an existing county.
        
        Args:
            token: Admin session token
            county_id: County identifier to update
            county_name: Optional new display name
            login_username: Optional new username
            login_password: Optional new password
            dashboard_url: Optional new dashboard URL
            
        Returns:
            Updated county information
        """
        session = AuthVerifier.verify_super_admin(token)
        
        # Sanitize county_id
        county_id = sanitize_input(county_id)
        
        # Check if county exists
        if not frappe.db.exists(COUNTY_DASHBOARD_DOCTYPE, county_id):
            frappe.throw(_(ERROR_COUNTY_NOT_FOUND))
        
        # Prepare update data
        update_data = {}
        
        if county_name is not None:
            update_data["county_name"] = sanitize_input(county_name)
        if login_username is not None:
            sanitized_username = sanitize_input(login_username)
            if sanitized_username:
                update_data["login_username"] = sanitized_username.lower()
        if login_password is not None:
            # Frappe's Password field handles encryption
            update_data["login_password"] = login_password
        if dashboard_url is not None:
            update_data["dashboard_url"] = sanitize_url(dashboard_url)
        
        if not update_data:
            frappe.throw(_("No fields to update"))
        
        # Validate update data
        validate_county_data(update_data, is_update=True)
        
        # Check for duplicates (excluding current county)
        if "county_name" in update_data:
            existing = frappe.db.exists(COUNTY_DASHBOARD_DOCTYPE, {
                "county_name": update_data["county_name"],
                "name": ["!=", county_id]
            })
            if existing:
                frappe.throw(_("A county with this name already exists"))
        
        if "login_username" in update_data:
            existing = frappe.db.exists(COUNTY_DASHBOARD_DOCTYPE, {
                "login_username": update_data["login_username"],
                "name": ["!=", county_id]
            })
            if existing:
                frappe.throw(_("This username is already taken"))
        
        # Update county
        doc = frappe.get_doc(COUNTY_DASHBOARD_DOCTYPE, county_id)
        for key, value in update_data.items():
            setattr(doc, key, value)
        doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        SecurityLogger.log("county_updated", {
            "admin": session.get("user"),
            "county_id": county_id,
            "updated_fields": list(update_data.keys())
        })
        
        return {
            "status": "success",
            "message": "County updated successfully",
            "county": {
                "county_id": doc.name,
                "county_name": doc.county_name,
                "login_username": doc.login_username,
                "dashboard_url": doc.dashboard_url
            }
        }
    
    @staticmethod
    def delete(token: str, county_id: str) -> Dict[str, Any]:
        """
        Delete a county.
        
        Args:
            token: Admin session token
            county_id: County identifier to delete
            
        Returns:
            Deletion confirmation
        """
        session = AuthVerifier.verify_super_admin(token)
        
        # Sanitize input
        county_id = sanitize_input(county_id)
        
        # Check if county exists
        if not frappe.db.exists(COUNTY_DASHBOARD_DOCTYPE, county_id):
            frappe.throw(_(ERROR_COUNTY_NOT_FOUND))
        
        # Get county info for logging
        county_name = frappe.db.get_value(COUNTY_DASHBOARD_DOCTYPE, county_id, "county_name")
        
        # Delete county
        frappe.delete_doc(COUNTY_DASHBOARD_DOCTYPE, county_id, ignore_permissions=True)
        frappe.db.commit()
        
        SecurityLogger.log("county_deleted", {
            "admin": session.get("user"),
            "county_id": county_id,
            "county_name": county_name
        })
        
        return {
            "status": "success",
            "message": "County deleted successfully"
        }
