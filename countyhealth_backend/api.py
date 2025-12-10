"""
CountyHealth Backend API.

This module provides the public API endpoints for the CountyHealth system.
All business logic is delegated to service classes for better separation of concerns.
"""
from typing import Optional

import frappe
from frappe import _

from .services.auth_service import AuthService
from .services.county_service import CountyService


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@frappe.whitelist(allow_guest=True)
def login(username: str, password: str) -> dict:
    """
    Authenticate a user (super admin or county).
    
    Args:
        username: Login username
        password: Login password
        
    Returns:
        dict: Login response containing:
            - status: "success"
            - token: Session token
            - is_super_user: Whether user is super admin
            - county_id: County identifier
            - county_name: County display name
            - dashboard_url: URL for county dashboard (None for super admin)
    """
    try:
        return AuthService.login(username, password)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "County Login Error")
        frappe.throw(_(str(e)))


@frappe.whitelist(allow_guest=True)
def logout(token: str) -> dict:
    """
    Logout a user by invalidating their session.
    
    Args:
        token: Session token to invalidate
        
    Returns:
        dict: Logout response with status
    """
    try:
        return AuthService.logout(token)
    except Exception as e:
        return {"status": "error", "message": str(e)}


# =============================================================================
# COUNTY QUERY ENDPOINTS
# =============================================================================

@frappe.whitelist(allow_guest=True)
def get_all_counties(
    token: str,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 50
) -> dict:
    """
    Get all counties with pagination and search (admin only).
    
    Args:
        token: Admin session token
        search: Optional search term for filtering by name or username
        page: Page number (1-indexed)
        page_size: Number of results per page (max 100)
        
    Returns:
        dict: Paginated response containing:
            - counties: List of county records
            - total: Total count of matching counties
            - page: Current page number
            - page_size: Items per page
            - total_pages: Total number of pages
    """
    try:
        return CountyService.get_all(token, search, page, page_size)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Get All Counties Error")
        frappe.throw(_(str(e)))


@frappe.whitelist(allow_guest=True)
def get_dashboard(token: str, county_id: Optional[str] = None) -> dict:
    """
    Get dashboard information for a county.
    
    Args:
        token: Session token
        county_id: Optional county ID (uses session county if not provided)
        
    Returns:
        dict: County dashboard info containing:
            - county_id: County identifier
            - county_name: County display name
            - dashboard_url: URL for the dashboard
    """
    try:
        return CountyService.get_dashboard(token, county_id)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Get Dashboard Error")
        frappe.throw(_(str(e)))


@frappe.whitelist(allow_guest=True)
def get_county_details(token: str, county_id: str) -> dict:
    """
    Get detailed county information for editing (admin only).
    
    Args:
        token: Admin session token
        county_id: County identifier
        
    Returns:
        dict: Detailed county information containing:
            - county_id: County identifier
            - county_name: County display name
            - login_username: County login username
            - dashboard_url: Dashboard URL
            - created: Creation timestamp
            - modified: Last modification timestamp
    """
    try:
        return CountyService.get_details(token, county_id)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Get County Details Error")
        frappe.throw(_(str(e)))


# =============================================================================
# COUNTY MANAGEMENT ENDPOINTS
# =============================================================================

@frappe.whitelist(allow_guest=True)
def create_county(
    token: str,
    name: str,
    county_name: str,
    login_username: str,
    login_password: str,
    dashboard_url: str
) -> dict:
    """
    Create a new county (admin only).
    
    Args:
        token: Admin session token
        name: Unique county identifier
        county_name: Display name for the county
        login_username: Username for county login
        login_password: Password for county login
        dashboard_url: URL for county dashboard
        
    Returns:
        dict: Creation response containing:
            - status: "success"
            - message: Success message
            - county: Created county details
    """
    try:
        return CountyService.create(
            token, name, county_name, login_username, login_password, dashboard_url
        )
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Create County Error")
        frappe.throw(_(str(e)))


@frappe.whitelist(allow_guest=True)
def update_county(
    token: str,
    county_id: str,
    county_name: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    dashboard_url: Optional[str] = None
) -> dict:
    """
    Update an existing county (admin only).
    
    Args:
        token: Admin session token
        county_id: County identifier to update
        county_name: Optional new display name
        login_username: Optional new username
        login_password: Optional new password
        dashboard_url: Optional new dashboard URL
        
    Returns:
        dict: Update response containing:
            - status: "success"
            - message: Success message
            - county: Updated county details
    """
    try:
        return CountyService.update(
            token, county_id, county_name, login_username, login_password, dashboard_url
        )
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Update County Error")
        frappe.throw(_(str(e)))


@frappe.whitelist(allow_guest=True)
def delete_county(token: str, county_id: str) -> dict:
    """
    Delete a county (admin only).
    
    Args:
        token: Admin session token
        county_id: County identifier to delete
        
    Returns:
        dict: Deletion response containing:
            - status: "success"
            - message: Success message
    """
    try:
        return CountyService.delete(token, county_id)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Delete County Error")
        frappe.throw(_(str(e)))