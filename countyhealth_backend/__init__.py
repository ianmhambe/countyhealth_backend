"""
CountyHealth Backend - A Frappe app for managing county health dashboards.
"""
__version__ = "0.0.1"

# Public API exports
from .api import (
    login,
    logout,
    get_all_counties,
    get_dashboard,
    get_county_details,
    create_county,
    update_county,
    delete_county,
)

__all__ = [
    "__version__",
    "login",
    "logout",
    "get_all_counties",
    "get_dashboard",
    "get_county_details",
    "create_county",
    "update_county",
    "delete_county",
]
