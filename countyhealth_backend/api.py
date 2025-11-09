import frappe 
import uuid 
import re 
from frappe import _ 
from frappe.utils import now_datetime

# ---
# TOKEN SESSION HELPERS (REDIS)
# ---
def session_set(token, data):
    """Store session data in cache as JSON string"""
    frappe.cache().setex(f"session_{token}", 3600, frappe.as_json(data))

def session_get(token):
    """Retrieve and parse session data from cache"""
    data = frappe.cache().get(f"session_{token}")
    if data:
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return frappe.parse_json(data)
    return None

def session_delete(token):
    """Delete session from cache"""
    frappe.cache().delete_value(f"session_{token}")

# ---
# SECURITY HELPERS
# ---
def verify_super_admin(token):
    """Verify if the token belongs to a super admin"""
    session = session_get(token)
    if not session:
        frappe.throw(_("Not authenticated"), frappe.AuthenticationError)
    if not session.get("is_super_user"):
        log_security_event("unauthorized_access_attempt", {
            "user": session.get("user"),
            "action": "admin_access_denied"
        })
        frappe.throw(_("Unauthorized. Super admin access required."), frappe.PermissionError)
    return session

def validate_county_data(data, is_update=False):
    """Comprehensive validation for county data"""

    errors = []

    # Validate name (only for creation)
    if not is_update and "name" in data:
        name = data.get("name", "").strip()
        if not name:
            errors.append("County ID is required")
        elif len(name) < 2:
            errors.append("County ID must be at least 2 characters")
        elif len(name) > 100:
            errors.append("County ID must not exceed 100 characters")
        elif not re.match(r'^[a-zA-Z0-9-_]+$', name):
            errors.append("County ID can only contain letters, numbers, hyphens, and underscores")

    # Validate county name
    if not is_update or "county_name" in data:
        county_name = data.get("county_name", "").strip()
        if not county_name:
            errors.append("County name is required")
        elif len(county_name) < 2:
            errors.append("County name must be at least 2 characters")
        elif len(county_name) > 100:
            errors.append("County name must not exceed 100 characters")

    # Validate login username
    if not is_update or "login_username" in data:
        username = data.get("login_username", "").strip().lower()
        if not username:
            errors.append("Login username is required")
        elif len(username) < 3:
            errors.append("Username must be at least 3 characters")
        elif len(username) > 50:
            errors.append("Username must not exceed 50 characters")
        elif not re.match(r'^[a-z0-9_]+$', username):
            errors.append("Username can only contain lowercase letters, numbers, and underscores")
        elif username in ["admin", "superadmin", "root", "administrator"]:
            errors.append("This username is reserved")

    # Validate password
    if not is_update or "login_password" in data:
        password = data.get("login_password", "")
        if not password:
            errors.append("Password is required")
        elif len(password) < 6:
            errors.append("Password must be at least 6 characters")
        elif len(password) > 100:
            errors.append("Password must not exceed 100 characters")

    # Validate dashboard URL
    if not is_update or "dashboard_url" in data:
        url = data.get("dashboard_url", "").strip()
        if not url:
            errors.append("Dashboard URL is required")
        elif not url.startswith(("http://", "https://")):
            errors.append("Dashboard URL must start with http:// or https://")
        elif len(url) > 500:
            errors.append("Dashboard URL must not exceed 500 characters")

    if errors:
        frappe.throw(_("<br>".join(errors)), frappe.ValidationError)

    return True

def log_security_event(event_type, details):
    """Log security-related events"""
    try:
        frappe.log_error(
            title=f"Security Event: {event_type}",
            message=frappe.as_json({
                "event": event_type,
                "timestamp": now_datetime(),
                "details": details
            })
        )
    except Exception:
        pass

def sanitize_input(value):
    """Sanitize user input"""
    if isinstance(value, str):
        return value.strip()
    return value

# ---
# LOGIN (EXISTING - ENHANCED)
# ---
@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        username = sanitize_input(username).lower()

        # Rate limiting check
        cache_key = f"login_attempts_{username}"
        attempts = frappe.cache().get(cache_key) or 0
        if attempts >= 5:
            log_security_event("rate_limit_exceeded", {"username": username})
            frappe.throw(_("Too many login attempts. Please try again later."))

        # Check for superadmin
        if username == "superadmin" and password == "SuperAdmin@2025":
            token = str(uuid.uuid4())
            session_set(token, {
                "user": username,
                "is_super_user": True,
                "county_id": "super",
                "county_name": "All Counties"
            })
            log_security_event("super_admin_login", {"username": username})
            frappe.cache().delete_value(cache_key)
            return {
                "status": "success",
                "token": token,
                "is_super_user": True,
                "county_id": "super",
                "county_name": "All Counties",
                "dashboard_url": None
            }

        # Regular county login
        counties = frappe.get_all(
            "CountyDashboard",
            filters={"login_username": username},
            fields=["name", "county_name", "dashboard_url"]
        )

        if not counties:
            frappe.cache().setex(cache_key, 300, attempts + 1)
            log_security_event("login_failed", {"username": username, "reason": "user_not_found"})
            frappe.throw(_("Invalid username or password"))
        
        county = counties[0]
        county_doc = frappe.get_doc("CountyDashboard", county.name)
        stored_password = county_doc.get_password("login_password")

        if stored_password != password:
            frappe.cache().setex(cache_key, 300, attempts + 1)
            log_security_event("login_failed", {"username": username, "reason": "invalid_password"})
            frappe.throw(_("Invalid username or password"))
        
        token = str(uuid.uuid4())
        session_set(token, {
            "user": username,
            "is_super_user": False,
            "county_id": county.name,
            "county_name": county.county_name,
            "dashboard_url": county.dashboard_url
        })

        frappe.cache().delete_value(cache_key)
        log_security_event("county_login", {"username": username, "county": county.county_name})

        return {
            "status": "success",
            "token": token,
            "is_super_user": False,
            "county_id": county.name,
            "county_name": county.county_name,
            "dashboard_url": county.dashboard_url
        }

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "County Login Error")
        frappe.throw(_(str(e)))

# ---
# LOGOUT (EXISTING)
# ---
@frappe.whitelist(allow_guest=True)
def logout(token):
    try:
        session = session_get(token)
        if session:
            log_security_event("logout", {"user": session.get("user")})
            session_delete(token)
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ---
# GET ALL COUNTIES (EXISTING - ENHANCED)
# ---
@frappe.whitelist(allow_guest=True)
def get_all_counties(token, search=None, page=1, page_size=50):
    try:
        verify_super_admin(token)

        filters = {}

        if search:
            search = sanitize_input(search)
            filters = [
                ["county_name", "like", f"%{search}%"],
                "or",
                ["login_username", "like", f"%{search}%"]
            ]

        page = int(page) if page else 1
        page_size = min(int(page_size) if page_size else 50, 100)
        start = (page - 1) * page_size

        counties = frappe.get_all(
            "CountyDashboard",
            filters=filters,
            fields=["name as county_id", "county_name", "login_username", "dashboard_url", "modified"], 
            order_by="county_name asc",
            start=start,
            page_length=page_size
        )

        total = frappe.db.count("CountyDashboard", filters)

        return {
            "counties": counties,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size
        }

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Get All Counties Error")
        frappe.throw(_(str(e)))

# ---
# GET DASHBOARD (EXISTING)
# ---
@frappe.whitelist(allow_guest=True)
def get_dashboard(token, county_id=None):
    try:
        session = session_get(token)
        if not session:
            frappe.throw(_("Not authenticated"))
        target_id = county_id or session.get("county_id")
        if not target_id or target_id == "super":
            frappe.throw(_("Please select a county"))
        county = frappe.db.get_value(
            "CountyDashboard",
            target_id,
            ["name as county_id", "county_name", "dashboard_url"],
            as_dict=True
        )

        if not county:
            frappe.throw(_("County not found"))
        return county
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Get Dashboard Error")
        frappe.throw(_(str(e)))

# ---
# NEW COUNTY MANAGEMENT ENDPOINTS
# ---

# ---
# CREATE COUNTY
# ---
@frappe.whitelist(allow_guest=True)
def create_county(token, name, county_name, login_username, login_password, dashboard_url):
    try:
        session = verify_super_admin(token)

        # Sanitize inputs
        name = sanitize_input(name)
        county_name = sanitize_input(county_name)
        login_username = sanitize_input(login_username).lower()
        dashboard_url = sanitize_input(dashboard_url)

        # Validate data
        validate_county_data({
            "name": name,
            "county_name": county_name,
            "login_username": login_username,
            "login_password": login_password,
            "dashboard_url": dashboard_url
        })

        # Check for duplicates
        if frappe.db.exists("CountyDashboard", name):
            frappe.throw(_("A county with this ID already exists"))

        if frappe.db.exists("CountyDashboard", {"county_name": county_name}):
            frappe.throw(_("A county with this name already exists"))

        if frappe.db.exists("CountyDashboard", {"login_username": login_username}):
            frappe.throw(_("This username is already taken"))

        # Create county document with explicit name
        doc = frappe.get_doc({
            "doctype": "CountyDashboard",
            "name": name,
            "county_name": county_name,
            "login_username": login_username,
            "login_password": login_password,
            "dashboard_url": dashboard_url
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()

        log_security_event("county_created", {
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
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Create County Error")
        frappe.throw(_(str(e)))

# ---
# UPDATE COUNTY
# ---
@frappe.whitelist(allow_guest=True)
def update_county(token, county_id, county_name=None, login_username=None, login_password=None, dashboard_url=None):
    try:
        session = verify_super_admin(token)

        # Check if county exists
        if not frappe.db.exists("CountyDashboard", county_id):
            frappe.throw(_("County not found"))
        
        # Prepare update data
        update_data = {}

        if county_name is not None:
            update_data["county_name"] = sanitize_input(county_name)
        if login_username is not None:
            update_data["login_username"] = sanitize_input(login_username).lower()
        if login_password is not None:
            update_data["login_password"] = login_password
        if dashboard_url is not None:
            update_data["dashboard_url"] = sanitize_input(dashboard_url)

        if not update_data:
            frappe.throw(_("No fields to update"))
        
        # Validate update data
        validate_county_data(update_data, is_update=True)

        # Check for duplicates (excluding current county)
        if "county_name" in update_data:
            existing = frappe.db.exists("CountyDashboard", {
                "county_name": update_data["county_name"],
                "name": ["!=", county_id]
            })
            if existing:
                frappe.throw(_("A county with this name already exists"))
        
        if "login_username" in update_data:
            existing = frappe.db.exists("CountyDashboard", {
                "login_username": update_data["login_username"],
                "name": ["!=", county_id]
            })
            if existing:
                frappe.throw(_("This username is already taken"))

        # Update county
        doc = frappe.get_doc("CountyDashboard", county_id)
        for key, value in update_data.items():
            setattr(doc, key, value)
        doc.save(ignore_permissions=True)
        frappe.db.commit()

        log_security_event("county_updated", {
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

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Update County Error")
        frappe.throw(_(str(e)))

# ---
# DELETE COUNTY
# ---
@frappe.whitelist(allow_guest=True)
def delete_county(token, county_id):
    try:
        session = verify_super_admin(token)

        # Check if county exists
        if not frappe.db.exists("CountyDashboard", county_id):
            frappe.throw(_("County not found"))
        
        # Get county info for logging
        county_name = frappe.db.get_value("CountyDashboard", county_id, "county_name")

        # Delete county
        frappe.delete_doc("CountyDashboard", county_id, ignore_permissions=True)
        frappe.db.commit()

        log_security_event("county_deleted", {
            "admin": session.get("user"),
            "county_id": county_id,
            "county_name": county_name
        })

        return {
            "status": "success",
            "message": "County deleted successfully"
        }

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Delete County Error")
        frappe.throw(_(str(e)))

# ---
# GET COUNTY DETAILS (For Editing)
# ---
@frappe.whitelist(allow_guest=True)
def get_county_details(token, county_id):
    try:
        verify_super_admin(token)

        if not frappe.db.exists("CountyDashboard", county_id):
            frappe.throw(_("County not found"))
        
        county = frappe.get_doc("CountyDashboard", county_id)

        return {
            "county_id": county.name,
            "county_name": county.county_name,
            "login_username": county.login_username,
            "dashboard_url": county.dashboard_url,
            "created": county.creation,
            "modified": county.modified
        }

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Get County Details Error")
        frappe.throw(_(str(e)))