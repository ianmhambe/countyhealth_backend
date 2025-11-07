import frappe
import uuid
from frappe import _

# -------------------------------
# TOKEN SESSION HELPERS (REDIS)
# -------------------------------
def session_set(token, data):
    """Store session data in cache as JSON string"""
    frappe.cache().setex(f"session_{token}", 3600, frappe.as_json(data))  # 1 hour

def session_get(token):
    """Retrieve and parse session data from cache"""
    data = frappe.cache().get(f"session_{token}")
    if data:
        # If data is bytes, decode it first
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return frappe.parse_json(data)
    return None

def session_delete(token):
    """Delete session from cache"""
    frappe.cache().delete_value(f"session_{token}")

# -------------------------------
# LOGIN
# -------------------------------
@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        username = username.strip().lower()
        
        # Check for superadmin
        if username == "superadmin" and password == "SuperAdmin@2025":
            token = str(uuid.uuid4())
            session_set(token, {
                "user": username,
                "is_super_user": True,
                "county_id": "super",
                "county_name": "All Counties"
            })
            
            return {
                "status": "success",
                "token": token,
                "is_super_user": True,
                "county_id": "super",
                "county_name": "All Counties",
                "dashboard_url": None
            }
        
        # Regular county login using get_password for security
        counties = frappe.get_all(
            "CountyDashboard",
            filters={"login_username": username},
            fields=["name", "county_name", "dashboard_url"]
        )
        
        if not counties:
            frappe.throw(_("Invalid username or password"))
        
        county = counties[0]
        county_doc = frappe.get_doc("CountyDashboard", county.name)
        stored_password = county_doc.get_password("login_password")
        
        if stored_password != password:
            frappe.throw(_("Invalid username or password"))
        
        token = str(uuid.uuid4())
        session_set(token, {
            "user": username,
            "is_super_user": False,
            "county_id": county.name,
            "county_name": county.county_name,
            "dashboard_url": county.dashboard_url
        })
        
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

# -------------------------------
# LOGOUT
# -------------------------------
@frappe.whitelist(allow_guest=True)
def logout(token):
    try:
        session_delete(token)
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------
# GET ALL COUNTIES (Super Admin)
# -------------------------------
@frappe.whitelist(allow_guest=True)
def get_all_counties(token):
    try:
        session = session_get(token)
        if not session:
            frappe.throw(_("Not authenticated"))
        
        if not session.get("is_super_user"):
            frappe.throw(_("Unauthorized. Super admin access required."))
        
        counties = frappe.get_all(
            "CountyDashboard",
            fields=["name as county_id", "county_name", "dashboard_url"],
            order_by="county_name asc"
        )
        
        return counties
        
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Get All Counties Error")
        frappe.throw(_(str(e)))

# -------------------------------
# GET DASHBOARD FOR COUNTY
# -------------------------------
@frappe.whitelist(allow_guest=True)
def get_dashboard(token, county_id=None):
    try:
        session = session_get(token)
        if not session:
            frappe.throw(_("Not authenticated"))
        
        # If super admin switches county
        target_id = county_id or session.get("county_id")
        
        if not target_id or target_id == "super":
            frappe.throw(_("Please select a county"))
        
        # Get county data
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