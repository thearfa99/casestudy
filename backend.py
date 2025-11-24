import pymongo
from pymongo.errors import ServerSelectionTimeoutError, ConfigurationError
import bcrypt
from abc import ABC, abstractmethod
from datetime import datetime, date
from typing import List, Optional, Dict
import time
import logging
from bson.objectid import ObjectId
from pydantic import BaseModel, Field, validator
from collections import Counter

# --- LOGGING ---
logging.basicConfig(
    filename='system.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- UPDATED MODELS WITH STRICT VALIDATION ---
class DriverModel(BaseModel):
    # strip_whitespace=True ensures "   " is treated as empty and fails validation
    name: str = Field(..., min_length=1, strip_whitespace=True)
    license_number: str = Field(..., min_length=5, strip_whitespace=True)
    phone: str = Field(..., min_length=10, max_length=15, strip_whitespace=True)
    dl_expiry: str = Field(..., min_length=10, strip_whitespace=True) # Expecting YYYY-MM-DD
    status: str = "Inactive"
    documents_verified: bool = False

    @validator('phone')
    def phone_must_be_digits(cls, v):
        if not v.isdigit():
            raise ValueError('Phone number must contain only digits')
        return v

class VehicleModel(BaseModel):
    reg_number: str = Field(..., min_length=4, strip_whitespace=True)
    model: str = Field(..., min_length=2, strip_whitespace=True)
    capacity: int = Field(..., gt=0) # Capacity must be greater than 0
    fuel_type: str = Field(..., min_length=2, strip_whitespace=True)
    rc_expiry: str = Field(..., min_length=10)
    pollution_expiry: str = Field(..., min_length=10)
    permit_expiry: str = Field(..., min_length=10)
    vendor_id: Optional[str] = None
    assigned_driver_id: Optional[str] = None
    status: str = "Inactive"

# --- DATABASE CONNECTION ---
class DatabaseManager:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance.client = None; cls._instance.db = None
        return cls._instance

    def connect(self, uri, db_name="vendor_onboarding_db"):
        try:
            self.client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
            self.client.server_info() 
            self.db = self.client[db_name]
            logging.info("Database connected successfully.")
            return True
        except Exception as e:
            logging.error(f"DB Error: {e}")
            return False

# --- PUBLIC REGISTRATION FUNCTION (Updated) ---
def register_new_super_vendor(username, password, db):
    """Allows a new Super Vendor to sign up with strict checks."""
    # 1. Empty / Whitespace Check
    if not username or not username.strip():
        return False, "Username cannot be empty."
    
    if not password or not password.strip():
        return False, "Password cannot be empty."

    # 2. Minimum Length Check
    if len(password) < 7:
        return False, "Password must be at least 7 characters long."
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters long."

    # 3. Duplicate Check
    if db.users.find_one({"username": username}):
        return False, "Username already taken."
    
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_id = ObjectId()
    
    user_doc = {
        "_id": new_id,
        "username": username,
        "password": hashed,
        "role": "super_vendor",
        "level": "National",
        "root_id": str(new_id),
        "permissions": ["all"],
        "created_at": datetime.now(),
        "status": "Active"
    }
    db.users.insert_one(user_doc)
    logging.info(f"New Super Vendor registered: {username}")
    return True, "Registration successful! Please login."

# --- OOPS ARCHITECTURE ---
class SystemUser(ABC):
    def __init__(self, username, role, db_handle):
        self.username = username
        self.role = role
        self.db = db_handle

    @abstractmethod
    def get_dashboard_data(self):
        pass

    def verify_password(self, plain_password, hashed_password):
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)
        except: return plain_password == hashed_password

    def check_compliance(self, date_str):
        try:
            exp_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            if exp_date < date.today(): return False
            return True
        except ValueError: return False

# INHERITANCE: Vendor Logic
# --- INHERITANCE: Vendor Logic ---
class Vendor(SystemUser):
    def __init__(self, data, db_handle):
        super().__init__(data['username'], data['role'], db_handle)
        self.user_id = str(data['_id'])
        self.level = data.get('level', 'local')
        self.parent_id = data.get('parent_id')
        self.root_id = data.get('root_id', self.user_id) 
        self.delegated_permissions = data.get('permissions', [])

    # NEW HELPER: Recursively get all IDs in my downline
    def _get_subtree_ids(self, current_id):
        direct_children = list(self.db.users.find({"parent_id": current_id}))
        ids = []
        for child in direct_children:
            c_id = str(child['_id'])
            ids.append(c_id)
            # Recursion to get children of children
            ids.extend(self._get_subtree_ids(c_id))
        return ids

    def get_dashboard_data(self):
        # 1. Get all vendor IDs in my network (Me + Descendants)
        network_ids = self._get_subtree_ids(self.user_id)
        all_relevant_ids = [self.user_id] + network_ids

        # 2. Create a Map of ID -> Username for display purposes
        # We fetch user docs for everyone in the list to map names later
        relevant_users = list(self.db.users.find({"_id": {"$in": [ObjectId(i) for i in all_relevant_ids]}}))
        id_name_map = {str(u['_id']): u['username'] for u in relevant_users}

        # 3. Fetch Vehicles and Drivers for the WHOLE network
        vehicles = list(self.db.vehicles.find({"vendor_id": {"$in": all_relevant_ids}}))
        drivers = list(self.db.drivers.find({"vendor_id": {"$in": all_relevant_ids}}))

        # 4. Enrich Drivers with "Owner Name" so UI knows if it's yours or a sub-vendor's
        for d in drivers:
            d_vid = d.get('vendor_id')
            d['owner_name'] = "Me" if d_vid == self.user_id else id_name_map.get(d_vid, "Sub-Vendor")

        data = {
            "vehicles": vehicles,
            "drivers": drivers,
            # Direct children only (for the Manage Sub-Vendors tab)
            "sub_vendors": list(self.db.users.find({"parent_id": self.user_id})),
            "total_network_drivers": len(drivers), # Added this key for app.py
            "my_level": self.level
        }
        return data

    def create_sub_vendor(self, username, password, sub_level):
        if not username.strip(): return False, "Username cannot be empty."
        if len(password) < 7: return False, "Password must be at least 7 characters."

        hierarchy_map = {"National": "Regional", "Regional": "City", "City": "Local"}
        
        if self.role != 'super_vendor':
            allowed_child = hierarchy_map.get(self.level)
            if sub_level != allowed_child:
                return False, f"A {self.level} vendor can only create {allowed_child} vendors."

        if self.db.users.find_one({"username": username}):
            return False, "Username already exists."
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_doc = {
            "username": username, 
            "password": hashed, 
            "role": "vendor", 
            "level": sub_level, 
            "parent_id": self.user_id,
            "root_id": self.root_id,
            "permissions": [],
            "created_at": datetime.now(),
            "status": "Active"
        }
        self.db.users.insert_one(user_doc)
        logging.info(f"{self.username} created sub-vendor {username}")
        return True, f"Vendor {username} ({sub_level}) created."
    
    def onboard_driver(self, driver_data: DriverModel):
        try:
            driver_dict = driver_data.dict()
            
            # --- NEW: UNIQUENESS CHECKS ---
            # 1. Check if License Number exists
            if self.db.drivers.find_one({"license_number": driver_dict['license_number']}):
                return False, f"Driver with License {driver_dict['license_number']} already exists!"

            # 2. Check if Phone Number exists
            if self.db.drivers.find_one({"phone": driver_dict['phone']}):
                return False, f"Driver with Phone {driver_dict['phone']} already exists!"
            # -------------------------------

            if not self.check_compliance(driver_dict['dl_expiry']):
                return False, "Cannot onboard: Driving License is Expired!"

            driver_dict['vendor_id'] = self.user_id
            driver_dict['root_id'] = self.root_id
            driver_dict['onboarded_at'] = datetime.now()
            self.db.drivers.insert_one(driver_dict)
            return True, "Driver onboarded successfully."
        except Exception as e:
            return False, f"Validation Error: {str(e)}"

    def onboard_vehicle(self, vehicle_data: VehicleModel):
        try:
            v_dict = vehicle_data.dict()
            
            # --- NEW: UNIQUENESS CHECK ---
            # 1. Check if Registration Number exists
            if self.db.vehicles.find_one({"reg_number": v_dict['reg_number']}):
                return False, f"Vehicle {v_dict['reg_number']} is already registered!"
            # -----------------------------

            if not all([
                self.check_compliance(v_dict['rc_expiry']),
                self.check_compliance(v_dict['pollution_expiry']),
                self.check_compliance(v_dict['permit_expiry'])
            ]):
                return False, "Cannot onboard: One or more vehicle documents are Expired!"

            v_dict['vendor_id'] = self.user_id
            v_dict['root_id'] = self.root_id
            self.db.vehicles.insert_one(v_dict)
            return True, "Vehicle onboarded successfully."
        except Exception as e:
            return False, f"Validation Error: {str(e)}"
        
    def update_driver_status(self, driver_id, new_status):
        try:
            # 1. Get complete list of valid IDs (Me + My Sub-vendors)
            # This ensures you can act on drivers deep in your hierarchy
            hierarchy_ids = self._get_subtree_ids(self.user_id)
            valid_vendor_ids = [self.user_id] + hierarchy_ids
            
            # 2. Update ONLY if the driver belongs to your hierarchy
            # We match _id AND verify the vendor_id is in your allowed list
            result = self.db.drivers.update_one(
                {
                    "_id": ObjectId(driver_id),
                    "vendor_id": {"$in": valid_vendor_ids}
                },
                {"$set": {"status": new_status}}
            )
            
            if result.matched_count > 0:
                return True, f"Driver status updated to {new_status}."
            else:
                return False, "Driver not found in your hierarchy."
                
        except Exception as e:
            return False, f"Error updating status: {str(e)}"

# INHERITANCE: Super Vendor Logic
# --- INHERITANCE: Super Vendor Logic ---
class SuperVendor(Vendor):
    def get_dashboard_data(self):
        # 1. Fetch Hierarchy
        my_network = list(self.db.users.find({"root_id": self.user_id, "role": "vendor"}))
        
        # 2. Create ID -> Name Map
        id_to_name = {self.user_id: self.username}
        for u in my_network:
            id_to_name[str(u['_id'])] = u['username']
            
        # Enrich parent names
        for u in my_network:
            pid = u.get('parent_id')
            u['parent_name'] = id_to_name.get(pid, "Unknown")

        # 3. Fetch Fleet Data
        network_ids = [str(u['_id']) for u in my_network]
        network_ids.append(self.user_id)
        
        vehicles = list(self.db.vehicles.find({"vendor_id": {"$in": network_ids}}))
        drivers = list(self.db.drivers.find({"vendor_id": {"$in": network_ids}}))
        
        # --- ADVANCED ANALYTICS ENGINE ---
        
        # A. Drivers per Vendor
        driver_counts = Counter()
        for d in drivers:
            v_name = id_to_name.get(d.get('vendor_id'), 'Unknown Vendor')
            driver_counts[v_name] += 1
            
        # B. Vehicle Status & Fuel
        vehicle_status = Counter([v.get('status', 'Inactive') for v in vehicles])
        fuel_stats = Counter([v.get('fuel_type', 'Unknown') for v in vehicles])
        
        # C. Driver Compliance (Expired Licenses)
        expired_drivers = [d for d in drivers if not self.check_compliance(d.get('dl_expiry', '2000-01-01'))]
        for d in expired_drivers:
             d['owner_name'] = id_to_name.get(d.get('vendor_id'), "Unknown")

        # D. NEW: Vehicle Compliance (Expired RC/Pollution/Permit) 
        non_compliant_vehicles = []
        for v in vehicles:
            issues = []
            if not self.check_compliance(v.get('rc_expiry', '2000-01-01')): issues.append("RC Expired")
            if not self.check_compliance(v.get('pollution_expiry', '2000-01-01')): issues.append("Pollution Expired")
            if not self.check_compliance(v.get('permit_expiry', '2000-01-01')): issues.append("Permit Expired")
            
            if issues:
                v['compliance_issues'] = ", ".join(issues)
                v['owner_name'] = id_to_name.get(v.get('vendor_id'), "Unknown")
                non_compliant_vehicles.append(v)
        
        return {
            "total_vendors": len(my_network),
            "total_vehicles": len(vehicles),
            "sub_vendors_list": my_network,
            "compliance_issues_count": len(expired_drivers) + len(non_compliant_vehicles),
            "expired_driver_list": expired_drivers,
            "non_compliant_vehicles": non_compliant_vehicles, # New Data Point
            "analytics": {
                "drivers_by_vendor": dict(driver_counts),
                "vehicle_status": dict(vehicle_status),
                "fuel_stats": dict(fuel_stats),
                "total_drivers": len(drivers)
            }
        }

    # Keep existing methods...
    def delegate_access(self, sub_vendor_username, permission):
        result = self.db.users.update_one(
            {"username": sub_vendor_username, "root_id": self.user_id},
            {"$addToSet": {"permissions": permission}}
        )
        return (True, "Permission granted") if result.modified_count > 0 else (False, "User not found")

    def suspend_vendor(self, vendor_id):
        self.db.users.update_one(
            {"_id": ObjectId(vendor_id), "root_id": self.user_id}, 
            {"$set": {"status": "Suspended"}}
        )
        return True, "Vendor Suspended."

    def disable_vehicle(self, vehicle_id):
        self.db.vehicles.update_one({"_id": ObjectId(vehicle_id)}, {"$set": {"status": "Disabled"}})
        return True, "Vehicle Operations Disabled."
        
    def get_pending_drivers(self):
        my_network = list(self.db.users.find({"root_id": self.user_id}))
        ids = [str(u['_id']) for u in my_network]
        return list(self.db.drivers.find({"vendor_id": {"$in": ids}, "documents_verified": False}))

    def approve_driver(self, driver_id):
        self.db.drivers.update_one(
            {"_id": ObjectId(driver_id)},
            {"$set": {"documents_verified": True, "status": "Active"}}
        )
        return True, "Driver Approved."

class UserFactory:
    @staticmethod
    def get_user(user_data, db_handle):
        if user_data.get('status') == 'Suspended':
            return None 
            
        if user_data.get('role') == 'super_vendor':
            return SuperVendor(user_data, db_handle)
        elif user_data.get('role') == 'vendor':
            return Vendor(user_data, db_handle)
        return None