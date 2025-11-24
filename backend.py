import pymongo
from pymongo.errors import ServerSelectionTimeoutError, ConfigurationError
import bcrypt
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict
import time
import logging
from bson.objectid import ObjectId

# --- LOGGING (Evaluation Point 6: System Monitoring) ---
logging.basicConfig(
    filename='system.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

from pydantic import BaseModel, Field

class DriverModel(BaseModel):
    name: str
    license_number: str
    phone: str
    status: str = "Active"
    documents_verified: bool = False

class VehicleModel(BaseModel):
    reg_number: str
    model: str
    capacity: int
    fuel_type: str
    assigned_driver_id: Optional[str] = None

# --- DATABASE CONNECTION (Evaluation Point 3: Handling System Failure) ---
class DatabaseManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance.client = None
            cls._instance.db = None
        return cls._instance

    def connect(self, uri, db_name="vendor_onboarding_db"):
        """
        Connects to MongoDB (Atlas or Local).
        Increased timeout for cloud latency.
        """
        try:
            # serverSelectionTimeoutMS=5000 (5s) gives Atlas time to respond
            self.client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
            
            # Force a connection check to fail fast if URI is wrong
            self.client.server_info() 
            
            self.db = self.client[db_name]
            logging.info("Database connected successfully.")
            return True
        except (ServerSelectionTimeoutError, ConfigurationError) as e:
            logging.error(f"Database connection failed: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected DB Error: {e}")
            return False

# --- OOPS ARCHITECTURE (Evaluation Point 4: OOPS Principles) ---

class SystemUser(ABC):
    def __init__(self, username, role, db_handle):
        self.username = username
        self.role = role
        self.db = db_handle

    @abstractmethod
    def get_dashboard_data(self):
        pass

    def verify_password(self, plain_password, hashed_password):
        # Handle cases where password might be plain text (legacy/demo data)
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)
        except TypeError:
            return plain_password == hashed_password

# INHERITANCE: Specific Vendor Logic
class Vendor(SystemUser):
    def __init__(self, data, db_handle):
        super().__init__(data['username'], data['role'], db_handle)
        self.user_id = str(data['_id'])
        self.level = data.get('level', 'local')
        self.parent_id = data.get('parent_id')
        self.delegated_permissions = data.get('permissions', [])

    def get_dashboard_data(self):
        start_time = time.time()
        
        # Standard query for local fleet
        data = {
            "vehicles": list(self.db.vehicles.find({"vendor_id": self.user_id})),
            "drivers": list(self.db.drivers.find({"vendor_id": self.user_id})),
            "sub_vendors": list(self.db.users.find({"parent_id": self.user_id}))
        }
        
        exec_time = time.time() - start_time
        logging.info(f"Dashboard fetch for {self.username} took {exec_time:.4f}s")
        return data

    def onboard_driver(self, driver_data: DriverModel):
        try:
            driver_dict = driver_data.dict()
            driver_dict['vendor_id'] = self.user_id
            driver_dict['onboarded_at'] = datetime.now()
            self.db.drivers.insert_one(driver_dict)
            logging.info(f"Driver {driver_dict['name']} onboarded by {self.username}")
            return True, "Driver onboarded successfully."
        except Exception as e:
            logging.error(f"Error onboarding driver: {str(e)}")
            return False, f"System Error: {str(e)}"

# INHERITANCE: Super Vendor Logic
class SuperVendor(Vendor):
    def get_dashboard_data(self):
        # Aggregation Pipeline for efficient Global Stats
        pipeline = [
            {"$match": {"role": {"$ne": "super_admin"}}},
            {"$group": {"_id": "$level", "count": {"$sum": 1}}}
        ]
        stats = list(self.db.users.aggregate(pipeline))
        
        return {
            "total_vendors": self.db.users.count_documents({"role": "vendor"}),
            "total_vehicles": self.db.vehicles.count_documents({}),
            "total_drivers": self.db.drivers.count_documents({}),
            "level_breakdown": stats,
            "sub_vendors_list": list(self.db.users.find({"role": "vendor"}))
        }

    def create_sub_vendor(self, username, password, level):
        try:
            # Check if exists
            if self.db.users.find_one({"username": username}):
                return False, "Username already exists."
            
            # Hash password
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            user_doc = {
                "username": username,
                "password": hashed,
                "role": "vendor",
                "level": level,
                "parent_id": self.user_id, # Linking hierarchy
                "permissions": [],
                "created_at": datetime.now()
            }
            self.db.users.insert_one(user_doc)
            logging.info(f"SuperVendor {self.username} created new vendor {username}")
            return True, f"Vendor '{username}' created successfully."
        except Exception as e:
            logging.error(f"Error creating vendor: {e}")
            return False, str(e)

    def delegate_access(self, sub_vendor_username, permission):
        try:
            result = self.db.users.update_one(
                {"username": sub_vendor_username},
                {"$addToSet": {"permissions": permission}}
            )
            if result.modified_count > 0:
                return True, "Permission granted."
            return False, "User not found or permission already exists."
        except Exception as e:
            return False, str(e)

    def get_pending_drivers(self):
        """Fetch all drivers across the system who are not verified yet."""
        # This demonstrates 'Super Vendor Visibility' (Case Study Point IV)
        return list(self.db.drivers.find({"documents_verified": False}))

    def approve_driver(self, driver_id):
        """Override/Action control to approve a driver."""
        try:
            result = self.db.drivers.update_one(
                {"_id": ObjectId(driver_id)},
                {"$set": {"documents_verified": True, "status": "Active"}}
            )
            if result.modified_count > 0:
                logging.info(f"SuperVendor {self.username} approved driver {driver_id}")
                return True, "Driver approved successfully."
            return False, "Driver not found."
        except Exception as e:
            logging.error(f"Error approving driver: {e}")
            return False, str(e)

# Factory Pattern
class UserFactory:
    @staticmethod
    def get_user(user_data, db_handle):
        if user_data.get('role') == 'super_vendor':
            return SuperVendor(user_data, db_handle)
        elif user_data.get('role') == 'vendor':
            return Vendor(user_data, db_handle)
        return None