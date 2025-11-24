import pymongo
import bcrypt
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import time
import os
import random

# --- CONFIGURATION ---
DEFAULT_URI = "mongodb://localhost:27017/" 
DB_NAME = "vendor_onboarding_db"

# --- HELPER FUNCTIONS ---
def get_mongo_uri_from_secrets():
    """Tries to read MONGO_URI from .streamlit/secrets.toml"""
    secret_path = ".streamlit/secrets.toml"
    if os.path.exists(secret_path):
        try:
            with open(secret_path, "r") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line.startswith("MONGO_URI"):
                        parts = clean_line.split("=", 1)
                        if len(parts) == 2:
                            return parts[1].strip().strip('"').strip("'")
        except: pass
    return None

def get_db_connection():
    uri = get_mongo_uri_from_secrets()
    if not uri:
        print("⚠️ Secrets not found. Falling back to manual input.")
        uri = input(f"Enter MongoDB URI (Press Enter for localhost): ").strip() or DEFAULT_URI
    
    try:
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.server_info()
        print(f"✅ Connected to {DB_NAME}")
        return client[DB_NAME]
    except Exception as e:
        print(f"❌ Connection Failed: {e}")
        return None

def hash_pass(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def create_user(db, username, password, role, level, parent_id, root_id, permissions=[]):
    uid = ObjectId()
    db.users.insert_one({
        "_id": uid,
        "username": username,
        "password": hash_pass(password),
        "role": role,
        "level": level,
        "parent_id": str(parent_id) if parent_id else None,
        "root_id": str(root_id),
        "permissions": permissions,
        "status": "Active",
        "created_at": datetime.now()
    })
    return uid

def create_driver(db, name, lic, phone, days_expiry_offset, vendor_id, root_id, status="Active", verified=True):
    expiry_date = (datetime.now() + timedelta(days=days_expiry_offset)).strftime("%Y-%m-%d")
    db.drivers.insert_one({
        "name": name,
        "license_number": lic,
        "phone": phone,
        "dl_expiry": expiry_date,
        "vendor_id": str(vendor_id),
        "root_id": str(root_id),
        "status": status,
        "documents_verified": verified,
        "onboarded_at": datetime.now()
    })

def create_vehicle(db, reg, model, cap, fuel, days_expiry_offset, vendor_id, root_id, status="Active"):
    expiry_date = (datetime.now() + timedelta(days=days_expiry_offset)).strftime("%Y-%m-%d")
    db.vehicles.insert_one({
        "reg_number": reg,
        "model": model,
        "capacity": cap,
        "fuel_type": fuel,
        "rc_expiry": expiry_date,
        "pollution_expiry": expiry_date,
        "permit_expiry": expiry_date,
        "vendor_id": str(vendor_id),
        "root_id": str(root_id),
        "status": status
    })

# --- MAIN SEEDING LOGIC ---
def seed_database(db):
    print("⚠️  WARNING: This will WIPE the current database.")
    if input("Type 'yes' to proceed: ").lower() != 'yes': return

    db.users.delete_many({})
    db.drivers.delete_many({})
    db.vehicles.delete_many({})
    print("🧹 Database wiped.")

    # ==================================================
    # HIERARCHY 1: Green Fleet Logistics (The Main Demo)
    # ==================================================
    print("🌱 Seeding Green Fleet (National Scale)...")
    
    # 1. ROOT: Super Vendor
    root_id = ObjectId()
    db.users.insert_one({
        "_id": root_id, "username": "Green_Fleet_HQ", "password": hash_pass("admin12345"),
        "role": "super_vendor", "level": "National", "root_id": str(root_id), 
        "permissions": ["all"], "status": "Active", "created_at": datetime.now()
    })

    # --- REGIONS ---
    south_id = create_user(db, "South_India_Ops", "south12345", "vendor", "Regional", root_id, root_id, ["view_reports"])
    north_id = create_user(db, "North_India_Ops", "north12345", "vendor", "Regional", root_id, root_id)
    west_id  = create_user(db, "West_India_Ops",  "west123456", "vendor", "Regional", root_id, root_id)
    east_id  = create_user(db, "East_India_Ops",  "east123456", "vendor", "Regional", root_id, root_id)

    # --- CITIES & LOCALS ---

    # 1. SOUTH BRANCH
    blr_id = create_user(db, "Bangalore_Hub", "blr1234567", "vendor", "City", south_id, root_id, ["manage_payments"])
    hyd_id = create_user(db, "Hyderabad_Hub", "hyd1234567", "vendor", "City", south_id, root_id)
    
    # Locals
    whitefield_id = create_user(db, "Whitefield_Local", "local12345", "vendor", "Local", blr_id, root_id)
    hitech_id = create_user(db, "Hitech_City_Local", "local12345", "vendor", "Local", hyd_id, root_id)

    # 2. NORTH BRANCH
    del_id = create_user(db, "Delhi_NCR_Hub", "del1234567", "vendor", "City", north_id, root_id)
    gurgaon_id = create_user(db, "Gurgaon_Local", "local12345", "vendor", "Local", del_id, root_id)

    # 3. WEST BRANCH
    mum_id = create_user(db, "Mumbai_Hub", "mum1234567", "vendor", "City", west_id, root_id)
    pune_id = create_user(db, "Pune_Hub", "pun1234567", "vendor", "City", west_id, root_id)
    
    andheri_id = create_user(db, "Andheri_Local", "local12345", "vendor", "Local", mum_id, root_id)
    hinjewadi_id = create_user(db, "Hinjewadi_Local", "local12345", "vendor", "Local", pune_id, root_id)

    # 4. EAST BRANCH
    kol_id = create_user(db, "Kolkata_Hub", "kol1234567", "vendor", "City", east_id, root_id)
    saltlake_id = create_user(db, "Salt_Lake_Local", "local12345", "vendor", "Local", kol_id, root_id)

    # --- FLEET DATA ---

    # A. WHITEFIELD (EV Powerhouse)
    print("   -> Populating Whitefield (EVs)...")
    for i in range(1, 8):
        create_vehicle(db, f"KA-53-EV-{100+i}", "Tata Nexon EV", 4, "EV", 600, whitefield_id, root_id)
        create_driver(db, f"EV Pilot {i}", f"DL-EV-{100+i}", "9900000000", 400, whitefield_id, root_id)

    # B. GURGAON (High Volume Pending)
    print("   -> Populating Gurgaon (Pending Approvals)...")
    for i in range(1, 6):
        create_driver(db, f"Pending Driver {i}", f"HR-26-P-{i}", "9666666666", 300, gurgaon_id, root_id, "Pending", False)
        create_vehicle(db, f"HR-26-CNG-{200+i}", "Maruti Ertiga", 7, "CNG", 300, gurgaon_id, root_id)

    # C. MUMBAI (CNG Fleet & Revoked Driver)
    print("   -> Populating Mumbai (CNG & Compliance)...")
    create_vehicle(db, "MH-01-C-900", "WagonR CNG", 4, "CNG", 200, andheri_id, root_id)
    create_vehicle(db, "MH-01-C-901", "WagonR CNG", 4, "CNG", 200, andheri_id, root_id)
    # Revoked Driver to show status feature
    create_driver(db, "Bad Driver (Revoked)", "MH-BAD-00", "9000000000", 100, andheri_id, root_id, "Revoked", True)
    
    # D. PUNE (Hybrid Tech)
    print("   -> Populating Pune (Hybrids)...")
    create_vehicle(db, "MH-12-H-777", "Honda City Hybrid", 4, "Hybrid", 400, hinjewadi_id, root_id)
    create_vehicle(db, "MH-12-H-888", "Toyota Hyryder", 5, "Hybrid", 400, hinjewadi_id, root_id)
    create_driver(db, "Pune Pro 1", "MH-12-GOOD", "9222222222", 200, hinjewadi_id, root_id)

    # E. KOLKATA (Old Fleet / Suspended)
    print("   -> Populating Kolkata (Legacy)...")
    create_vehicle(db, "WB-01-D-1990", "Ambassador", 4, "Diesel", 50, saltlake_id, root_id)
    # Suspended Driver
    create_driver(db, "Suspended User", "WB-SUS-01", "8000000000", 20, saltlake_id, root_id, "Suspended", True)

    # F. HITECH CITY (Mixed & Expired)
    print("   -> Populating Hyderabad (Expired Docs)...")
    create_vehicle(db, "TS-09-P-111", "Hyundai Aura", 4, "Petrol", 20, hitech_id, root_id)
    # Expired License
    create_driver(db, "Expired User", "TS-OLD-00", "8888888888", -10, hitech_id, root_id, "Active", True)

    print("\n✅ SEEDING COMPLETE! National Demo Ready.")
    print("------------------------------------------------")
    print("1. GREEN FLEET HQ (admin12345) -> See National Analytics")
    print("2. SOUTH OPS (south12345) -> See Bangalore/Hyd Only")
    print("3. WEST OPS (west123456) -> See Mumbai/Pune Only")
    print("------------------------------------------------")

if __name__ == "__main__":
    db = get_db_connection()
    if db is not None:
        seed_database(db)