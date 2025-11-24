import pymongo
import bcrypt
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import os

DEFAULT_URI = "mongodb://localhost:27017/"
DB_NAME = "vendor_onboarding_db"

def get_connection():
    uri = DEFAULT_URI
    if os.path.exists(".streamlit/secrets.toml"):
        with open(".streamlit/secrets.toml") as f:
            for l in f:
                if "MONGO_URI" in l: uri = l.split("=", 1)[1].strip().strip('"')
    try: return pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)[DB_NAME]
    except: return None

def hash_p(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt())

def seed(db):
    print("Wiping DB...")
    db.users.delete_many({}); db.drivers.delete_many({}); db.vehicles.delete_many({})
    
    print("Creating Green Fleet (National)...")
    rid = ObjectId()
    db.users.insert_one({"_id": rid, "username": "Green_Fleet_HQ", "password": hash_p("admin12345"), "role": "super_vendor", "level": "National", "root_id": str(rid), "permissions": ["all"], "status": "Active"})
    
    # Regions
    sid = ObjectId(); db.users.insert_one({"_id": sid, "username": "South_India_Ops", "password": hash_p("south123"), "role": "vendor", "level": "Regional", "parent_id": str(rid), "root_id": str(rid), "permissions": ["view_reports"]})
    nid = ObjectId(); db.users.insert_one({"_id": nid, "username": "North_India_Ops", "password": hash_p("north123"), "role": "vendor", "level": "Regional", "parent_id": str(rid), "root_id": str(rid), "permissions": []})

    # Cities
    bid = ObjectId(); db.users.insert_one({"_id": bid, "username": "Bangalore_Hub", "role": "vendor", "level": "City", "parent_id": str(sid), "root_id": str(rid), "permissions": ["manage_payments"]})
    did = ObjectId(); db.users.insert_one({"_id": did, "username": "Delhi_Hub", "role": "vendor", "level": "City", "parent_id": str(nid), "root_id": str(rid)})

    # Locals
    wid = ObjectId(); db.users.insert_one({"_id": wid, "username": "Whitefield_Local", "role": "vendor", "level": "Local", "parent_id": str(bid), "root_id": str(rid)})
    gid = ObjectId(); db.users.insert_one({"_id": gid, "username": "Gurgaon_Local", "role": "vendor", "level": "Local", "parent_id": str(did), "root_id": str(rid)})

    # Assets
    # Whitefield (EVs)
    for i in range(5):
        db.vehicles.insert_one({"reg_number": f"EV-{i}", "fuel_type": "EV", "vendor_id": str(wid), "root_id": str(rid), "status": "Active"})
        db.drivers.insert_one({"name": f"EV Driver {i}", "license_number": f"DL-{i}", "phone": "9999999999", "dl_expiry": "2030-01-01", "vendor_id": str(wid), "root_id": str(rid), "status": "Active", "documents_verified": True})

    # Gurgaon (Pending & Expired)
    db.drivers.insert_one({"name": "Pending Guy", "license_number": "PEND-01", "phone": "888", "dl_expiry": "2030-01-01", "vendor_id": str(gid), "root_id": str(rid), "status": "Pending", "documents_verified": False})
    db.drivers.insert_one({"name": "Expired Guy", "license_number": "EXP-01", "phone": "777", "dl_expiry": "2020-01-01", "vendor_id": str(gid), "root_id": str(rid), "status": "Active", "documents_verified": True})

    print("✅ Seeded. Login: Green_Fleet_HQ / admin12345")

if __name__ == "__main__":
    db = get_connection()
    if db: seed(db)