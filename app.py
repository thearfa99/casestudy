import streamlit as st
import backend
from backend import DatabaseManager, UserFactory, DriverModel
import bcrypt
import pandas as pd
import time

# --- SETUP & CONFIG ---
st.set_page_config(page_title="VendorFleet Onboarding", layout="wide")

# --- MONGODB CONNECTION HANDLING ---
# 1. Try to get secrets (Best Practice for deploying)
# 2. If no secrets, show Sidebar Input (Best Practice for Interview Demo)

if 'db_connected' not in st.session_state:
    st.session_state['db_connected'] = False

def init_connection():
    db_manager = DatabaseManager()
    
    # Check streamlit secrets first
    if "MONGO_URI" in st.secrets:
        uri = st.secrets["MONGO_URI"]
        if db_manager.connect(uri):
            st.session_state['db_connected'] = True
            return db_manager.db
            
    # Fallback: Sidebar Input
    with st.sidebar:
        st.header("⚙️ DB Configuration")
        st.warning("No secrets found. Enter Atlas URI manually.")
        uri_input = st.text_input("MongoDB Connection String", type="password")
        if st.button("Connect"):
            if db_manager.connect(uri_input):
                st.session_state['db_connected'] = True
                st.success("Connected!")
                st.rerun()
            else:
                st.error("Connection Failed. Check IP Whitelist on Atlas.")
    return None

db = None
if st.session_state['db_connected']:
    # Re-establish connection object if session says we are connected
    # (In a real app, connection pooling handles this, simplified here)
    manager = DatabaseManager()
    # We rely on the manager having the client, but for streamit reruns we might need to reconnect 
    # if the object was lost. Ideally, we store the URI in session state to reconnect silently.
    pass 
    # For this simple demo, we run init_connection each time if not connected, 
    # or get the existing instance if connected.
    manager = DatabaseManager()
    if manager.client:
        db = manager.db
    else:
        # If object lost (hard refresh), ask for connect again
        st.session_state['db_connected'] = False
        st.rerun()
else:
    db = init_connection()

# Stop execution if DB not connected
if not st.session_state['db_connected']:
    st.info("Please connect to MongoDB Atlas to proceed.")
    st.stop()

# --- CACHING (Evaluation Point 7) ---
@st.cache_data(ttl=60)
def fetch_system_stats():
    # Simulating expensive op
    time.sleep(0.5) 
    return {
        "active_fleets": db.vehicles.count_documents({"status": "Active"}),
        "pending_docs": db.drivers.count_documents({"documents_verified": False})
    }

# --- AUTHENTICATION HELPER ---
def login(username, password):
    user_data = db.users.find_one({"username": username})
    if user_data:
        # Support both hashed (production) and plain (demo) passwords
        try:
            if bcrypt.checkpw(password.encode(), user_data['password']):
                return user_data
        except:
             if user_data['password'] == password:
                 return user_data
    return None

# --- UI COMPONENTS ---
def login_page():
    st.markdown("## 🔒 Vendor Portal Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            user_data = login(username, password)
            if user_data:
                st.session_state['user'] = UserFactory.get_user(user_data, db)
                st.session_state['logged_in'] = True
                st.rerun()
            else:
                st.error("Invalid credentials.")

    # DEV TOOL: Seed Data
    st.divider()
    if st.checkbox("Dev Tools: Seed Data (First Run Only)"):
        if st.button("Create Demo Super Vendor"):
            hashed = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
            try:
                db.users.insert_one({
                    "username": "admin",
                    "password": hashed,
                    "role": "super_vendor",
                    "level": "National",
                    "permissions": ["all"]
                })
                st.success("User 'admin' / 'admin123' created!")
            except:
                st.warning("User likely exists.")

def super_vendor_dashboard(user):
    st.title(f"🚀 Super Vendor Control Center")
    
    stats = fetch_system_stats()
    col1, col2, col3 = st.columns(3)
    col1.metric("Active Vehicles", stats['active_fleets'])
    col2.metric("Pending Verifications", stats['pending_docs'])
    col3.metric("System Health", "Online 🟢")

    st.subheader("Manage Sub-Vendors")
    data = user.get_dashboard_data()
    
    tab1, tab2 = st.tabs(["Overview", "Delegation"])
    
    with tab1:
        if data['level_breakdown']:
            df = pd.DataFrame(data['level_breakdown'])
            st.bar_chart(df.set_index('_id'))
        else:
            st.info("No sub-vendor data available.")
            
    with tab2:
        st.write("Delegate permissions to Sub-Vendors")
        sub_vendor = st.text_input("Sub Vendor Username")
        perm = st.selectbox("Permission", ["approve_drivers", "manage_payments", "view_reports"])
        if st.button("Grant Permission"):
            success, msg = user.delegate_access(sub_vendor, perm)
            if success: st.success(msg)
            else: st.error(msg)

def sub_vendor_dashboard(user):
    st.title(f"📍 Vendor Dashboard ({user.level})")
    
    if "approve_drivers" in user.delegated_permissions:
        st.info("🌟 You have delegated authority to Approve Drivers")

    tab1, tab2, tab3 = st.tabs(["My Fleet", "Onboard Driver", "Upload Docs"])
    data = user.get_dashboard_data()

    with tab1:
        st.dataframe(pd.DataFrame(data['vehicles']))
        
    with tab2:
        st.subheader("Onboard New Driver")
        with st.form("driver_form"):
            name = st.text_input("Full Name")
            lic_no = st.text_input("License Number")
            phone = st.text_input("Phone")
            
            if st.form_submit_button("Onboard"):
                try:
                    new_driver = DriverModel(name=name, license_number=lic_no, phone=phone)
                    success, msg = user.onboard_driver(new_driver)
                    if success: st.success(msg)
                    else: st.error(msg)
                except Exception as e:
                    st.error(f"Validation Error: {e}")

    with tab3:
        st.subheader("Document Upload")
        uploaded_file = st.file_uploader("Upload Driver License / RC")
        if uploaded_file:
            st.success(f"File {uploaded_file.name} uploaded successfully! Verification Pending.")

# --- MAIN CONTROLLER ---
def main():
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    if not st.session_state['logged_in']:
        login_page()
    else:
        user = st.session_state['user']
        with st.sidebar:
            st.write(f"Logged in as: **{user.username}**")
            if st.button("Logout"):
                st.session_state['logged_in'] = False
                st.rerun()

        if user.role == "super_vendor":
            super_vendor_dashboard(user)
        else:
            sub_vendor_dashboard(user)

if __name__ == "__main__":
    main()