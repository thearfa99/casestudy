import streamlit as st
import backend
from backend import DatabaseManager, UserFactory, DriverModel, VehicleModel, register_new_super_vendor
import bcrypt
import pandas as pd
import time
from datetime import datetime
from bson.objectid import ObjectId

st.set_page_config(page_title="VendorFleet Ultimate", layout="wide")

# --- DB CONNECTION ---
if 'db_connected' not in st.session_state:
    st.session_state['db_connected'] = False

def init_connection():
    db_manager = DatabaseManager()
    if "MONGO_URI" in st.secrets:
        if db_manager.connect(st.secrets["MONGO_URI"]):
            st.session_state['db_connected'] = True
            return db_manager.db
    with st.sidebar:
        st.header("Database Connection")
        uri = st.text_input("Enter Mongo URI", type="password")
        if st.button("Connect"): 
            if db_manager.connect(uri):
                st.session_state['db_connected'] = True
                st.rerun()
            else:
                st.error("Connection failed.")
    return None

if st.session_state['db_connected']:
    db = DatabaseManager().db
else:
    db = init_connection()
    if db is None: 
        st.info("Please connect to the database to proceed.")
        st.stop()

# --- AUTH ---
def login_page():
    st.markdown("## 🚖 Fleet System Access")
    
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Register Super Vendor"])
    
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Login"):
                user_data = db.users.find_one({"username": username})
                if user_data:
                    user_obj = UserFactory.get_user(user_data, db)
                    if user_obj:
                        if user_obj.verify_password(password, user_data['password']):
                            st.session_state['user'] = user_obj
                            st.session_state['logged_in'] = True
                            st.rerun()
                        else: st.error("Wrong password")
                    else: st.error("Account Suspended or Invalid Role.")
                else: st.error("User not found")

    with tab2:
        st.info("Start a new isolated fleet hierarchy. Password must be 7+ characters.")
        with st.form("register_form"):
            new_u = st.text_input("Choose Username")
            new_p = st.text_input("Choose Password", type="password", help="Min 7 chars")
            
            if st.form_submit_button("Sign Up as Super Vendor"):
                # UI-side quick check, backend has full check
                success, msg = register_new_super_vendor(new_u, new_p, db)
                if success:
                    st.success(msg)
                else:
                    st.error(msg)

    st.divider()
    with st.expander("Dev Tools (Seed Data)"):
        if st.button("Seed Default Admin"):
            hashed = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
            new_id = ObjectId()
            try:
                db.users.insert_one({
                    "_id": new_id,
                    "username": "admin", "password": hashed,
                    "role": "super_vendor", "level": "National",
                    "root_id": str(new_id),
                    "status": "Active", "permissions": ["all"]
                })
                st.success("Created admin/admin123")
            except: st.warning("Admin likely exists.")

# --- SUPER VENDOR UI ---
def super_vendor_dashboard(user):
    st.title(f"🚀 {user.username}'s Command Center")
    
    data = user.get_dashboard_data()
    analytics = data.get('analytics', {}) # Safe get
    
    # Top Metrics Row
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Vehicles", data['total_vehicles'])
    c2.metric("Total Drivers", analytics.get('total_drivers', 0))
    c3.metric("Sub-Vendors", data['total_vendors'])
    c4.metric("Compliance Alerts", data['compliance_issues'], delta_color="inverse")

    # --- NEW TABS LAYOUT ---
    tabs = st.tabs(["📊 Analytics", "Network", "Overrides", "Approvals", "Delegation"])

    with tabs[0]:
        st.subheader("Fleet Operations Overview")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🚙 Drivers per Vendor (Load Distribution)")
            if analytics.get('drivers_by_vendor'):
                # Streamlit bar chart expects a dict or dataframe
                st.bar_chart(analytics['drivers_by_vendor'])
            else:
                st.info("No driver data available.")
                
        with col2:
            st.markdown("### ⛽ Fleet Fuel Composition")
            if analytics.get('fuel_stats'):
                # Simple dataframe for cleaner display of categorical data
                df_fuel = pd.DataFrame.from_dict(analytics['fuel_stats'], orient='index', columns=['Count'])
                st.dataframe(df_fuel, use_container_width=True)
                # Or a bar chart if preferred
                st.bar_chart(analytics['fuel_stats'])
            else:
                st.info("No vehicle data available.")

        st.markdown("### 🚦 Vehicle Operational Status")
        if analytics.get('vehicle_status'):
            # Display as status metrics row
            status_cols = st.columns(len(analytics['vehicle_status']))
            for i, (status, count) in enumerate(analytics['vehicle_status'].items()):
                status_cols[i].metric(label=status, value=count)
        else:
            st.info("No vehicle status data.")

    with tabs[1]:
        st.subheader("Sub-Vendor Network")
        if data['sub_vendors_list']:
            df = pd.DataFrame(data['sub_vendors_list'])
            if 'status' not in df.columns: df['status'] = 'Active'
            if 'parent_name' not in df.columns: df['parent_name'] = 'N/A'
            st.dataframe(df[['username', 'level', 'status', 'parent_name']])
        else:
            st.info("No sub-vendors in your network.")
        
        st.subheader("Register New Top-Level Vendor")
        with st.form("super_create"):
            u = st.text_input("Username"); p = st.text_input("Password", type="password", help="Min 7 chars")
            l = st.selectbox("Level", ["Regional", "City"])
            if st.form_submit_button("Create"):
                s, m = user.create_sub_vendor(u, p, l)
                if s: st.success(m); time.sleep(1); st.rerun()
                else: st.error(m)

    with tabs[2]:
        st.subheader("🚨 Compliance & Override Actions")
        if data['sub_vendors_list']:
            v_list = [u for u in data['sub_vendors_list'] if u.get('status', 'Active') == 'Active']
            if v_list:
                sus_target = st.selectbox("Select Vendor to Suspend", [u['username'] for u in v_list])
                if st.button("⛔ Suspend Vendor Access"):
                    target_id = next(u['_id'] for u in v_list if u['username'] == sus_target)
                    s, m = user.suspend_vendor(target_id)
                    if s: st.success(m); st.rerun()
            else:
                st.info("No Active vendors to suspend.")

        if data['expired_driver_list']:
            st.error(f"Found {len(data['expired_driver_list'])} Drivers with Expired Licenses!")
            exp_df = pd.DataFrame(data['expired_driver_list'])
            if 'dl_expiry' not in exp_df.columns: exp_df['dl_expiry'] = 'Unknown'
            st.dataframe(exp_df[['name', 'dl_expiry', 'vendor_id']])
        else:
            st.success("No Compliance Issues Detected.")

    with tabs[3]:
        st.subheader("Pending Approvals")
        pending = user.get_pending_drivers()
        if pending:
            for d in pending:
                name = d.get('name', 'Unknown Driver')
                expiry = d.get('dl_expiry', 'N/A')
                license_no = d.get('license_number', 'Unknown')
                
                with st.expander(f"{name} (Expiry: {expiry})"):
                    c1, c2 = st.columns([3, 1])
                    with c1:
                        st.write(f"**License:** {license_no}")
                        st.write(f"**Status:** {d.get('status', 'Pending')}")
                    with c2:
                        if st.button("Approve", key=str(d['_id'])):
                            user.approve_driver(d['_id'])
                            st.rerun()
        else:
            st.success("No pending approvals in your fleet.")

    with tabs[4]:
        st.subheader("Delegate Authority")
        if data['sub_vendors_list']:
            sub = st.selectbox("Sub Vendor", [u['username'] for u in data['sub_vendors_list']])
            perm = st.selectbox("Permission", ["manage_payments", "booking_management", "compliance_audit"])
            if st.button("Grant"):
                s, m = user.delegate_access(sub, perm)
                if s: st.success(m)
        else:
             st.info("Create sub-vendors first to delegate permissions.")

# --- SUB VENDOR UI (Recursive) ---
def sub_vendor_dashboard(user):
    st.title(f"🏢 {user.level} Vendor: {user.username}")
    
    if user.delegated_permissions:
        st.info(f"Delegated Permissions: {', '.join(user.delegated_permissions)}")

    tabs = ["My Fleet", "Operations (Delegated)", "Manage Sub-Vendors"]
    t1, t2, t3 = st.tabs(tabs)

    with t1:
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Onboard Driver")
            with st.form("driver_add"):
                dn = st.text_input("Name"); dl = st.text_input("License No (Min 5 chars)"); dp = st.text_input("Phone (Min 10 digits)")
                de = st.date_input("DL Expiry Date") 
                if st.form_submit_button("Add Driver"):
                    try:
                        d_mod = DriverModel(name=dn, license_number=dl, phone=dp, dl_expiry=str(de))
                        s, m = user.onboard_driver(d_mod)
                        if s: st.success(m)
                        else: st.error(m)
                    except Exception as e:
                        st.error(f"Validation Error: {e}")

        with c2:
            st.subheader("Onboard Vehicle")
            with st.form("veh_add"):
                vr = st.text_input("Reg No"); vm = st.text_input("Model")
                vc = st.number_input("Capacity", min_value=1); vf = st.selectbox("Fuel", ["Petrol", "Diesel", "EV"])
                re = st.date_input("RC Expiry"); pe = st.date_input("Pollution Expiry"); prm = st.date_input("Permit Expiry")
                
                if st.form_submit_button("Add Vehicle"):
                    try:
                        v_mod = VehicleModel(
                            reg_number=vr, model=vm, capacity=vc, fuel_type=vf,
                            rc_expiry=str(re), pollution_expiry=str(pe), permit_expiry=str(prm)
                        )
                        s, m = user.onboard_vehicle(v_mod)
                        if s: st.success(m)
                        else: st.error(m)
                    except Exception as e:
                        st.error(f"Validation Error: {e}")

        data = user.get_dashboard_data()
        st.write("#### My Drivers")
        if data['drivers']:
            st.dataframe(pd.DataFrame(data['drivers']))
        else:
            st.info("No drivers onboarded yet.")

    with t2:
        st.subheader("Operational Tasks")
        if "manage_payments" in user.delegated_permissions:
            st.success("✅ Access Granted: Payment Gateway")
            st.button("Process Pending Vendor Payouts")
        else:
            st.warning("🚫 Access Denied: You do not have 'manage_payments' permission.")

        if "booking_management" in user.delegated_permissions:
            st.success("✅ Access Granted: Booking Dispatch")
            st.button("Assign Cabs to Rides")
        else:
            st.warning("🚫 Access Denied: Booking Management.")

    with t3:
        hierarchy_map = {"Regional": "City", "City": "Local", "Local": None}
        allowed_child = hierarchy_map.get(user.level)
        
        if allowed_child:
            st.subheader(f"Create Child Vendor ({allowed_child})")
            with st.form("create_child"):
                cu = st.text_input("Username"); cp = st.text_input("Password", type="password", help="Min 7 chars")
                if st.form_submit_button(f"Create {allowed_child} Vendor"):
                    s, m = user.create_sub_vendor(cu, cp, allowed_child)
                    if s: st.success(m); time.sleep(1); st.rerun()
                    else: st.error(m)
            
            st.write("#### My Sub-Vendors")
            if data['sub_vendors']:
                df = pd.DataFrame(data['sub_vendors'])
                # --- FIX: FILTER COLUMNS TO HIDE PASSWORD ---
                cols_to_show = ['username', 'level', 'status', 'created_at']
                # Default Missing Cols to avoid crash
                for col in cols_to_show:
                    if col not in df.columns:
                        df[col] = 'N/A'
                st.dataframe(df[cols_to_show])
            else:
                st.info("No sub-vendors created yet.")
        else:
            st.info("Local Vendors cannot create sub-vendors.")

# --- MAIN ---
if 'logged_in' not in st.session_state: st.session_state['logged_in'] = False

if not st.session_state['logged_in']:
    login_page()
else:
    user = st.session_state['user']
    with st.sidebar:
        st.write(f"User: **{user.username}**")
        st.write(f"Role: {user.role} ({user.level})")
        if st.button("Logout"):
            st.session_state['logged_in'] = False
            st.rerun()
    
    if user.role == "super_vendor":
        super_vendor_dashboard(user)
    else:
        sub_vendor_dashboard(user)