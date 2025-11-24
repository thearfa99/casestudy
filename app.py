import streamlit as st
import backend
from backend import DatabaseManager, UserFactory, DriverModel, VehicleModel, register_new_super_vendor
import bcrypt
import pandas as pd
import time
from datetime import datetime
from bson.objectid import ObjectId
from pydantic import ValidationError

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
    st.markdown("## Fleet Management System")
    
    tab1, tab2 = st.tabs(["Login", "Register Super Vendor"])
    
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
    st.title(f"{user.username}'s Command Center")
    
    data = user.get_dashboard_data()
    analytics = data.get('analytics', {}) 
    
    # Top Metrics Row
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Vehicles", data['total_vehicles'])
    c2.metric("Total Drivers", analytics.get('total_drivers', 0))
    c3.metric("Sub-Vendors", data['total_vendors'])
    c4.metric("Compliance Alerts", data['compliance_issues_count'], delta_color="inverse")

    tabs = st.tabs(["Analytics", "Network", "Compliance & Overrides", "Approvals", "Delegation"])

    with tabs[0]:
        st.subheader("Fleet Operations Overview")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### Drivers per Vendor (Load)")
            if analytics.get('drivers_by_vendor'):
                st.bar_chart(analytics['drivers_by_vendor'])
            else: st.info("No data.")
            
        with col2:
            st.markdown("### Vehicle Fleet Status")
            status_data = analytics.get('vehicle_status', {})
            if status_data:
                st.bar_chart(status_data)
            else: st.info("No vehicles onboarded.")

    with tabs[1]:
        st.subheader("Sub-Vendor Network")
        if data['sub_vendors_list']:
            df = pd.DataFrame(data['sub_vendors_list'])
            if 'status' not in df.columns: df['status'] = 'Active'
            if 'parent_name' not in df.columns: df['parent_name'] = 'N/A'
            st.dataframe(df[['username', 'level', 'status', 'parent_name']])
        else:
            st.info("No sub-vendors in your network.")
        
        with st.expander("Register New Vendor"):
             with st.form("super_create"):
                u = st.text_input("Username"); p = st.text_input("Password", type="password")
                l = st.selectbox("Level", ["Regional", "City"])
                if st.form_submit_button("Create"):
                    s, m = user.create_sub_vendor(u, p, l)
                    if s: st.success(m); time.sleep(1); st.rerun()
                    else: st.error(m)

    with tabs[2]:
        st.header("System Compliance & Overrides")
        
        # SECTION 1: Vehicle Compliance 
        st.subheader("Non-Compliant Vehicles (Action Required)")
        bad_vehicles = data.get('non_compliant_vehicles', [])
        
        if bad_vehicles:
            for v in bad_vehicles:
                with st.container(border=True):
                    c1, c2, c3 = st.columns([2, 2, 1])
                    with c1:
                        st.write(f"**Reg:** {v['reg_number']}")
                        st.write(f"**Owner:** {v['owner_name']}")
                    with c2:
                        st.error(f"Issues: {v['compliance_issues']}")
                        st.caption(f"Status: {v.get('status', 'Unknown')}")
                    with c3:
                        if v.get('status') != 'Disabled':
                            if st.button("Disable", key=f"dis_{v['_id']}"):
                                user.disable_vehicle(v['_id']) 
                                st.rerun()
                        else:
                            st.write("🔴 Disabled")
        else:
            st.success("✅ All vehicles are compliant.")

        st.divider()

        # SECTION 2: Driver Compliance
        st.subheader("Expired Driver Licenses")
        if data['expired_driver_list']:
            exp_df = pd.DataFrame(data['expired_driver_list'])
            st.dataframe(exp_df[['name', 'dl_expiry', 'owner_name']])
        else:
            st.success("✅ All drivers have valid licenses.")

    with tabs[3]:
        st.subheader("Pending Approvals")
        pending = user.get_pending_drivers()
        if pending:
            for d in pending:
                name = d.get('name', 'Unknown')
                with st.expander(f"Review: {name}"):
                    st.write(f"License: {d.get('license_number')}")
                    if st.button("Approve", key=str(d['_id'])):
                        user.approve_driver(d['_id'])
                        st.rerun()
        else:
            st.success("No pending approvals.")

    with tabs[4]:
        st.subheader("Delegate Authority")
        if data['sub_vendors_list']:
            sub = st.selectbox("Select Vendor", [u['username'] for u in data['sub_vendors_list']])
            perm = st.selectbox("Permission", ["manage_payments", "booking_management", "view_reports", "compliance_audit"])
            if st.button("Grant Permission"):
                s, m = user.delegate_access(sub, perm)
                if s: st.success(m)
        else: st.info("No sub-vendors.")

# --- SUB VENDOR UI (Recursive) ---
def sub_vendor_dashboard(user):
    st.title(f"{user.level} Vendor: {user.username}")
    
    if user.delegated_permissions:
        st.success(f"Active Delegations: {', '.join(user.delegated_permissions)}")
    else:
        st.info("No special permissions delegated.")

    tabs = ["My Fleet & Actions", "Operations (Delegated)", "Manage Sub-Vendors"]
    t1, t2, t3 = st.tabs(tabs)

    with t1:
        # Metrics Row
        data = user.get_dashboard_data()
        c1, c2, c3 = st.columns(3)
        
        c1.metric("Network Drivers", data.get('total_network_drivers', 0))
        sub_vendors_count = len(data.get('sub_vendors', []))
        c2.metric("Direct Sub-Vendors", sub_vendors_count)
        c3.metric("Your Level", user.level)

        st.divider()
        
        # --- INTERACTIVE FLEET MANAGER ---
        st.subheader("Fleet Management")
        
        drivers_list = data.get('drivers', [])
        
        if drivers_list:
            for d in drivers_list:
                status_color = "🟢" if d.get('status') == 'Active' else "🔴"
                if d.get('status') == 'Revoked': status_color = "⚫"
                
                owner = d.get('owner_name', 'Me')
                
                with st.expander(f"{status_color} {d['name']} ({owner})"):
                    col_a, col_b = st.columns([3, 2])
                    
                    with col_a:
                        st.write(f"**License:** {d['license_number']}")
                        st.write(f"**Phone:** {d['phone']}")
                        st.write(f"**Expiry:** {d['dl_expiry']}")
                        st.write(f"**Current Status:** {d.get('status', 'Unknown')}")
                    
                    with col_b:
                        st.write("**Actions:**")
                        if d.get('status') == 'Active':
                            if st.button("Suspend Driver", key=f"sus_{d['_id']}"):
                                user.update_driver_status(d['_id'], "Suspended")
                                st.rerun()
                            if st.button("Revoke License", key=f"rev_{d['_id']}"):
                                user.update_driver_status(d['_id'], "Revoked")
                                st.rerun()
                        else:
                            if st.button("Activate Driver", key=f"act_{d['_id']}"):
                                user.update_driver_status(d['_id'], "Active")
                                st.rerun()
        else:
            st.info("No drivers found in your hierarchy.")

        st.divider()
        
        with st.expander("Onboard New Driver/Vehicle"):
            c1, c2 = st.columns(2)
            
            # --- DRIVER FORM ---
            with c1:
                st.markdown("### 👨‍✈️ Add Driver")
                with st.form("driver_add"):
                    dn = st.text_input("Name")
                    dl = st.text_input("License No")
                    dp = st.text_input("Phone")
                    de = st.date_input("DL Expiry Date") 
                    
                    if st.form_submit_button("Add Driver"):
                        try:
                            # 1. Try to create the model (Pydantic validation happens here)
                            d_mod = DriverModel(name=dn, license_number=dl, phone=dp, dl_expiry=str(de))
                            
                            # 2. If valid, attempt onboarding
                            s, m = user.onboard_driver(d_mod)
                            if s: 
                                st.success(m)
                                time.sleep(1)
                                st.rerun()
                            else: 
                                st.error(m)
                                
                        except ValidationError as e:
                            # 3. Catch Pydantic errors and format them nicely
                            st.error("❌ **Please fix the following errors:**")
                            for err in e.errors():
                                # cleanup field name: 'license_number' -> 'License Number'
                                field = str(err['loc'][0]).replace('_', ' ').title()
                                msg = err['msg']
                                st.warning(f"**{field}:** {msg}")
                                
                        except Exception as e: 
                            st.error(f"System Error: {str(e)}")

            # --- VEHICLE FORM ---
            with c2:
                st.markdown("### 🚕 Add Vehicle")
                with st.form("veh_add"):
                    vr = st.text_input("Reg No")
                    vm = st.text_input("Model")
                    vc = st.number_input("Capacity", min_value=1)
                    vf = st.selectbox("Fuel", ["Petrol", "Diesel", "EV"])
                    re = st.date_input("RC Expiry")
                    pe = st.date_input("Pollution Expiry")
                    prm = st.date_input("Permit Expiry")
                    
                    if st.form_submit_button("Add Vehicle"):
                        try:
                            v_mod = VehicleModel(
                                reg_number=vr, model=vm, capacity=vc, fuel_type=vf, 
                                rc_expiry=str(re), pollution_expiry=str(pe), permit_expiry=str(prm)
                            )
                            s, m = user.onboard_vehicle(v_mod)
                            if s: 
                                st.success(m)
                                time.sleep(1)
                                st.rerun()
                            else: 
                                st.error(m)
                                
                        except ValidationError as e:
                            st.error("❌ **Please fix the following errors:**")
                            for err in e.errors():
                                field = str(err['loc'][0]).replace('_', ' ').title()
                                msg = err['msg']
                                st.warning(f"**{field}:** {msg}")
                                
                        except Exception as e: 
                            st.error(f"System Error: {str(e)}")

    with t2:
        st.subheader("Delegated Operational Tasks")
        has_any_permission = False
        if "manage_payments" in user.delegated_permissions:
            has_any_permission = True
            with st.container(border=True):
                st.markdown("### Payment Gateway")
                if st.button("Process Batch Payments"): st.success("Paid.")
        if "booking_management" in user.delegated_permissions:
            has_any_permission = True
            with st.container(border=True):
                st.markdown("### Booking Dispatch")
                if st.button("Auto-Dispatch"): st.info("Dispatched.")
        if "view_reports" in user.delegated_permissions:
            has_any_permission = True
            with st.container(border=True):
                st.markdown("### Network Reports")
                st.download_button("Download Report", "data.csv")
        if "compliance_audit" in user.delegated_permissions:
            has_any_permission = True
            with st.container(border=True):
                st.markdown("### Compliance Audit")
                if st.button("Run Audit"): st.warning("Issues found.")
        if not has_any_permission: st.warning("No tasks delegated.")

    with t3:
        hierarchy_map = {"Regional": "City", "City": "Local", "Local": None}
        allowed_child = hierarchy_map.get(user.level)
        if allowed_child:
            st.subheader(f"Create Child Vendor ({allowed_child})")
            with st.form("create_child"):
                cu = st.text_input("Username"); cp = st.text_input("Password", type="password")
                if st.form_submit_button(f"Create"):
                    s, m = user.create_sub_vendor(cu, cp, allowed_child)
                    if s: st.success(m); st.rerun()
                    else: st.error(m)
            st.write("#### My Sub-Vendors")
            if data.get('sub_vendors'):
                df = pd.DataFrame(data['sub_vendors'])
                cols = ['username', 'level', 'status', 'created_at']
                for c in cols: 
                    if c not in df.columns: df[c] = 'N/A'
                st.dataframe(df[cols])
        else: st.info("Local Vendors cannot create sub-vendors.")
        
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