# import streamlit as st
# import sqlite3
# import hashlib
# import base64
# import os
# import time

# from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives import hashes  # ✅ Fix for PBKDF2

# # ------------------ Database Setup ------------------
# def init_db():
#     conn = sqlite3.connect("secure_data.db")
#     c = conn.cursor()
#     c.execute('''CREATE TABLE IF NOT EXISTS users (
#         username TEXT PRIMARY KEY,
#         password_hash TEXT
#     )''')
#     c.execute('''CREATE TABLE IF NOT EXISTS data (
#         username TEXT,
#         encrypted_text TEXT,
#         salt TEXT
#     )''')
#     conn.commit()
#     conn.close()

# def add_user(username, password_hash):
#     conn = sqlite3.connect("secure_data.db")
#     c = conn.cursor()
#     c.execute("INSERT INTO users VALUES (?, ?)", (username, password_hash))
#     conn.commit()
#     conn.close()

# def get_user(username):
#     conn = sqlite3.connect("secure_data.db")
#     c = conn.cursor()
#     c.execute("SELECT * FROM users WHERE username=?", (username,))
#     user = c.fetchone()
#     conn.close()
#     return user

# def save_user_data(username, encrypted_text, salt):
#     conn = sqlite3.connect("secure_data.db")
#     c = conn.cursor()
#     c.execute("DELETE FROM data WHERE username=?", (username,))
#     c.execute("INSERT INTO data VALUES (?, ?, ?)", (username, encrypted_text, salt))
#     conn.commit()
#     conn.close()

# def get_user_data(username):
#     conn = sqlite3.connect("secure_data.db")
#     c = conn.cursor()
#     c.execute("SELECT encrypted_text, salt FROM data WHERE username=?", (username,))
#     data = c.fetchone()
#     conn.close()
#     return data

# # ------------------ Auth & Encryption ------------------
# def hash_password(password):
#     return hashlib.sha256(password.encode()).hexdigest()

# def verify_password(input_password, stored_hash):
#     return hash_password(input_password) == stored_hash

# def generate_key(passkey: str, salt: bytes):
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),  # ✅ FIXED
#         length=32,
#         salt=salt,
#         iterations=100000,
#     )
#     return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# def encrypt_data(data: str, passkey: str):
#     salt = os.urandom(16)
#     key = generate_key(passkey, salt)
#     fernet = Fernet(key)
#     encrypted = fernet.encrypt(data.encode())
#     return encrypted.decode(), salt.hex()

# def decrypt_data(encrypted_text: str, passkey: str, salt_hex: str):
#     salt = bytes.fromhex(salt_hex)
#     key = generate_key(passkey, salt)
#     fernet = Fernet(key)
#     return fernet.decrypt(encrypted_text.encode()).decode()

# # ------------------ Streamlit App ------------------
# st.set_page_config(page_title="Secure Data System",page_icon="🔐", layout="wide")
# init_db()

# # Session initialization
# if "logged_in" not in st.session_state:
#     st.session_state.logged_in = False
#     st.session_state.username = ""
#     st.session_state.failed_attempts = 0

# # Pages
# def login_page():
#     st.title("🔐 Login")
#     username = st.text_input("Username")
#     password = st.text_input("Password", type="password")
#     if st.button("Login"):
#         user = get_user(username)
#         if user and verify_password(password, user[1]):
#             st.session_state.logged_in = True
#             st.session_state.username = username
#             st.session_state.failed_attempts = 0
#             st.success("✅ Login successful!")
#         else:
#             st.session_state.failed_attempts += 1
#             st.error(f"❌ Login failed! Attempt {st.session_state.failed_attempts}/3")
#             if st.session_state.failed_attempts >= 3:
#                 st.warning("⚠️ Too many attempts. Please wait 30 seconds.")
#                 time.sleep(30)
#                 st.session_state.failed_attempts = 0

# def register_page():
#     st.title("📝 Register")
#     username = st.text_input("Choose a Username")
#     password = st.text_input("Choose a Password", type="password")
#     if st.button("Register"):
#         if get_user(username):
#             st.error("🚫 Username already exists!")
#         else:
#             add_user(username, hash_password(password))
#             st.success("✅ Registered successfully! You can now log in.")

# def home_page():
#     st.title(f"👋 Welcome, {st.session_state.username}")
#     menu = st.radio("Choose Action", ["Insert Data", "Retrieve Data", "Logout"])

#     if menu == "Insert Data":
#         st.subheader("🔏 Encrypt and Store Data")
#         plain_text = st.text_area("Enter text to encrypt")
#         passkey = st.text_input("Encryption Passkey", type="password")
#         if st.button("Encrypt & Store"):
#             if plain_text and passkey:
#                 encrypted, salt = encrypt_data(plain_text, passkey)
#                 save_user_data(st.session_state.username, encrypted, salt)
#                 st.success("✅ Data encrypted and saved securely!")
#             else:
#                 st.warning("Please enter both text and passkey.")

#     elif menu == "Retrieve Data":
#         st.subheader("🔓 Decrypt Your Data")
#         passkey = st.text_input("Enter your decryption passkey", type="password")
#         if st.button("Decrypt"):
#             data = get_user_data(st.session_state.username)
#             if data:
#                 try:
#                     decrypted = decrypt_data(data[0], passkey, data[1])
#                     st.success("🔐 Decrypted Data:")
#                     st.code(decrypted)
#                     st.session_state.failed_attempts = 0
#                 except Exception:
#                     st.session_state.failed_attempts += 1
#                     st.error(f"❌ Incorrect passkey! Attempt {st.session_state.failed_attempts}/3")
#                     if st.session_state.failed_attempts >= 3:
#                         st.session_state.logged_in = False
#                         st.session_state.failed_attempts = 0
#                         st.error("🚫 Too many failed attempts. You are logged out.")
#             else:
#                 st.info("ℹ️ No data stored yet.")

#     elif menu == "Logout":
#         st.session_state.logged_in = False
#         st.session_state.username = ""
#         st.success("👋 Logged out successfully!")

# # Routing
# def main():
#     st.sidebar.title("🛡️ Secure App Menu")
#     if not st.session_state.logged_in:
#         choice = st.sidebar.selectbox("Select Page", ["Login", "Register"])
#         if choice == "Login":
#             login_page()
#         else:
#             register_page()
#     else:
#         st.sidebar.success(f"Logged in as: {st.session_state.username}")
#         home_page()

# if __name__ == "__main__":
#     main()




# part2



# import streamlit as st
# import sqlite3
# import hashlib
# import base64
# import time
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.fernet import Fernet
# import os

# # ---------------------- DB Setup ----------------------
# conn = sqlite3.connect("users.db", check_same_thread=False)
# c = conn.cursor()
# c.execute("""
#     CREATE TABLE IF NOT EXISTS users (
#         username TEXT PRIMARY KEY,
#         password TEXT NOT NULL
#     )
# """)
# conn.commit()

# # ------------------ Password Hashing ------------------
# def hash_password(password):
#     return hashlib.sha256(password.encode()).hexdigest()

# def verify_password(password, hashed):
#     return hash_password(password) == hashed

# # ------------------ Fernet Key Gen ------------------
# def generate_key(passkey: str, salt: bytes) -> bytes:
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000,
#         backend=default_backend(),
#     )
#     return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# # ------------------ Encryption & Decryption ------------------
# def encrypt_data(plain_text: str, passkey: str) -> tuple:
#     salt = os.urandom(16)
#     key = generate_key(passkey, salt)
#     fernet = Fernet(key)
#     encrypted = fernet.encrypt(plain_text.encode())
#     return encrypted.decode(), base64.b64encode(salt).decode()

# def decrypt_data(encrypted_text: str, passkey: str, salt: str) -> str:
#     salt_bytes = base64.b64decode(salt.encode())
#     key = generate_key(passkey, salt_bytes)
#     fernet = Fernet(key)
#     return fernet.decrypt(encrypted_text.encode()).decode()

# # ------------------ User Management ------------------
# def create_user(username, password):
#     hashed_pw = hash_password(password)
#     c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
#     conn.commit()

# def get_user(username):
#     c.execute("SELECT * FROM users WHERE username = ?", (username,))
#     return c.fetchone()

# # ------------------ App State Init ------------------
# if "logged_in" not in st.session_state:
#     st.session_state.logged_in = False
# if "username" not in st.session_state:
#     st.session_state.username = ""
# if "failed_attempts" not in st.session_state:
#     st.session_state.failed_attempts = 0
# if "lockout_time" not in st.session_state:
#     st.session_state.lockout_time = None
# if "show_register" not in st.session_state:
#     st.session_state.show_register = False
# if "user_data" not in st.session_state:
#     st.session_state.user_data = {}

# # ------------------ UI Functions ------------------
# def apply_custom_styles():
#     st.markdown("""
#     <style>
#     /* Dark theme */
#     :root {
#         --primary: #6a11cb;
#         --secondary: #2575fc;
#         --dark-bg: #0e1117;
#         --darker-bg: #0a0c10;
#         --card-bg: #1e1e2f;
#         --text: #f1f1f1;
#         --text-muted: #a1a1a1;
#         --success: #28a745;
#         --error: #dc3545;
#         --warning: #fd7e14;
#         --info: #17a2b8;
#     }
    
#     /* Main container */
#     .main {
#         background-color: var(--dark-bg);
#         color: var(--text);
#     }
    
#     /* Enhanced Sidebar Styling */
#      [data-testid="stSidebar"] {
#         background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%) !important;
#         color: white !important;
#         padding: 1rem;
#         box-shadow: 2px 0 10px rgba(0,0,0,0.3);
#     }
    
#     /* Sidebar header */
#     .sidebar-header {
#         text-align: center;
#         margin-bottom: 2rem;
#         padding-bottom: 1rem;
#         border-bottom: 1px solid rgba(255,255,255,0.1);
#     }
    
#     /* Sidebar navigation items */
#     [data-testid="stSidebarNav"] > div > ul {
#         padding-left: 0;
#         margin-top: 0;
#     }
    
#     [data-testid="stSidebarNav"] > div > ul > li > div {
#         padding: 0.5rem 1rem;
#         margin: 0.25rem 0;
#         border-radius: 8px;
#         transition: all 0.3s ease;
#         background-color: rgba(255,255,255,0.05);
#     }
    
#     [data-testid="stSidebarNav"] > div > ul > li > div:hover {
#         background-color: rgba(255,255,255,0.1) !important;
#         transform: translateX(5px);
#     }
    
#     [data-testid="stSidebarNav"] > div > ul > li > div > a {
#         color: white !important;
#         font-weight: 500;
#         display: flex;
#         align-items: center;
#         gap: 0.75rem;
#         text-decoration: none;
#     }
    
#     /* Selected menu item */
#     [data-testid="stSidebarNav"] > div > ul > li > div[data-baseweb="radio"] {
#         background-color: rgba(100,149,237,0.3) !important;
#         box-shadow: 0 0 0 1px rgba(255,255,255,0.1);
#     }
    
#     /* Sidebar radio buttons (for menu) */
#     [data-testid="stSidebar"] .stRadio > div {
#         flex-direction: column;
#         gap: 0.5rem;
#     }
    
#     /* Sidebar divider */
#     .sidebar-divider {
#         height: 1px;
#         background: rgba(255,255,255,0.1);
#         margin: 1.5rem 0;
#     }
    
#     /* User profile section */
#     .user-profile {
#         text-align: center;
#         margin-top: auto;
#         padding-top: 1.5rem;
#         border-top: 1px solid rgba(255,255,255,0.1);
#     }
    
#     .user-avatar {
#         width: 60px;
#         height: 60px;
#         border-radius: 50%;
#         margin: 0 auto 1rem;
#         background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
#         display: flex;
#         align-items: center;
#         justify-content: center;
#         font-size: 24px;
#         color: white;
#         font-weight: bold;
#     }
    
#     .user-name {
#         font-size: 1.1rem;
#         font-weight: 600;
#         margin-bottom: 0.25rem;
#     }
    
#     .user-email {
#         font-size: 0.85rem;
#         opacity: 0.8;
#     }
    
#     /* Sidebar footer */
#     .sidebar-footer {
#         font-size: 0.75rem;
#         text-align: center;
#         margin-top: 2rem;
#         opacity: 0.6;
#     }
    
#     /* Input fields */
#     .stTextInput input, .stTextArea textarea {
#         background-color: var(--darker-bg) !important;
#         color: var(--text) !important;
#         border: 1px solid #2d3748 !important;
#         border-radius: 8px;
#         padding: 10px;
#     }
    
#     /* Buttons */
#     .stButton>button {
#         border: none;
#         border-radius: 8px;
#         padding: 10px 20px;
#         font-weight: 600;
#         transition: all 0.3s;
#         background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
#         color: white;
#     }
    
#     .stButton>button:hover {
#         transform: translateY(-2px);
#         box-shadow: 0 4px 8px rgba(0,0,0,0.2);
#     }
    
#     /* Alerts */
#     .stAlert .st-b7 {
#         background-color: rgba(40, 167, 69, 0.2) !important;
#         color: var(--text) !important;
#         border-radius: 8px;
#         border-left: 4px solid var(--success);
#     }
    
#     .stAlert .st-be {
#         background-color: rgba(220, 53, 69, 0.2) !important;
#         color: var(--text) !important;
#         border-radius: 8px;
#         border-left: 4px solid var(--error);
#     }
    
#     .stAlert .st-bb {
#         background-color: rgba(23, 162, 184, 0.2) !important;
#         color: var(--text) !important;
#         border-radius: 8px;
#         border-left: 4px solid var(--info);
#     }
    
#     /* Cards */
#     .card {
#         background: var(--card-bg);
#         border-radius: 12px;
#         padding: 20px;
#         box-shadow: 0 4px 6px rgba(0,0,0,0.2);
#         margin-bottom: 20px;
#         color: var(--text);
#     }
    
#     /* Data display card */
#     .data-card {
#         background: var(--darker-bg);
#         border-radius: 8px;
#         padding: 15px;
#         margin: 10px 0;
#         border-left: 4px solid var(--secondary);
#     }
    
#     /* Decrypted content */
#     .decrypted-content {
#         background-color: var(--darker-bg) !important;
#         color: var(--text) !important;
#         padding: 15px;
#         border-radius: 8px;
#         margin: 10px 0;
#         border-left: 4px solid var(--success);
#         white-space: pre-wrap;
#         word-wrap: break-word;
#     }
    
#     /* Headers */
#     h1, h2, h3, h4, h5, h6 {
#         color: var(--text) !important;
#     }
    
#     /* Lockout message */
#     .lockout {
#         background-color: rgba(253, 126, 20, 0.2);
#         color: var(--text);
#         padding: 15px;
#         border-radius: 8px;
#         text-align: center;
#         margin: 20px 0;
#         border-left: 4px solid var(--warning);
#     }
    
#     /* Text elements */
#     p, div {
#         color: var(--text);
#     }
    
#     /* Custom scrollbar */
#     ::-webkit-scrollbar {
#         width: 8px;
#     }
    
#     ::-webkit-scrollbar-track {
#         background: var(--darker-bg);
#     }
    
#     ::-webkit-scrollbar-thumb {
#         background: var(--primary);
#         border-radius: 4px;
#     }
    
#     ::-webkit-scrollbar-thumb:hover {
#         background: var(--secondary);
#     }
    
#     /* Empty state */
#     .empty-state {
#         text-align: center;
#         padding: 40px 20px;
#     }
#     </style>
#     """, unsafe_allow_html=True)

# def login_ui():
#     apply_custom_styles()
    
#     # Hero section
#     col1, col2 = st.columns([2, 1])
#     with col1:
#         st.markdown("""
#         <div style='padding: 20px 0;'>
#             <h1 style='color: #2575fc; margin-bottom: 10px;'>🔐 Secure Vault</h1>
#             <p style='font-size: 18px; color: #6c757d;'>Your personal encryption solution</p>
#         </div>
#         """, unsafe_allow_html=True)
    
#     if st.session_state.failed_attempts >= 3:
#         if st.session_state.lockout_time is None:
#             st.session_state.lockout_time = time.time()

#         time_left = int(30 - (time.time() - st.session_state.lockout_time))

#         if time_left > 0:
#             st.markdown(f"""
#             <div class='lockout'>
#                 <h3>🚨 Account Temporarily Locked</h3>
#                 <p>Too many failed attempts. Please wait {time_left} seconds before trying again.</p>
#             </div>
#             """, unsafe_allow_html=True)
#             time.sleep(1)
#             st.rerun()
#         else:
#             st.session_state.failed_attempts = 0
#             st.session_state.lockout_time = None
#             st.rerun()
#         return

#     # Login form in a card
#     with st.container():
#         st.markdown("<div class='card'>", unsafe_allow_html=True)
        
#         st.markdown("### Sign In to Your Account")
#         st.markdown("Enter your credentials to access your encrypted data")
        
#         with st.form("login_form"):
#             username = st.text_input("Username", placeholder="Enter your username")
#             password = st.text_input("Password", type="password", placeholder="Enter your password")
#             submitted = st.form_submit_button("Login", use_container_width=True)

#             if submitted:
#                 user = get_user(username)
#                 if user and verify_password(password, user[1]):
#                     st.session_state.logged_in = True
#                     st.session_state.username = username
#                     st.session_state.failed_attempts = 0
#                     st.success("✅ Login successful! Redirecting...")
#                     time.sleep(1)
#                     st.rerun()
#                 else:
#                     st.session_state.failed_attempts += 1
#                     st.error(f"❌ Invalid credentials. Attempt {st.session_state.failed_attempts}/3")
#                     if st.session_state.failed_attempts >= 3:
#                         st.session_state.lockout_time = time.time()
#                         st.rerun()
        
#         st.markdown("<div style='text-align: center; margin-top: 20px;'>", unsafe_allow_html=True)
#         st.markdown("Don't have an account?")
#         if st.button("Register Now", key="register_btn"):
#             st.session_state.show_register = True
#             st.rerun()
#         st.markdown("</div>", unsafe_allow_html=True)
        
#         st.markdown("</div>", unsafe_allow_html=True)

# def register_ui():
#     apply_custom_styles()
    
#     # Hero section
#     col1, col2 = st.columns([2, 1])
#     with col1:
#         st.markdown("""
#         <div style='padding: 20px 0;'>
#             <h1 style='color: #2575fc; margin-bottom: 10px;'>📝 Create Account</h1>
#             <p style='font-size: 18px; color: #6c757d;'>Join Secure Vault today</p>
#         </div>
#         """, unsafe_allow_html=True)
    
#     # Registration form in a card
#     with st.container():
#         st.markdown("<div class='card'>", unsafe_allow_html=True)
        
#         with st.form("register_form"):
#             st.markdown("### Register New Account")
#             username = st.text_input("Username", placeholder="Choose a username")
#             password = st.text_input("Password", type="password", placeholder="Create a password")
#             confirm = st.text_input("Confirm Password", type="password", placeholder="Re-enter your password")
#             submitted = st.form_submit_button("Register", use_container_width=True)

#             if submitted:
#                 if password != confirm:
#                     st.error("Passwords do not match")
#                 elif get_user(username):
#                     st.error("Username already exists")
#                 else:
#                     create_user(username, password)
#                     st.success("🎉 Account created successfully! Redirecting to login...")
#                     st.session_state.show_register = False
#                     time.sleep(1)
#                     st.rerun()
        
#         st.markdown("<div style='text-align: center; margin-top: 20px;'>", unsafe_allow_html=True)
#         if st.button("Back to Login", key="back_login_btn"):
#             st.session_state.show_register = False
#             st.rerun()
#         st.markdown("</div>", unsafe_allow_html=True)
        
#         st.markdown("</div>", unsafe_allow_html=True)

# def home_page():
#     apply_custom_styles()
    
#     # Enhanced Sidebar navigation
#     with st.sidebar:
#         # User profile section
#         st.markdown(f"""
#         <div class="sidebar-header">
#             <div class="user-avatar">
#                 {st.session_state.username[0].upper()}
#             </div>
#             <div class="user-name">{st.session_state.username}</div>
#         </div>
#         """, unsafe_allow_html=True)
        
#         # Menu divider
#         st.markdown('<div class="sidebar-divider"></div>', unsafe_allow_html=True)
        
#         # Navigation menu
#         menu = st.radio(
#             "Navigation",
#             ["Encrypt Data", "Retrieve Data", "Logout"],
#             label_visibility="collapsed",
#             format_func=lambda x: {
#                 "Encrypt Data": "🔒 Encrypt Data",
#                 "Retrieve Data": "🔓 Retrieve Data", 
#                 "Logout": "🚪 Logout"
#             }[x]
#         )
        
#         # Footer
#         st.markdown("""
#         <div class="sidebar-footer">
#             Secure Vault v1.0<br>
#             © 2023 All rights reserved
#         </div>
#         """, unsafe_allow_html=True)
    
#     # Main content area
#     st.markdown(f"# 🔐 Secure Vault")
#     st.markdown(f"Welcome back, **{st.session_state.username}**! What would you like to do today?")
    
#     if menu == "Encrypt Data":
#         st.markdown("## 🔒 Encrypt & Store Data")
#         with st.container():
#             st.markdown("<div class='card'>", unsafe_allow_html=True)
            
#             text = st.text_area("Enter text to encrypt", height=150, 
#                               placeholder="Type or paste your sensitive information here...")
#             passkey = st.text_input("Encryption passkey", type="password", 
#                                    placeholder="Enter a strong passkey (remember this!)")
            
#             if st.button("Encrypt & Store", key="encrypt_btn"):
#                 if text and passkey:
#                     encrypted, salt = encrypt_data(text, passkey)
#                     st.success("✅ Data encrypted and stored securely!")
#                     if st.session_state.username not in st.session_state.user_data:
#                         st.session_state.user_data[st.session_state.username] = []
#                     st.session_state.user_data[st.session_state.username].append({
#                         "encrypted": encrypted, 
#                         "salt": salt
#                     })
#                 else:
#                     st.error("Please provide both text to encrypt and a passkey")
            
#             st.markdown("</div>", unsafe_allow_html=True)
            
#             # Encryption tips
#             st.markdown("""
#             <div class='card'>
#                 <h4>🔒 Encryption Tips</h4>
#                 <ul>
#                     <li>Use a strong, unique passkey that you can remember</li>
#                     <li>Never share your passkey with anyone</li>
#                     <li>The same passkey is required to decrypt your data</li>
#                     <li>For maximum security, use a passphrase instead of a simple password</li>
#                 </ul>
#             </div>
#             """, unsafe_allow_html=True)

#     elif menu == "Retrieve Data":
#         st.markdown("## 🔓 Retrieve & Decrypt Data")
#         with st.container():
#             user_entries = st.session_state.user_data.get(st.session_state.username, [])
            
#             if not user_entries:
#                 st.markdown("""
#                 <div class='card'>
#                     <div class='empty-state'>
#                         <h4>🔍 No Encrypted Data Found</h4>
#                         <p>You haven't stored any encrypted data yet.</p>
#                         <p>Use the "Encrypt Data" section to store your first secret!</p>
#                     </div>
#                 </div>
#                 """, unsafe_allow_html=True)
#             else:
#                 passkey = st.text_input("Decryption passkey", type="password", 
#                                       placeholder="Enter your passkey to decrypt data",
#                                       key="decrypt_passkey")
                
#                 if st.button("Decrypt All", key="decrypt_btn"):
#                     with st.spinner("Decrypting your data..."):
#                         for i, item in enumerate(user_entries):
#                             try:
#                                 decrypted = decrypt_data(item['encrypted'], passkey, item['salt'])
#                                 st.markdown(f"""
#                                 <div class='card'>
#                                     <h4>Entry #{i+1}</h4>
#                                     <div class='decrypted-content'>
#                                         {decrypted}
#                                     </div>
#                                 </div>
#                                 """, unsafe_allow_html=True)
#                             except Exception as e:
#                                 st.error(f"❌ Failed to decrypt entry {i+1}. Please check your passkey and try again.")

#     elif menu == "Logout":
#         st.session_state.logged_in = False
#         st.session_state.username = ""
#         st.success("👋 You have been logged out successfully.")
#         time.sleep(1)
#         st.rerun()

# # ------------------ Main Logic ------------------
# def main():
#     st.set_page_config(
#         page_title="Secure Vault",
#         page_icon="🔒",
#         layout="wide",
#         initial_sidebar_state="expanded"
#     )
    
#     if not st.session_state.logged_in:
#         if st.session_state.show_register:
#             register_ui()
#         else:
#             login_ui()
#     else:
#         home_page()

# if __name__ == '__main__':
#     main()