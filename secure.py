import streamlit as st
import hashlib
import base64
import time
import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
from pathlib import Path

# ------------------ Database Setup ------------------
def init_db():
    db_path = Path("secure_vault.db")
    if not db_path.exists():
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY, password_hash TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS user_data
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT,
                      encrypted_text TEXT,
                      salt TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        conn.commit()
        conn.close()

# ------------------ Password Hashing ------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

# ------------------ Fernet Key Gen ------------------
def generate_key(passkey: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# ------------------ Encryption & Decryption ------------------
def encrypt_data(plain_text: str, passkey: str) -> tuple:
    salt = os.urandom(16)
    key = generate_key(passkey, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(plain_text.encode())
    return encrypted.decode(), base64.b64encode(salt).decode()

def decrypt_data(encrypted_text: str, passkey: str, salt: str) -> str:
    salt_bytes = base64.b64decode(salt.encode())
    key = generate_key(passkey, salt_bytes)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_text.encode()).decode()

# ------------------ User Management ------------------
def create_user(username, password):
    conn = sqlite3.connect("secure_vault.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                  (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user(username):
    conn = sqlite3.connect("secure_vault.db")
    c = conn.cursor()
    c.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result if result else None

def store_encrypted_data(username, encrypted_text, salt):
    conn = sqlite3.connect("secure_vault.db")
    c = conn.cursor()
    c.execute("INSERT INTO user_data (username, encrypted_text, salt) VALUES (?, ?, ?)",
              (username, encrypted_text, salt))
    conn.commit()
    conn.close()

def get_user_data(username):
    conn = sqlite3.connect("secure_vault.db")
    c = conn.cursor()
    c.execute("SELECT id, encrypted_text, salt, timestamp FROM user_data WHERE username = ? ORDER BY timestamp DESC", 
              (username,))
    result = c.fetchall()
    conn.close()
    return result

# ------------------ App State Init ------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None
if "show_register" not in st.session_state:
    st.session_state.show_register = False

init_db()

# ------------------ UI Functions ------------------
def apply_custom_styles():
    st.markdown("""
    <style>
    :root {
        --primary: #6a11cb;
        --secondary: #2575fc;
        --dark-bg: #0e1117;
        --darker-bg: #0a0c10;
        --card-bg: #1e1e2f;
        --text: #f1f1f1;
        --text-muted: #a1a1a1;
        --success: #28a745;
        --error: #dc3545;
        --warning: #fd7e14;
        --info: #17a2b8;
    }
    
    /* Base button styles - applies to all themes */
    .stButton>button {
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 10px 20px !important;
        font-weight: 600 !important;
        transition: all 0.3s !important;
        background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%) !important;
    }
    
    .stButton>button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 8px rgba(0,0,0,0.2) !important;
    }
    
    .stButton>button:focus {
        color: white !important;
    }
    
    button p {
        color: white !important;
    }
                        
    
    /* Light theme overrides */
    @media (prefers-color-scheme: light) {
        :root {
            --dark-bg: #ffffff;
            --darker-bg: #f8f9fa;
            --card-bg: #ffffff;
            --text: #000000;
            --text-muted: #6c757d;
        }
        
        .main .block-container {
            background: white !important;
        }
        
        body, p, h1, h2, h3, h4, h5, h6, div, span, label {
            color: var(--text) !important;
        }
        
        .card {
            background: white !important;
            color: #000000 !important;
            border: 1px solid #e0e0e0 !important;
        }
        
        .stTextInput input, 
        .stTextArea textarea {
            color: #000000 !important;
            background-color: white !important;
            border: 1px solid #ced4da !important;
        }
        
        .stTextInput input::placeholder,
        .stTextArea textarea::placeholder {
            color: #6c757d !important;
            opacity: 1 !important;
        }
        
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%) !important;
        }
        
        [data-testid="stSidebar"] * {
            color: white !important;
        } 
                      
    }
                
    
    /* Dark theme (unchanged) */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%) !important;
        color: white !important;
        padding: 1rem;
        box-shadow: 2px 0 10px rgba(0,0,0,0.3);
    }
    
    .sidebar-header {
        text-align: center;
        margin-bottom: 2rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid rgba(255,255,255,0.1);
    }
    
    [data-testid="stSidebarNav"] > div > ul {
        padding-left: 0;
        margin-top: 0;
    }
    
    [data-testid="stSidebarNav"] > div > ul > li > div {
        padding: 0.5rem 1rem;
        margin: 0.25rem 0;
        border-radius: 8px;
        transition: all 0.3s ease;
        background-color: rgba(255,255,255,0.05);
    }
    
    [data-testid="stSidebarNav"] > div > ul > li > div:hover {
        background-color: rgba(255,255,255,0.1) !important;
        transform: translateX(5px);
    }
    
    [data-testid="stSidebarNav"] > div > ul > li > div > a {
        color: white !important;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        text-decoration: none;
    }
    
    [data-testid="stSidebarNav"] > div > ul > li > div[data-baseweb="radio"] {
        background-color: rgba(100,149,237,0.3) !important;
        box-shadow: 0 0 0 1px rgba(255,255,255,0.1);
    }
    
    [data-testid="stSidebar"] .stRadio > div {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .sidebar-divider {
        height: 1px;
        background: rgba(255,255,255,0.1);
        margin: 1.5rem 0;
    }
    
    .user-avatar {
        width: 60px;
        height: 60px;
        border-radius: 50%;
        margin: 0 auto 1rem;
        background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
        color: white;
        font-weight: bold;
    }
    
    .user-name {
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 0.25rem;
    }
    
    .sidebar-footer {
        font-size: 0.75rem;
        text-align: center;
        margin-top: 2rem;
        opacity: 0.6;
    }
    
    .stTextInput input, .stTextArea textarea {
        background-color: var(--darker-bg) !important;
        color: var(--text) !important;
        border: 1px solid #2d3748 !important;
        border-radius: 8px;
        padding: 10px;
    }
    
    .stAlert .st-b7 {
        background-color: rgba(40, 167, 69, 0.2) !important;
        color: var(--text) !important;
        border-radius: 8px;
        border-left: 4px solid var(--success);
    }
    
    .stAlert .st-be {
        background-color: rgba(220, 53, 69, 0.2) !important;
        color: var(--text) !important;
        border-radius: 8px;
        border-left: 4px solid var(--error);
    }
    
    .stAlert .st-bb {
        background-color: rgba(23, 162, 184, 0.2) !important;
        color: var(--text) !important;
        border-radius: 8px;
        border-left: 4px solid var(--info);
    }
    
    .card {
        background: var(--card-bg);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        margin-bottom: 20px;
        color: var(--text);
    }
    
    .data-card {
        background: var(--darker-bg);
        border-radius: 8px;
        padding: 15px;
        margin: 10px 0;
        border-left: 4px solid var(--secondary);
    }
    
    .decrypted-content {
        background-color: var(--darker-bg) !important;
        color: var(--text) !important;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
        border-left: 4px solid var(--success);
        white-space: pre-wrap;
        word-wrap: break-word;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: var(--text) !important;
    }
    
    .lockout {
        background-color: rgba(253, 126, 20, 0.2);
        color: var(--text);
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        margin: 20px 0;
        border-left: 4px solid var(--warning);
    }
    
    p, div {
        color: var(--text);
    }
    
    ::-webkit-scrollbar {
        width: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: var(--darker-bg);
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--primary);
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: var(--secondary);
    }
    
    .empty-state {
        text-align: center;
        padding: 40px 20px;
    }

    div.stButton > button { 
        color: black;
    }            

    </style>
    """, unsafe_allow_html=True)


def login_ui():
    apply_custom_styles()
    
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        <div style='padding: 20px 0;'>
            <h1 style='color: #2575fc; margin-bottom: 10px;'>🔐 Secure Vault</h1>
            <p style='font-size: 18px; color: var(--text-muted);'>Your personal encryption solution</p>
        </div>
        """, unsafe_allow_html=True)
    
    if st.session_state.failed_attempts >= 3:
        if st.session_state.lockout_time is None:
            st.session_state.lockout_time = time.time()

        time_left = int(30 - (time.time() - st.session_state.lockout_time))

        if time_left > 0:
            st.markdown(f"""
            <div class='lockout'>
                <h3>🚨 Account Temporarily Locked</h3>
                <p>Too many failed attempts. Please wait {time_left} seconds before trying again.</p>
            </div>
            """, unsafe_allow_html=True)
            time.sleep(1)
            st.rerun()
        else:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            st.rerun()
        return

    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        
        st.markdown("### Sign In to Your Account")
        st.markdown("Enter your credentials to access your encrypted data")
        
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Login", use_container_width=True)

            if submitted:
                if not username or not password:
                    st.error("Both username and password are required")
                else:
                    user = get_user(username)
                    if user and verify_password(password, user[1]):
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.failed_attempts = 0
                        st.success("✅ Login successful! Redirecting...")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.session_state.failed_attempts += 1
                        st.error(f"❌ Invalid credentials. Attempt {st.session_state.failed_attempts}/3")
                        if st.session_state.failed_attempts >= 3:
                            st.session_state.lockout_time = time.time()
                            st.rerun()
        
        st.markdown("<div style='text-align: center; margin-top: 20px;'>", unsafe_allow_html=True)
        st.markdown("Don't have an account?")
        if st.button("Register Now", key="register_btn"):
            st.session_state.show_register = True
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)

def register_ui():
    apply_custom_styles()
    
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        <div style='padding: 20px 0;'>
            <h1 style='color: #2575fc; margin-bottom: 10px;'>📝 Create Account</h1>
            <p style='font-size: 18px; color: var(--text-muted);'>Join Secure Vault today</p>
        </div>
        """, unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        
        with st.form("register_form"):
            st.markdown("### Register New Account")
            username = st.text_input("Username", placeholder="Choose a username")
            password = st.text_input("Password", type="password", placeholder="Create a password")
            confirm = st.text_input("Confirm Password", type="password", placeholder="Re-enter your password")
            submitted = st.form_submit_button("Register", use_container_width=True)

            if submitted:
                if not username or not password or not confirm:
                    st.error("All fields are required")
                elif password != confirm:
                    st.error("Passwords do not match")
                elif get_user(username):
                    st.error("Username already exists")
                else:
                    if create_user(username, password):
                        st.success("🎉 Account created successfully! Redirecting to login...")
                        st.session_state.show_register = False
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Failed to create account. Please try again.")
        
        st.markdown("<div style='text-align: center; margin-top: 20px;'>", unsafe_allow_html=True)
        if st.button("Back to Login", key="back_login_btn"):
            st.session_state.show_register = False
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)

def home_page():
    apply_custom_styles()
    
    with st.sidebar:
        st.markdown(f"""
        <div class="sidebar-header">
            <div class="user-avatar">
                {st.session_state.username[0].upper()}
            </div>
            <div class="user-name">{st.session_state.username}</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="sidebar-divider"></div>', unsafe_allow_html=True)
        
        menu = st.radio(
            "Navigation",
            ["Encrypt Data", "Retrieve Data", "Logout"],
            label_visibility="collapsed",
            format_func=lambda x: {
                "Encrypt Data": "🔒 Encrypt Data",
                "Retrieve Data": "🔓 Retrieve Data", 
                "Logout": "🚪 Logout"
            }[x]
        )
        
        st.markdown("""
        <div class="sidebar-footer">
            Secure Vault v1.0<br>
            © 2025 All rights reserved
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown(f"# 🔐 Secure Vault")
    st.markdown(f"Welcome back, **{st.session_state.username}**! What would you like to do today?")
    
    if menu == "Encrypt Data":
        st.markdown("## 🔒 Encrypt & Store Data")
        with st.container():
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            
            text = st.text_area("Enter text to encrypt", height=150, 
                              placeholder="Type or paste your sensitive information here...")
            passkey = st.text_input("Encryption passkey", type="password", 
                                   placeholder="Enter a strong passkey (remember this!)")
            
            if st.button("Encrypt & Store", key="encrypt_btn"):
                if text and passkey:
                    encrypted, salt = encrypt_data(text, passkey)
                    store_encrypted_data(st.session_state.username, encrypted, salt)
                    st.success("✅ Data encrypted and stored securely!")
                else:
                    st.error("Please provide both text to encrypt and a passkey")
            
            st.markdown("</div>", unsafe_allow_html=True)
            
            st.markdown("""
            <div class='card'>
                <h4>🔒 Encryption Tips</h4>
                <ul>
                    <li>Use a strong, unique passkey that you can remember</li>
                    <li>Never share your passkey with anyone</li>
                    <li>The same passkey is required to decrypt your data</li>
                    <li>For maximum security, use a passphrase instead of a simple password</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

    elif menu == "Retrieve Data":
        st.markdown("## 🔓 Retrieve & Decrypt Data")
        with st.container():
            user_entries = get_user_data(st.session_state.username)
            
            if not user_entries:
                st.markdown("""
                <div class='card'>
                    <div class='empty-state'>
                        <h4>🔍 No Encrypted Data Found</h4>
                        <p>You haven't stored any encrypted data yet.</p>
                        <p>Use the "Encrypt Data" section to store your first secret!</p>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                passkey = st.text_input("Decryption passkey", type="password", 
                                      placeholder="Enter your passkey to decrypt data",
                                      key="decrypt_passkey")
                
                if st.button("Decrypt All", key="decrypt_btn"):
                    with st.spinner("Decrypting your data..."):
                        for entry in user_entries:
                            try:
                                decrypted = decrypt_data(entry[1], passkey, entry[2])
                                st.markdown(f"""
                                <div class='card'>
                                    <h4>Entry from {entry[3]}</h4>
                                    <div class='decrypted-content'>
                                        {decrypted}
                                    </div>
                                </div>
                                """, unsafe_allow_html=True)
                            except Exception as e:
                                st.error(f"❌ Failed to decrypt entry. Please check your passkey and try again.")

    elif menu == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.success("👋 You have been logged out successfully.")
        time.sleep(1)
        st.rerun()

def main():
    st.set_page_config(
        page_title="Secure Vault",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    if not st.session_state.logged_in:
        if st.session_state.show_register:
            register_ui()
        else:
            login_ui()
    else:
        home_page()

if __name__ == '__main__':
    main()


