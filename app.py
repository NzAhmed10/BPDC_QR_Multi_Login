import streamlit as st
import json
import os
import threading
import time
import numpy as np
from PIL import Image
import cv2  # Replaced pyzbar with opencv-python
from cryptography.fernet import Fernet
import datetime
import pandas as pd

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# ======================================================
# Logging Functions
# ======================================================

LOG_FILE = "app_log.txt"

def log_event(message):
    """Log an important event with a timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    with open(LOG_FILE, "a") as log:
        log.write(log_entry)

def load_logs():
    """Load all log entries."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as log:
            return log.readlines()
    return []

def clear_logs():
    """Clear the log file."""
    with open(LOG_FILE, "w") as log:
        log.write("")

# ======================================================
# Credential Encryption and Storage Functions
# ======================================================

def load_key():
    """Load encryption key from file or generate one if not present."""
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

key = load_key()
fernet = Fernet(key)

def load_credentials():
    """Load and decrypt credentials from local file."""
    if os.path.exists("credentials.enc"):
        with open("credentials.enc", "rb") as file:
            encrypted_data = file.read()
        try:
            decrypted_data = fernet.decrypt(encrypted_data).decode()
            credentials = json.loads(decrypted_data)
            # Ensure backward compatibility: add "nickname" if missing
            for cred in credentials:
                if "nickname" not in cred:
                    cred["nickname"] = "Unknown"
            return credentials
        except Exception as e:
            log_event(f"Error decrypting credentials: {e}")
            st.error("Error decrypting credentials: " + str(e))
            return []
    else:
        return []

def save_credentials(credentials):
    """Encrypt and save credentials to local file."""
    data_str = json.dumps(credentials)
    encrypted_data = fernet.encrypt(data_str.encode())
    with open("credentials.enc", "wb") as file:
        file.write(encrypted_data)

# ======================================================
# QR Code Decoding with OpenCV
# ======================================================

def decode_qr_code(image):
    """Decode QR code using OpenCV."""
    # Convert the image to a numpy array
    img_array = np.array(image)
    
    # Convert to grayscale (required by OpenCV's QR code detector)
    gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY)
    
    # Initialize the QR code detector
    detector = cv2.QRCodeDetector()
    
    # Detect and decode the QR code
    data, bbox, _ = detector.detectAndDecode(gray)
    
    if bbox is not None:
        return data
    return None

# ======================================================
# Selenium Login Function
# ======================================================

def login_to_lms(account, drivers_list):
    """Log into BITS LMS using Selenium for a single account and add the driver to drivers_list."""
    nickname = account.get("nickname", "Unknown")
    email = account["email"]
    password = account["password"]
    options = webdriver.ChromeOptions()
    options.add_argument("--start-maximized")

    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    except Exception as e:
        st.error(f"Error launching ChromeDriver for {nickname}: {e}")
        log_event(f"Error launching ChromeDriver for {nickname}: {e}")
        return

    drivers_list.append(driver)
    try:
        driver.get("https://lms.bits-pilani.ac.in/")
        wait = WebDriverWait(driver, 10)
        google_login_button = wait.until(
            EC.element_to_be_clickable((By.XPATH, "//*[@id='region-main']/div[1]/div[1]/div[1]/div[1]/div[3]/a[1]"))
        )
        google_login_button.click()
        time.sleep(2)
        email_field = wait.until(EC.presence_of_element_located((By.XPATH, "//input[@type='email']")))
        email_field.send_keys(email)
        email_field.send_keys(Keys.RETURN)
        time.sleep(3)
        password_field = wait.until(EC.presence_of_element_located((By.XPATH, "//input[@type='password']")))
        password_field.send_keys(password)
        password_field.send_keys(Keys.RETURN)
        time.sleep(5)
        st.write(f"✅ {nickname} logged in successfully!")
        log_event(f"{nickname} logged in successfully")
    except Exception as e:
        st.write(f"❌ Error logging in for {nickname}: {e}")
        log_event(f"Error logging in for {nickname}: {e}")

# ======================================================
# Streamlit App Interface
# ======================================================

st.set_page_config(page_title="BITS LMS Multi-Account Login & QR Redirect", layout="wide")
st.title("BITS LMS Multi-Account Login & QR Redirect App")

# Sidebar Navigation (only two pages now)
menu = st.sidebar.radio("Navigation", ["Manage Credentials", "Login & QR Redirect"])

# ----- Manage Credentials Page -----
if menu == "Manage Credentials":
    st.header("Manage Gmail Credentials")
    credentials = load_credentials()

    with st.form("add_account_form"):
        new_nickname = st.text_input("Nickname (e.g., 'Personal', 'Work')")
        new_email = st.text_input("Gmail")
        new_password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Add Account")
        if submitted:
            if new_nickname and new_email and new_password:
                credentials.append({
                    "nickname": new_nickname,
                    "email": new_email,
                    "password": new_password
                })
                save_credentials(credentials)
                log_event(f"New account added: {new_nickname}")
                st.success("Account added successfully!")
                st.rerun()
            else:
                st.error("Please provide all details.")

    if credentials:
        st.subheader("Stored Accounts")
        df = pd.DataFrame([
            {"Nickname": cred.get("nickname", "Unknown"), "Email": cred["email"]}
            for cred in credentials
        ])
        st.dataframe(df, use_container_width=True)

        st.subheader("Delete an Account")
        delete_option = st.selectbox("Select account to delete", options=[cred["nickname"] for cred in credentials])
        if st.button("Delete Selected Account"):
            credentials = [cred for cred in credentials if cred["nickname"] != delete_option]
            save_credentials(credentials)
            log_event(f"Deleted account: {delete_option}")
            st.success(f"Deleted account: {delete_option}")
            st.rerun()
    else:
        st.info("No accounts stored.")

# ----- Login & QR Redirect Page -----
elif menu == "Login & QR Redirect":
    st.header("Login to LMS & Redirect via Captured QR Code")
    credentials = load_credentials()
    st.write(f"**Total accounts:** {len(credentials)}")

    if st.button("Start Login Process"):
        clear_logs()  # Clear any logs from previous sessions
        log_event("Starting new login process...")
        if not credentials:
            st.error("No credentials found. Please add credentials first in the 'Manage Credentials' page.")
        else:
            drivers = []  # This list will store Selenium driver sessions
            threads = []
            for account in credentials:
                t = threading.Thread(target=login_to_lms, args=(account, drivers))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            st.session_state["drivers"] = drivers
            st.success("All accounts are logged in!")
            st.write(f"**Number of active sessions:** {len(drivers)}")
            log_event("All accounts logged in successfully.")

    if "drivers" in st.session_state:
        st.subheader("QR Code Scanner via Camera")
        st.info("Capture a picture of the QR code using your camera.")
        captured_img = st.camera_input("Take a picture of the QR code")
        if captured_img is not None:
            # Open the captured image using PIL
            image = Image.open(captured_img)
            
            # Decode the QR code
            qr_data = decode_qr_code(image)
            
            if qr_data:
                st.success(f"QR Code Detected: {qr_data}")
                if st.button("Redirect All Sessions"):
                    for driver in st.session_state["drivers"]:
                        try:
                            driver.get(qr_data)
                        except Exception as e:
                            st.write(f"Error redirecting one session: {e}")
                    log_event(f"Redirected all sessions to {qr_data}")
                    st.success("All sessions redirected successfully!")
            else:
                st.info("No QR code detected in the captured image. Please try again.")

    st.subheader("Logs (New Session)")
    logs = load_logs()
    if logs:
        st.text("".join(logs))
    else:
        st.info("No logs available.")

# ----- Sidebar: Close All Sessions Button -----
if st.sidebar.button("Close All Sessions"):
    if "drivers" in st.session_state:
        for driver in st.session_state["drivers"]:
            try:
                driver.quit()
            except Exception:
                pass
        del st.session_state["drivers"]
        log_event("Closed all sessions.")
        st.success("All sessions closed!")
    else:
        st.info("No active sessions to close.")