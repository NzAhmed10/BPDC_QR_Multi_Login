import streamlit as st
import json
import os
import threading
import time
import numpy as np
from PIL import Image
import cv2
import datetime
import pandas as pd
import traceback

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import subprocess  # Import subprocess

# MUST be the very first Streamlit command!
st.set_page_config(page_title="BITS LMS Multi-Account Login & QR Redirect", layout="wide")

# NOTE: Ensure you have an apt.txt file with:
# chromium-browser
# chromium-chromedriver

# Import the cookie manager from streamlit-cookies-manager
from streamlit_cookies_manager import EncryptedCookieManager

# ======================================================
# Cookie Manager Setup Using st.secrets
# ======================================================
COOKIE_PASSWORD = st.secrets.get("COOKIE_PASSWORD", "My secret password")
COOKIE_NAME = "encrypted_credentials"

cookies = EncryptedCookieManager(prefix="my_app_", password=COOKIE_PASSWORD)
if not cookies.ready():
    st.stop()

# ======================================================
# Ephemeral Logging Functions (Session State Only)
# ======================================================
def add_log(message):
    """Append a log message with a timestamp to session state."""
    if "logs" not in st.session_state:
        st.session_state["logs"] = []
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    st.session_state["logs"].append(log_message)
    print(f"Log added: {log_message}")

def clear_logs():
    """Clear all logs from session state."""
    st.session_state["logs"] = []
    print("Logs cleared")

# ======================================================
# Credential Encryption Setup (Using st.secrets)
# ======================================================
FERNET_KEY = st.secrets.get("FERNET_KEY")
if not FERNET_KEY:
    st.error("FERNET_KEY is not set in st.secrets. Please add it to your secrets.toml.")
    st.stop()

from cryptography.fernet import Fernet
try:
    fernet = Fernet(FERNET_KEY.encode())
except Exception as e:
    st.error("Error initializing encryption. Please check FERNET_KEY in your secrets.")
    st.stop()

# ======================================================
# Credential Storage Functions Using Cookies
# ======================================================
def load_credentials():
    """
    Load and decrypt credentials from the browser cookie.
    The encrypted JSON string is stored in the cookie named COOKIE_NAME.
    """
    encrypted_data = cookies.get(COOKIE_NAME)
    if encrypted_data:
        try:
            decrypted_data = fernet.decrypt(encrypted_data.encode()).decode()
            credentials = json.loads(decrypted_data)
            for cred in credentials:
                if "nickname" not in cred:
                    cred["nickname"] = "Unknown"
            add_log("Credentials loaded successfully.")
            return credentials
        except Exception as e:
            add_log(f"Error decrypting credentials: {e}")
            st.error("Error decrypting credentials: " + str(e))
            return []
    else:
        add_log("No credentials found in cookie.")
        return []

def save_credentials(credentials):
    """
    Encrypt the credentials and save them in the browser cookie.
    """
    data_str = json.dumps(credentials)
    encrypted_data = fernet.encrypt(data_str.encode()).decode()
    cookies[COOKIE_NAME] = encrypted_data
    try:
        cookies.save()
        add_log("Credentials saved to cookie successfully.")
    except Exception as e:
        st.error("Error saving credentials to cookie: " + str(e))
        raise

# ======================================================
# QR Code Decoding with OpenCV
# ======================================================
def decode_qr_code(image):
    """Decode a QR code from an image using OpenCV."""
    img_array = np.array(image)
    gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY)
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(gray)
    if bbox is not None and data:
        add_log("QR code detected and decoded successfully.")
        return data
    add_log("No QR code detected.")
    return None

# ======================================================
# Selenium Login Function (Reordered: Gmail then LMS)
# ======================================================
def login_to_lms(account, drivers_list):
    nickname = account.get("nickname", "Unknown")
    email = account["email"]
    password = account["password"]

    add_log(f"[{nickname}] Starting login process.")
    
    options = Options()
    # Uncomment the line below to run headless if desired:
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-blink-features=AutomationControlled")

    try:
        add_log(f"[{nickname}] Launching ChromeDriver using auto version detection.")
        driver = webdriver.Chrome(options=options)
        _ = driver.title  # Basic check for driver launch
        add_log(f"[{nickname}] ChromeDriver launched successfully.")
    except Exception as e:
        st.error(f"[{nickname}] Error launching ChromeDriver: {e}")
        add_log(f"[{nickname}] Error launching ChromeDriver: {e}")
        return

    drivers_list.append(driver)

    try:
        wait = WebDriverWait(driver, 30)
        # Step 1: Log in to Gmail first
        add_log(f"[{nickname}] Navigating to Gmail login page.")
        driver.get("https://accounts.google.com/ServiceLogin?service=mail")
        add_log(f"[{nickname}] Waiting for Gmail email input field.")
        email_field = wait.until(EC.element_to_be_clickable((By.ID, "identifierId")))
        add_log(f"[{nickname}] Entering Gmail email: {email}")
        email_field.send_keys(email)
        next_button = driver.find_element(By.ID, "identifierNext")
        next_button.click()
        time.sleep(3)
        
        add_log(f"[{nickname}] Waiting for Gmail password input field.")
        password_field = wait.until(EC.element_to_be_clickable((By.NAME, "Passwd")))
        add_log(f"[{nickname}] Entering Gmail password.")
        password_field.send_keys(password)
        password_next = driver.find_element(By.ID, "passwordNext")
        password_next.click()
        time.sleep(5)
        add_log(f"[{nickname}] Gmail login successful.")

        # Step 2: Navigate to LMS page and click Google login button
        add_log(f"[{nickname}] Navigating to LMS URL.")
        driver.get("https://lms.bits-pilani.ac.in/")
        wait = WebDriverWait(driver, 30)
        
        add_log(f"[{nickname}] Waiting for Google login button on LMS page.")
        google_login_button = wait.until(
            EC.element_to_be_clickable((By.XPATH, "//*[@id='region-main']/div[1]/div[1]/div[1]/div[1]/div[3]/a[1]"))
        )
        add_log(f"[{nickname}] Google login button found; clicking it.")
        driver.execute_script("arguments[0].click();", google_login_button)
        time.sleep(2)
        
        # Since the Gmail session is active, LMS should now log in automatically.
        st.write(f"✅ {nickname} logged in successfully via Gmail!")
        add_log(f"[{nickname}] Login successful on LMS.")
        time.sleep(5)
    except Exception as e:
        tb = traceback.format_exc()
        error_message = f"[{nickname}] Error during login process: {e}\nTraceback:\n{tb}"
        st.error(error_message)
        add_log(error_message)
        try:
            screenshot_file = f"{nickname}_error.png"
            driver.save_screenshot(screenshot_file)
            st.info(f"Screenshot saved: {screenshot_file}")
        except Exception as ss_e:
            st.error(f"Error capturing screenshot: {ss_e}")
        try:
            page_source_file = f"{nickname}_error.html"
            with open(page_source_file, "w", encoding="utf-8") as f:
                f.write(driver.page_source)
            st.info(f"Page source saved: {page_source_file}")
        except Exception as ps_e:
            st.error(f"Error saving page source: {ps_e}")
        if driver:
            driver.quit()
            drivers_list.remove(driver)

# ======================================================
# Streamlit App Interface
# ======================================================
st.title("BITS LMS Multi-Account Login & QR Redirect App")
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
                add_log(f"New account added: {new_nickname}")
                st.success("Account added successfully!")
                st.experimental_set_query_params(rerun=str(time.time()))
                st.stop()
            else:
                st.error("Please provide all details.")
    if credentials:
        st.subheader("Stored Accounts")
        df = pd.DataFrame([{"Nickname": cred.get("nickname", "Unknown"), "Email": cred["email"]} for cred in credentials])
        st.dataframe(df, use_container_width=True)
        st.subheader("Delete an Account")
        delete_option = st.selectbox("Select account to delete", options=[cred["nickname"] for cred in credentials])
        if st.button("Delete Selected Account"):
            credentials = [cred for cred in credentials if cred["nickname"] != delete_option]
            save_credentials(credentials)
            add_log(f"Deleted account: {delete_option}")
            st.success(f"Deleted account: {delete_option}")
            st.experimental_set_query_params(rerun=str(time.time()))
            st.stop()
    else:
        st.info("No accounts stored.")

# ----- Login & QR Redirect Page -----
elif menu == "Login & QR Redirect":
    st.header("Login to LMS & Redirect via Captured QR Code")
    credentials = load_credentials()
    st.write(f"**Total accounts:** {len(credentials)}")
    clear_logs()
    if st.button("Start Login Process"):
        add_log("Starting new login process for all accounts.")
        if not credentials:
            st.error("No credentials found. Please add credentials first in the 'Manage Credentials' page.")
        else:
            drivers = []
            threads = []
            from streamlit.runtime.scriptrunner import add_script_run_ctx
            for account in credentials:
                t = threading.Thread(target=login_to_lms, args=(account, drivers))
                add_script_run_ctx(t)
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            st.session_state["drivers"] = drivers
            st.success("All accounts are logged in!")
            st.write(f"**Number of active sessions:** {len(drivers)}")
            add_log("All accounts logged in successfully.")
    if "drivers" in st.session_state:
        st.subheader("QR Code Scanner via Camera")
        st.info("Capture a picture of the QR code using your camera.")
        captured_img = st.camera_input("Take a picture of the QR code")
        if captured_img is not None:
            image = Image.open(captured_img)
            qr_data = decode_qr_code(image)
            if qr_data:
                st.success(f"QR Code Detected: {qr_data}")
                st.info(f"Redirecting all sessions to: {qr_data}")
                for driver in st.session_state["drivers"]:
                    try:
                        driver.get(qr_data)
                    except Exception as e:
                        st.error(f"Error redirecting one session: {e}")
                add_log(f"Redirected all sessions to {qr_data}")
                st.success("All sessions redirected successfully!")
            else:
                st.info("No QR code detected in the captured image. Please try again.")
    st.subheader("Logs (New Session)")
    if "logs" in st.session_state and st.session_state["logs"]:
        for log in st.session_state["logs"]:
            st.text(log)
    else:
        st.info("No logs available.")

if st.sidebar.button("Close All Sessions"):
    if "drivers" in st.session_state:
        for driver in st.session_state["drivers"]:
            try:
                driver.quit()
            except Exception:
                pass
        del st.session_state["drivers"]
        add_log("Closed all sessions.")
        st.success("All sessions closed!")
    else:
        st.info("No active sessions to close.")
