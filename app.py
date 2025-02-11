from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import os

def test_selenium_setup():
    """
    Tests basic Selenium setup: ChromeDriver download and browser launch.
    Prints success or error messages to the console.
    """
    print("Starting Selenium setup test...")

    options = webdriver.ChromeOptions()
    options.add_argument("--headless")  # Run in headless mode (no browser window)
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = None  # Initialize driver to None for the finally block
    try:
        print("Attempting to download ChromeDriver using ChromeDriverManager...")
        driver_path = ChromeDriverManager().install()
        print(f"ChromeDriver downloaded successfully to: {driver_path}")

        service = Service(driver_path)
        print("Launching ChromeDriver...")
        driver = webdriver.Chrome(service=service, options=options)
        print("ChromeDriver launched successfully!")

        print("Testing basic browser interaction: Getting page title...")
        driver.get("https://www.google.com") # Open a simple webpage
        title = driver.title
        print(f"Page title of google.com: {title}")
        if "Google" in title:
            print("Successfully retrieved page title. Selenium setup seems to be working!")
        else:
            print(f"Warning: Page title does not contain 'Google'. Something might be wrong. Title was: {title}")

        print("Selenium test completed successfully.")

    except Exception as e:
        print(f"Error during Selenium setup test: {e}")
        print("Selenium setup test failed.")

    finally:
        if driver:
            print("Closing the browser session...")
            driver.quit()
            print("Browser session closed.")
        else:
            print("No browser session to close (driver was not initialized due to error).")

if __name__ == "__main__":
    test_selenium_setup()