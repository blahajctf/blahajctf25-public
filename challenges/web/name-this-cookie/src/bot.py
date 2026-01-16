from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

FLAG = open('flag.txt').read().strip()

def setup_driver():
    """Set up Chrome driver with security options"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-plugins")
    chrome_options.add_argument("--disable-images")

    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(10)
        return driver
    except Exception as e:
        print(f"Error setting up Chrome driver: {e}")
        return None

def bot_visit(cookie_name: str):
    driver = setup_driver()
    if not driver:
        return False, "Failed to initialize browser"

    try:
        driver.get(f'http://localhost:5000/set-cookie?value={FLAG}&name={cookie_name}')
        time.sleep(1)
        driver.get('http://localhost:5000/')
        time.sleep(2)

        return True, "Successfully visited URL"

    except Exception as e:
        print(f"Error during browser automation: {e}")
        return False, f"Browser error: {str(e)}"

    finally:
        driver.quit()
