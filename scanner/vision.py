import base64
from playwright.sync_api import sync_playwright
import logging

def generate_screenshot(url):
    """
    Uses Playwright to quickly visit a URL and take a screenshot.
    Returns the screenshot as a base64 encoded string.
    """
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            # Timeout is critical for malicious/unresponsive sites
            page.goto(url, timeout=10000, wait_until="networkidle") 
            
            # Take a small screenshot
            screenshot_bytes = page.screenshot(type="jpeg", quality=50)
            browser.close()
            
            return base64.b64encode(screenshot_bytes).decode('utf-8')
    except Exception as e:
        logging.error(f"Playwright screenshot failed for {url}: {e}")
        return None
