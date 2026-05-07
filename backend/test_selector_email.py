from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth
import time
with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()
    Stealth().apply_stealth_sync(page)
    page.goto("https://haveibeenpwned.com/", wait_until="domcontentloaded")
    time.sleep(2)
    page.type("input[type='email']", "shehabd2023@gmail.com")
    page.keyboard.press("Enter")
    time.sleep(5)
    html = page.content()
    with open("page_email.html", "w") as f:
        f.write(html)
    browser.close()
