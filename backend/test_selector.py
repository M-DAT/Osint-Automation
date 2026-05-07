from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth
import time
with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()
    Stealth().apply_stealth_sync(page)
    page.goto("https://haveibeenpwned.com/Passwords", wait_until="domcontentloaded")
    time.sleep(2)
    page.type("input[type='password']", "admin")
    page.keyboard.press("Enter")
    time.sleep(5)
    print("H2 Texts:", [el.inner_text() for el in page.query_selector_all("h2")])
    html = page.content()
    with open("page.html", "w") as f:
        f.write(html)
    browser.close()
