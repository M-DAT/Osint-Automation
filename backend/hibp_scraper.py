import sys
import time
import argparse
from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth

def simulate_typing(page, selector, text):
    page.click(selector)
    time.sleep(0.5)
    page.type(selector, text, delay=100) # 100ms between keystrokes
    time.sleep(1)

def check_password(target):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False) # Headless=False is crucial to bypass Cloudflare
        context = browser.new_context()
        page = context.new_page()
        Stealth().apply_stealth_sync(page)

        print(f"[*] Navigating to HIBP Passwords...")
        page.goto("https://haveibeenpwned.com/Passwords", wait_until="domcontentloaded")
        time.sleep(2)

        print(f"[*] Entering password with human typing delay...")
        simulate_typing(page, "input[type='password'], input#Password", target)

        print(f"[*] Submitting form...")
        page.keyboard.press("Enter")
        
        print(f"[*] Waiting for results...")
        try:
            page.wait_for_selector("#pwned-result-bad:visible, #pwned-result-good:visible", timeout=15000)
            
            pwned_result = page.locator("#pwned-result-bad")
            no_pwnage_result = page.locator("#pwned-result-good")
            
            if pwned_result.is_visible():
                heading = pwned_result.locator("h3").inner_text() if pwned_result.locator("h3").is_visible() else "Oh no — pwned!"
                desc = pwned_result.locator("p").first.inner_text().replace('\n', ' ')
                result = f"[!] {heading} - {desc}"
            elif no_pwnage_result.is_visible():
                heading = no_pwnage_result.locator("h3").inner_text() if no_pwnage_result.locator("h3").is_visible() else "Good news — no pwnage found!"
                desc = no_pwnage_result.locator("p").first.inner_text().replace('\n', ' ')
                result = f"[+] {heading} - {desc}"
            else:
                result = "[?] Unknown result. Banners not matched."
        except Exception as e:
            result = f"[?] Could not find the result container. Cloudflare block or network timeout? Error: {e}"
        
        browser.close()
        return {"ok": True, "result": result}

def check_email(target):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = context.new_page()
        Stealth().apply_stealth_sync(page)

        print(f"[*] Navigating to HIBP Home...")
        page.goto("https://haveibeenpwned.com/", wait_until="domcontentloaded")
        time.sleep(2)

        print(f"[*] Entering email with human typing delay...")
        simulate_typing(page, "input[type='email'], input#emailInput, input#Account", target)

        print(f"[*] Submitting form...")
        page.keyboard.press("Enter")
        
        print(f"[*] Waiting for results...")
        try:
            page.wait_for_selector("#email-result-bad:visible, #email-result-good:visible", state="visible", timeout=15000)
            
            pwned_result = page.locator("#email-result-bad")
            no_pwnage_result = page.locator("#email-result-good")
            
            if pwned_result.is_visible():
                heading = pwned_result.locator(".result-message").inner_text().replace('\n', ' ') if pwned_result.locator(".result-message").is_visible() else "Oh no — pwned!"
                count = pwned_result.locator(".result-count").inner_text() if pwned_result.locator(".result-count").is_visible() else ""
                result = f"[!] {heading} (Breaches: {count})"
            elif no_pwnage_result.is_visible():
                heading = no_pwnage_result.locator(".result-message").inner_text().replace('\n', ' ') if no_pwnage_result.locator(".result-message").is_visible() else "Good news — no pwnage found!"
                result = f"[+] {heading}"
            else:
                result = "[?] Unknown result. Banners not matched."
        except Exception as e:
             result = f"[?] Could not find the result container. Cloudflare block or timeout? Error: {e}"

        browser.close()
        return {"ok": True, "result": result}

def check_hibp(target, check_type):
    if check_type == "password":
        return check_password(target)
    else:
        return check_email(target)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape HIBP with human-like behavior")
    parser.add_argument("--type", choices=["email", "password"], required=True, help="Type of target to check")
    parser.add_argument("--target", required=True, help="Email or password to check")
    args = parser.parse_args()

    if args.type == "password":
        check_password(args.target)
    else:
        check_email(args.target)
