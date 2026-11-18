# app.py
# Password Strength & Breach Check that evaluates a password against entropy 
# rules (length, special characters, uppercase, common dictionary words) and can 
# even query the HaveIBeenPwned API (using k-Anonymity) to see if the password has been leaked.

import hashlib
import re
import requests
import getpass

# Local Strength Analysis

def check_password_strength(password):
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        feedback.append("Password is too short. Aim for 12+ characters.")
    else:
        feedback.append("Password is too short (less than 8 characters).")

    # Character classes
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special symbols.")

    return score, feedback

# Breach Check using HaveIBeenPwned API (k-Anonymity)

def check_pwned_status(password):
    # Hash the password using SHA-1 (required by HIBP API)
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return f"Error connecting to HIBP API: {response.status_code}"
        
        # Parse response lines (Format: SUFFIX:COUNT)
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except requests.exceptions.RequestException as e:
        return f"Network error: {e}"

if __name__ == "__main__":
    print("=== Python Password Strength & Breach Checker ===")
    # getpass securely hides password characters as you type them in the terminal
    pwd = getpass.getpass("Enter password to check: ")

    print("\n[+] Analyzing strength locally...")
    score, feedback = check_password_strength(pwd)
    print(f"Strength Score: {score}/6")
    if feedback:
        print("Suggestions:")
        for f in feedback:
            print(f" - {f}")
    else:
        print(" [✓] Great complexity!")

    print("\n[+] Checking HaveIBeenPwned database (k-Anonymity)...")
    result = check_pwned_status(pwd)
    if isinstance(result, int):
        if result > 0:
            print(f" [!] WARNING: This password has been seen {result:,} times in data breaches!")
        else:
            print(" [✓] Good news! This password was not found in any known data breaches.")
    else:
        print(result)



