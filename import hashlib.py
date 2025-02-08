import hashlib
import requests

def check_password_strength(password):
    # Check password length and complexity
    if len(password) < 8:
        return "Weak: Password is too short."
    if not any(char.isdigit() for char in password):
        return "Weak: Password must contain at least one digit."
    if not any(char.isupper() for char in password):
        return "Weak: Password must contain at least one uppercase letter."
    if not any(char.islower() for char in password):
        return "Weak: Password must contain at least one lowercase letter."
    return "Strong: Password meets the criteria."

def check_password_breach(password):
    # Hash the password using SHA-1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    # Check password against Have I Been Pwned API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    if response.status_code != 200:
        return "Error: Unable to check password breach."
    
    # Compare suffix with API results
    for line in response.text.splitlines():
        if suffix in line:
            return f"Compromised: This password has been exposed {line.split(':')[1]} times."
    
    return "Safe: This password has not been exposed in any known data breaches."

def main():
    password = input("Enter a password to check: ")
    print(check_password_strength(password))
    print(check_password_breach(password))

if __name__ == "__main__":
    main()

