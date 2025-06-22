import bcrypt
import random
import json
import os
from datetime import datetime, timedelta

# File to store hashed passwords
PASSWORD_FILE = "password_storage.json"

# Task 1: Secure Password Storage Implementation
def hash_password(password):
    """
    Hash a password with a random salt using bcrypt
    
    Args:
        password (str): The password to hash
    
    Returns:
        bytes: The hashed password with salt embedded
    """
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def verify_password(stored_hash, provided_password):
    """
    Verify if the provided password matches the stored hash
    
    Args:
        stored_hash (bytes): The stored hashed password
        provided_password (str): The password to check
    
    Returns:
        bool: True if the password matches, False otherwise
    """
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash)

def save_user_credentials(username, hashed_password):
    """
    Save user credentials to a JSON file
    
    Args:
        username (str): The username
        hashed_password (bytes): The hashed password
    """
    # Convert bytes to string for JSON storage
    hashed_str = hashed_password.decode('utf-8')
    
    # Load existing users if file exists
    users = {}
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as file:
            users = json.load(file)
    
    # Add or update user
    users[username] = hashed_str
    
    # Save to file
    with open(PASSWORD_FILE, 'w') as file:
        json.dump(users, file, indent=4)
    
    print(f"User '{username}' saved successfully.")

def load_user_password(username):
    """
    Load a user's hashed password from storage
    
    Args:
        username (str): The username to load
        
    Returns:
        bytes: The hashed password or None if user doesn't exist
    """
    if not os.path.exists(PASSWORD_FILE):
        return None
    
    with open(PASSWORD_FILE, 'r') as file:
        users = json.load(file)
    
    if username not in users:
        return None
    
    # Convert string back to bytes
    return users[username].encode('utf-8')

# Task 2: Multi-Factor Authentication Implementation
def generate_otp():
    """
    Generate a 6-digit OTP code
    
    Returns:
        str: The OTP code
    """
    return str(random.randint(100000, 999999))

# Store active OTPs: {username: {'otp': code, 'expires': timestamp}}
active_otps = {}

def send_otp(username):
    """
    Simulate sending an OTP to a user
    In a real system, this would send the OTP via SMS, email, etc.
    
    Args:
        username (str): The username to send OTP for
        
    Returns:
        str: The generated OTP (in a real system, this wouldn't be returned)
    """
    otp = generate_otp()
    # Set OTP expiry to 5 minutes from now
    expires = datetime.now() + timedelta(minutes=5)
    
    active_otps[username] = {
        'otp': otp,
        'expires': expires
    }
    
    print(f"OTP sent to {username}: {otp}")
    print("(In a real system, this would be sent securely to the user's device)")
    
    return otp

def verify_otp(username, provided_otp):
    """
    Verify if the provided OTP is valid for the user
    
    Args:
        username (str): The username
        provided_otp (str): The OTP to verify
        
    Returns:
        bool: True if OTP is valid, False otherwise
    """
    if username not in active_otps:
        return False
    
    otp_data = active_otps[username]
    
    # Check if OTP is expired
    if datetime.now() > otp_data['expires']:
        del active_otps[username]
        return False
    
    # Check if OTP matches
    if otp_data['otp'] == provided_otp:
        del active_otps[username]
        return True
    
    return False

def register_user():
    """Interactive function to register a new user"""
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    hashed_password = hash_password(password)
    save_user_credentials(username, hashed_password)
    
    print("\nUser registered successfully!")
    print("Password has been securely hashed with bcrypt and stored.")

def login_user():
    """Interactive function to login a user with MFA"""
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    # Step 1: Verify password
    stored_hash = load_user_password(username)
    if stored_hash is None:
        print("User not found.")
        return False
    
    if not verify_password(stored_hash, password):
        print("Incorrect password.")
        return False
    
    print("Password verified successfully.")
    
    # Step 2: MFA with OTP
    print("\nInitiating Multi-Factor Authentication...")
    otp = send_otp(username)
    
    # In a real system, we wouldn't show the OTP here
    provided_otp = input("Enter the OTP sent to your device: ")
    
    if verify_otp(username, provided_otp):
        print("OTP verified successfully.")
        print(f"User '{username}' logged in successfully!")
        return True
    else:
        print("Invalid or expired OTP.")
        return False

def explain_security_features():
    """Explain the security features implemented"""
    print("\n--- Security Features Explanation ---")
    
    print("\n## Task 1: Secure Password Storage")
    print("This implementation uses bcrypt for password hashing, which:")
    print("- Automatically generates and incorporates a random salt")
    print("- Uses a one-way hash function that's computationally expensive")
    print("- Is resistant to brute force attacks due to its adaptive nature")
    
    print("\nImportance of Salting:")
    print("- Prevents rainbow table attacks by making pre-computed tables ineffective")
    print("- Ensures that identical passwords have different hash values")
    print("- Increases the complexity and computational cost of cracking attempts")
    
    print("\n## Task 2: Multi-Factor Authentication")
    print("The MFA implementation provides:")
    print("- Something you know (password) + something you have (OTP)")
    print("- Time-limited OTPs that expire after 5 minutes")
    print("- Protection against password-only compromise")
    
    print("\nSecurity Benefits of MFA:")
    print("- Even if a password is compromised, attackers still need the second factor")
    print("- Mitigates the risk of credential stuffing and password spraying attacks")
    print("- Provides an additional layer of security for sensitive operations")
    print("- Can alert users to unauthorized access attempts when they receive unexpected OTPs")

def main():
    """Main function to run the program"""
    while True:
        print("\n=== Password Security & MFA Demo ===")
        print("1. Register a new user")
        print("2. Login")
        print("3. Explain security features")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            register_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            explain_security_features()
        elif choice == '4':
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
