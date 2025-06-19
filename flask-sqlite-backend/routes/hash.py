from werkzeug.security import generate_password_hash, check_password_hash

def demonstrate_password_hashing():
   
    password = "12345678"
    
  
    hashed_password = generate_password_hash(password)
    
    print("\n=== Password Hashing Demonstration ===")
    print(f"Original Password: {password}")
    print(f"Hashed Password: {hashed_password}")
    

    if hashed_password.startswith('pbkdf2:sha256:'):
        parts = hashed_password.split('$')
        print("\nHash Structure Breakdown:")
        print(f"1. Algorithm: {parts[0]}") 
        print(f"2. Salt: {parts[1]}")      
        print(f"3. Hash: {parts[2]}")     
    
   
    print("\nVerification Tests:")
    print(f"Check 'correct_password': {check_password_hash(hashed_password, 'correct_password')}")  # False
    print(f"Check 'my_secure_password123': {check_password_hash(hashed_password, password)}")       # True

if __name__ == "__main__":
    demonstrate_password_hashing()