## This is not part of the sytstem , a simple utility i used to polpulate the db for testing

import bcrypt

# Password to hash
password = "test"

# Generate a salt and hash the password
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

# Print the hashed password
print(hashed_password.decode('utf-8'))

## generate otp secret key

import base64
import pyotp
import os

# Generate a random secret key (you can also use your own secret key)
secret_key_bytes = os.urandom(10)  # Generate 10 random bytes
base32_secret = base64.b32encode(secret_key_bytes).decode('utf-8')  # Encode bytes to base32 string

print("Sample Base32-encoded Secret Key:", base32_secret)

# Example of using the generated secret key to create a TOTP object
totp = pyotp.TOTP(base32_secret)
print("Sample TOTP:", totp.now()