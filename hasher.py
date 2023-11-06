## This is not part of the sytstem , a simple utility i used to polpulate the db for testing

import bcrypt

# Password to hash
password = "test"

# Generate a salt and hash the password
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

# Print the hashed password
print(hashed_password.decode('utf-8'))
