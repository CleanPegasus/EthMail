import hashlib

def compute_sha256(input_string):
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Update the hash object with the bytes of the input string
    sha256_hash.update(input_string.encode('utf-8'))

    # Get the hexadecimal representation of the hash
    hex_digest = sha256_hash.hexdigest()

    return hex_digest

input_string = '10'
hashed_output = compute_sha256(input_string)
print(f"The SHA-256 hash of the input is: {hashed_output}")
