import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# RSA Key Generation and Saving
def generate_keys():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize and save private key
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("priv.pem", 'wb') as priv_pem_file:
        priv_pem_file.write(priv_pem)
    
    # Derive and serialize public key
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("pub.pem", 'wb') as pub_pem_file:
        pub_pem_file.write(pub_pem)

    print("RSA Key pair generated and saved as 'priv.pem' and 'pub.pem'.")

# Load Keys from Environment Variables
def load_keys():
    # Get public key path
    pub_pem = os.environ.get('PUB_PEMK', 'pub.pem')
    with open(pub_pem, 'rb') as pub_key_file:
        public_key = serialization.load_pem_public_key(pub_key_file.read())

    # Get private key path
    priv_pem = os.environ.get('PEMK', 'priv.pem')
    with open(priv_pem, 'rb') as priv_key_file:
        private_key = serialization.load_pem_private_key(
            priv_key_file.read(),
            password=None
        )
    
    return public_key, private_key

# Encrypt Message
def encrypt_message(message, public_key):
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Message encrypted.")
    return encrypted

# Decrypt Message
def decrypt_message(encrypted, private_key):
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Message decrypted.")
    return decrypted.decode()

# Main script logic
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: encryption_script.py <message>")
        sys.exit(1)

    # Generate keys if they don't exist
    if not os.path.isfile("priv.pem") or not os.path.isfile("pub.pem"):
        generate_keys()

    # Load keys
    public_key, private_key = load_keys()

    # Message encoding and encryption
    org_alert = sys.argv[1].encode()  # Encode message from command line
    encrypted = encrypt_message(org_alert, public_key)

    # Decrypt message and display result
    decrypted_message = decrypt_message(encrypted, private_key)
    print("Decrypted message:", decrypted_message)