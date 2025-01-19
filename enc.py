from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import sys
import os

# Generate RSA Key Pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize private key to PEM format
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open("priv.pem", 'wb') as priv_pem_file:
        priv_pem_file.write(priv_pem)

    public_key = private_key.public_key()

    # Serialize public key to PEM format
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open("pub.pem", 'wb') as pub_pem_file:
        pub_pem_file.write(pub_pem)

    print("Key pair generated: priv.pem (private) and pub.pem (public)")

def encrypt_message(message):
    # Load public key
    pub_pem = os.environ.get('PUB_PEMK', 'pub.pem')
    with open(pub_pem, 'rb') as pub_key_file:
        public_key = serialization.load_pem_public_key(pub_key_file.read())

    # Encrypt the message
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Encrypted message:", encrypted.hex())
    return encrypted

def decrypt_message(encrypted):
    # Load private key
    priv_pem = os.environ.get('PEMK', 'priv.pem')
    with open(priv_pem, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Decrypt the message
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Decrypted message:", decrypted.decode())
    return decrypted

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./script.py <message>")
        sys.exit(-1)

    command = sys.argv[1]

    if command.lower() == "generate":
        generate_key_pair()
    else:
        # Encrypt and decrypt the message
        message = command
        encrypted_message = encrypt_message(message)
        decrypt_message(encrypted_message)
