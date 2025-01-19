
2024-6-19 12:36

This file is a part of my Zettelkasten (currently a private repo)

This code demonstrates how to encrypt and decrypt data using **asymmetric encryption** with **Python** on a **Linux command line** environment. It utilizes Python's cryptographic capabilities to implement a secure encryption method, where a **public key** is used to encrypt data, and a corresponding **private key** is required for decryption.

To run in a terminal:
python enc.py "Your message to encrypt and decrypt"

### Generate Key Pair

```
private_key = rsa.generate_private_key(
    public_exponent=65537, 
    key_size=2048           
)
```

This code snippet generates an RSA private key with a key size of **2048 bits**. The **public_exponent 65537** is selected as it is a standard choice for RSA, offering an optimal balance between security and computational efficiency.

```
priv_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,                   
    format=serialization.PrivateFormat.TraditionalOpenSSL, 
    encryption_algorithm=serialization.NoEncryption()      
)
```

This code snippet converts the private key into a byte format suitable for file storage. It uses **PEM encoding**, a Base64-encoded format widely used for cryptographic keys, with no encryption applied.
Further I open a new file `priv.pem`, in binary write mode and save the serialized private key to this file.

```
public_key = private_key.public_key()
```

This snippet extracts the `public key` from the generated `private key`.

```
pub_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,                       
    format=serialization.PublicFormat.SubjectPublicKeyInfo     
)
```

This snippet transforms the public key to a `PEM-encoded` byte format, making it appropriate for file storage.
Further I open a new file, `pub.pem` in binary write mode and save the serialized public key to this file.

### Encrypting and Decrypting

The following code encrypts a message (`message`) using a public key and decrypts it with the corresponding private key. It retrieves key file paths from environment variables and employs **asymmetric encryption** (RSA) with **Optimal Asymmetric Encryption Padding (OAEP)** for enhanced security.

```
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys, os
```

Imports the relevant modules (imported at the beginning of the file): 
- serialization - to manage key loading and format handling
- hashes - to provides cryptographic hash functions (`SHA-256`)
- padding - to provide padding options for secure RSA encryption (`OAEP`)
- sys and os - Handle command-line arguments and environment variables.

```
org_alert = sys.argv[1].encode()
```

This line of code encodes the message from the command-line argument to bytes, required for encryption.

### Encrypting

```
pub_pem = os.environ.get('PUB_PEMK')
with open(pub_pem, 'rb') as pub_key_file:
    public_key = serialization.load_pem_public_key(pub_key_file.read())
```

This code snippet retrieves public key file path from the environment variable `PUB_PEMK`; and then opens the public key file in binary mode, reads it, and loads it as a PEM-encoded public key using `serialization.load_pem_public_key`.

```
encrypted = public_key.encrypt(
    message.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),  
        algorithm=hashes.SHA256(),                   
        label=None                                  
    )
)
```

This code snippet encrypts `message` using the `public key` and applies `OAEP` with `SHA-256` algorithm for both the main hash and the mask generation function 1(`MGF1`). This enhances security by introducing randomness into the encryption process, ensuring unique outputs even if the same message is encrypted multiple times with the same key.

### Decrypting 

```
priv_pem = os.environ.get('PEMK', 'priv.pem')
with open(priv_pem, 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )
```

This code snippet fetches the private key file path from the `PEMK` environment variable, opens the file in binary mode, reads its contents, and loads it as a PEM-encoded private key. The password parameter is set to `None` since the key is not encrypted.

```
decrypted = private_key.decrypt(
    encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function with SHA-256
        algorithm=hashes.SHA256(),                   # Main hash algorithm for OAEP
        label=None                                   # Optional label, set to None
    )
)
```

This code snippet decrypts the encrypted message using the private key. It employs `OAEP` padding with `SHA-256` for both the main hash algorithm and the `MGF1` function, ensuring secure decryption.
Further print the decoded message in plaintext.





