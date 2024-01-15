from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from Crypto.Hash import SHA256

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from OpenSSL import crypto

import pathlib


#AES ---------------------------------------------------------------------------------
#https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/#encrypting
#https://nitratine.net/blog/post/xor-python-byte-strings/

def aes_key_gen(): # Function to generate each half of the shared AES symmetric encryption key at a specified path
    key = get_random_bytes(32) # Generate random 256 bit key
    return key # Return key generated

def aes_encryption(plaintext, key): # Function to AES encrypt [NOTE: pass plaintext to be encrypted (BYTE) and key]
    cipher = AES.new(key, AES.MODE_CBC) # Create AES cipher object with session key and select CBC mode (Uses padding), unique 16 byte initialisation vector also generated
    ciphered_data = cipher.encrypt(pad(plaintext, AES.block_size)) #Pad input data then encrypt
    ciphertext = cipher.iv + ciphered_data # Join IV to ciphertext - IV used to enable encryption of same message (with same key) to produce different ciphertext
    return ciphertext # Return ciphertext bytestream

def aes_decryption(ciphertext, key): # Function to AES decrypt [NOTE: pass ciphertext to be decrypted and key]
    iv = ciphertext[:16] # Extract IV from ciphertext
    message = ciphertext[16:] # Extract message section from ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv) # Create AES cipher object same as in encryption
    plaintext = unpad(cipher.decrypt(message), AES.block_size) # Decrypt and up-pad
    return plaintext # Return plaintext (BYTE)

def xor_aes_keys(K1, K2): # Function to XOR two 256-bit AES keys [NOTE: Accepts keys with type byte]
    shared_key = bytes([_a ^ _b for _a, _b in zip(K1, K2)]) # XOR operation for each bytestring
    return shared_key # Return shared key


#RSA ---------------------------------------------------------------------------------
#https://pycryptodome.readthedocs.io/en/latest/

def rsa_key_gen(key_folder): # Function to generate RSA key pairs for hosts and save in local /keys directory
    p = pathlib.Path(key_folder) # Specify path of keys folder [NOTE: Make sure folder containing this project's code = "project"]
    p.mkdir(parents=True, exist_ok=True) # Create keys folder
    sk = RSA.generate(2048) # Generate 2048-bit RSA private key
    with open(p / "RSAprivate.pem", 'wb')as file: # Create/open file specified as location for private key
        file.write(sk.export_key()) # Write private key to file in PEM standardised format
    pk = sk.publickey() # Find RSA public key based off of private key generated previously
    with open(p / "RSApublic.pem", 'wb')as file: # Create/open file specified as location for public key
        file.write(pk.export_key()) # Write public key to file in PEM standardised format

def rsa_encryption(plaintext, pk): # Function to RSA encrypt [NOTE: pass plaintext (BYTE) to be encrypted and public key (.PEM)]
    encryption_key = RSA.importKey(pk) # Import public key into pycryptodome object
    cipher = PKCS1_OAEP.new(encryption_key) # Create new PKCS1_OAEP instance (Asymmetric cipher based on RSA and OAEP padding)
    ciphertext = cipher.encrypt(plaintext) # Encrypt plaintext bytestream
    return ciphertext # Return ciphertext bytestream

def rsa_decryption(ciphertext, sk): # Function to RSA decrypt [NOTE: pass ciphertext to be decrypted (BYTE) and secret key (.PEM)]
    decryption_key = RSA.importKey(sk) # Import secret key into pycryptodome object
    cipher = PKCS1_OAEP.new(decryption_key) # Create new PKCS1_OAEP instance (Asymmetric cipher based on RSA and OAEP padding)
    plaintext = cipher.decrypt(ciphertext) # Decrypt ciphertext
    return plaintext # Return plaintext (BYTE)

def sign(data, signing_key): # Function to generate RSA signature [NOTE: pass data to be signed (BYTE) and secret key(.PEM)]
    signing_key = RSA.import_key(signing_key) # Import .PEM key into key object
    hash = SHA256.new(data) # SHA-256 hash the data
    signature = pkcs1_15.new(signing_key).sign(hash) # Sign the hashed data using sk, creating RSA signature (256-bits)
    return signature # Return signature encoded as a byte string

def verify(data, signature, verifying_key): # Function to verify RSA signature [NOTE: pass data signed (BTYE), signature (BYTE) and public key (.PEM)]
    verifying_key = RSA.import_key(verifying_key) # Import .PEM key into key object
    hash = SHA256.new(data) # SHA-256 hash the data
    try:
        pkcs1_15.new(verifying_key).verify(hash, signature) # Verify signature
        return True # If valid return True
    except (ValueError, TypeError):
        return False # If invalid return False


#Hybrid ---------------------------------------------------------------------------------
# As RSA signature is too big to be encrypted using RSA, hybrid encryption is used to encrypt and send the ciphertext containing the signature
def hybrid_encryption(k_s, pk): # Hybrid Encryption function used to encrypt K + Signature, in ciphertext generation [NOTE: pass K + signature (BTYE) and public key (.PEM)]
    sym_key = aes_key_gen() # Generate random 256 bit key for hybrid encryption
    k_s_ciphertext = aes_encryption(k_s, sym_key) # AES encrypt k_s (The half of the shared key + it's signature) using single use key generated 
    enc_key = rsa_encryption(sym_key, pk) # RSA encrypt the single use AES key
    return enc_key, k_s_ciphertext # Return the RSA encrypted single use key and the AES encrypted k_s


#Certificates ---------------------------------------------------------------------------------
#https://www.pyopenssl.org/en/latest/
#https://web.archive.org/web/20161107073715/http://blog.richardknop.com/2012/08/create-a-self-signed-x509-certificate-in-python/

def ss_cert_gen(emailAddress, commonName, countryName, organizationName, serialNumber, validityEndInSeconds, CERT_DESTINATION, sk, pk): # Function to generate self-signed X.509 certificate for TTP
    cert = crypto.X509() # Create OpenSSL X.509 object 
    cert.get_subject().C = countryName # Set country name
    cert.get_subject().O = organizationName # Set organization name
    cert.get_subject().CN = commonName # Set name of owner
    cert.get_subject().emailAddress = emailAddress  # Set email address
    cert.set_serial_number(serialNumber) # Set serial number
    cert.gmtime_adj_notBefore(0) # Set validity start date [NOTE: YYYYMMDDhhmmssZ format]
    cert.gmtime_adj_notAfter(validityEndInSeconds)  # Set validity start date [NOTE: YYYYMMDDhhmmssZ format]
    cert.set_issuer(cert.get_subject()) # Set issuer details as subject details as certificate is self-signed
    cert.set_pubkey(crypto.load_publickey(crypto.FILETYPE_PEM, pk)) # Convert pk (PEM) to OpenSSL object, set as public key attribute
    cert.sign(crypto.load_privatekey(crypto.FILETYPE_PEM, sk), 'sha256') # Convert sk (PEM) to OpenSSL object, RSA sign SHA hash of the certificate
    with open(CERT_DESTINATION, "wt") as f: # Open "CERT_DESTINATION" location
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")) # Dump certificate from OpenSSL object to PEM format and write to file

def user_cert_gen(emailAddress, commonName, countryName, organizationName, serialNumber, validityEndInSeconds, CERT_DESTINATION, sk, pk): # Function to generate X.509 certificate for users Alice and Bob
    package_path = pathlib.Path(__file__).parent.resolve() # Get the path of the package folder E.g. "\utils"
    project_path = pathlib.Path(package_path).parent.resolve() # Get the path of the project folder E.g. "\project"
    cert = crypto.X509() # Create OpenSSL X.509 object 
    cert.get_subject().C = countryName # Set country name
    cert.get_subject().O = organizationName # Set organization name
    cert.get_subject().CN = commonName # Set name of owner
    cert.get_subject().emailAddress = emailAddress  # Set email address
    cert.set_serial_number(serialNumber) # Set serial number
    cert.gmtime_adj_notBefore(0) # Set validity start date [NOTE: YYYYMMDDhhmmssZ format]
    cert.gmtime_adj_notAfter(validityEndInSeconds)  # Set validity start date [NOTE: YYYYMMDDhhmmssZ format]
    with open(f"{project_path}/ca/root.crt", "r") as f: # Open CA file location
        ca_cert_pem = f.read() # Save certificate file (PEM)
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem) # Load certificate (PEM) into OpenSSL object
    cert.set_issuer(ca_cert.get_subject()) # Set issuer details as subject details of CA from CA certificate loaded previously
    cert.set_pubkey(crypto.load_publickey(crypto.FILETYPE_PEM, pk)) # Convert pk (PEM) to OpenSSL object, set as public key attribute
    cert.sign(crypto.load_privatekey(crypto.FILETYPE_PEM, sk), 'sha256') # Convert sk (PEM) to OpenSSL object, RSA sign SHA hash of the certificate
    with open(CERT_DESTINATION, "wt") as f: # Open "CERT_DESTINATION" location
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")) # Dump certificate from OpenSSL object to PEM format and write to file

def get_cert(CERT_FILE): # Function to retrieve an X.509 certificate (PEM)
    with open(CERT_FILE, "r") as f: # Open "CERT_FILE" location
        cert_pem = f.read() # Save certificate read from fie
    return cert_pem # Returns cert (PEM)

def cert_to_obj (cert_pem): # Function to convert an X.509 certificate (PEM) to an OpenSSL object
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem) # Load certificate (PEM) into OpenSSL object
    return cert # Returns cert (OpenSSL Object)

def get_cert_pk(cert_obj): # Function to retrieve public key from X.509 certificate (OpenSSl Object)
    pk = crypto.dump_publickey(crypto.FILETYPE_PEM, cert_obj.get_pubkey()) # Get public key from certificate and dump to PEM format
    return pk # Returns pk (PEM)

def verify_cert(user_cert, trusted_cert): # Function to verify a certificate using the root certificate
    client_cert = cert_to_obj(user_cert) # Convert client certificate (PEM) to OpenSSL Object
    root_cert = cert_to_obj(trusted_cert) # Convert trusted certificate (PEM) to OpenSSL Object
    store = crypto.X509Store() # Initialise X.509 store, store describes a context used for verification
    store.add_cert(root_cert) # Add the certificate trusted for verification to the store
    ctx = crypto.X509StoreContext(store, client_cert) # Add the store description, E.g the trusted certificate, and the client certificate to the store context
    try: # Determine result of verification
        return ctx.verify_certificate() # If the verification is successful, "verify_certificate" returns "None"
    except: # [NOTE: if certificate cannot be verified "verify_certificate" throws error: "OpenSSL.crypto.X509StoreContextError: unable to get local issuer certificate"]
        return False # If the verification fails, return "False"