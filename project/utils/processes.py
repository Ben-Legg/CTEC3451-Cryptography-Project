from .crypto import aes_key_gen, aes_decryption, rsa_decryption, sign, verify, hybrid_encryption 

def get_key(file_location, type): # Function to get an asymmetric key from a .pem file
    try:
        with open(file_location, 'rb')as file: # Open file in requested location
            key = file.read() # save key
            if type == "RSA": # Flag for asymmetric RSA key
                return key.decode() # Return key (.PEM)
            elif type == "AES": # Flag for symmetric AES key
                return key # Return key (.PEM BYTE)
    except FileNotFoundError:
        print("\n-- [ERROR: Local Key Not Found!] --\n")
        exit()

def create_key_cipher(sk, pk, pathAES): # Function to generate ciphertext used to share one half of the symmertric key [NOTE: pass RSA sk and pk (BYTES)]
    try:
        sym_key = aes_key_gen() # Generate AES key
        with open(pathAES, 'wb')as file: # Create/open path specified
            file.write(sym_key) # Write AES key to file
        signature = sign(sym_key, sk) # Sign symmetric key using sk
        k_s = sym_key + signature # Concatenate the half of the shared key with the signature [NOTE: Both (BYTES)]
        enc_key, k_s_ciphertext = hybrid_encryption(k_s, pk) # Call the hybrid encryption function, returing RSA encrypted single use AES key and AES encrypted k_s
        ciphertext = enc_key + k_s_ciphertext # Concatenate the RSA encrypted single use key and the AES encrypted k_s
        return ciphertext # Return resultant 576-bit ciphertext (BYTE)
    except:
        print("\n-- [ERROR: Invalid Path To Local Hybrid Encryption Key!] --\n")
        exit()

def extract_key(ciphertext, sk, pk): # Function to extract other host's half of the symmertric key and verify the integrity of the message [NOTE: pass ciphertext (BYTES), RSA sk and pk (.PEM)]
    try:
        enc_key = ciphertext[:256] # Separate RSA encrypted single use AES key (256-bit) from ciphertext
        key = rsa_decryption(enc_key, sk) # RSA decrypt to obtain single use AES key
        k_s_ciphertext = ciphertext[256:] # Separate AES encrypted k_s_ciphertext (remaining 320-bits) from ciphertext
        k_s = aes_decryption(k_s_ciphertext, key) # AES decrypt to obtain k_s
        sym_key = k_s[:32] # Obtain other host's symmetric key (32-bit)
        signature = k_s[32:] # Obtain signature (Remaining 256-bits)
        check_integrity = verify(sym_key, signature, pk) # Save result of integrity check
        return sym_key, check_integrity # If message intergity has remained, return the half of the AES key and "True" (BOOL)
    except Exception: # Exceception is raisesd if message is manipulated in transit as either the RSA encryption function or the signature verification will fail
        return None, False # If message was manipulated "None", intstead of the half of the AES key, and "True" (BOOL) is returned
