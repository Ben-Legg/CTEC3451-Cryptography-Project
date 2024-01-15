# File containing protocol steps for Alice - Execute this file after executing bob.py to connect to user "bob"

from utils import listen, connect, verify_cert, get_cert, get_cert_pk, cert_to_obj, xor_aes_keys, aes_encryption, aes_decryption, get_key, create_key_cipher, extract_key
import pathlib

def main():
    cwd = pathlib.Path(__file__).parent.resolve() # Find the path to the current working directory
    local_addr = "localhost"  # Local IP address
    local_port = 65431   # The port used by localhost
    b_addr = "localhost"  # The remote hosts's IP address
    b_port = 65432   # The port used by the server

    local_sk = f"{cwd}/alice/RSAprivate.pem" # Path to local secret/private key
    local_cert = f"{cwd}/alice/certificate.crt" # Path to local certificate
    local_sym_key = f"{cwd}/alice/AES.txt" # Path to local symmetric key
    ca_cert = f"{cwd}/ca/root.crt" # Path to local CA certificate

    #------------------------------------------------ [Stage 2: Connect] 
    comm = connect(b_addr, b_port, b"connect") # Open listening socket to start communication, timeout duration = 6 seconds
    if comm:
        print("\n-- [CONNECTION ACTIVE: Protocol Initiating...] --\n")
        #------------------------------------------------ [Stage 3: Listen for Certificate]
        cert_b = listen(local_addr, local_port, 6) # Open listening socket to get certificate A, timeout duration = 6 seconds
        if cert_b:
            try:
                verification = verify_cert(cert_b.decode(), get_cert(ca_cert)) # Verify certificate recieved using local TTP cerificate
            except FileNotFoundError: # If local CA certificate cannot be found
                print("\n-- [ERROR: Root Certificate Not Found!] --\n")
                exit()
            except: # If local user/CA certificate does not meet X.509 format standards
                    print("\n-- [ERROR: Local Certificate Does Not Meet X.509 Standards!] --\n")
                    exit()
            #------------------------------------------------ [Stage 6: Send Certificate and Ciphertext]
            if verification == False:
                print("\n-- [ERROR: Remote Certificate Verification Failed!] --\n")
                connect(b_addr, b_port, b"cert-b-reject") # Connect to remote socket to notify remote host that their certificate has failed verification
                exit()
            else:
                print("\n-- [REMOTE CERTIFICATE VERIFIED] --\n")
                try:
                    connect(b_addr, b_port, get_cert(local_cert).encode()) # Connect to remote socket and send local certificate
                except FileNotFoundError: # If local certificate cannot be found
                    print("\n-- [ERROR: User Certificate Not Found!] --\n")
                    exit()
                pkB = get_cert_pk(cert_to_obj(cert_b)) # Extract host's public key from certificate recieved
                skA = get_key(local_sk, "RSA") # Get local private/secret key
                ciphertext_a = create_key_cipher(skA, pkB, local_sym_key) # Create ciphertext A
                connect(b_addr, b_port, ciphertext_a) # Send ciphertext A
                #------------------------------------------------ [Stage 7: Listen for Ciphertext]
                ciphertext_b = listen(local_addr, local_port, 6) # Open listening socket to get certificate A, timeout duration = 6 seconds
                if ciphertext_b:
                    if ciphertext_b == b"cert-a-reject": # # Connect to remote socket to notify remote host that their certificate has failed verification
                        print("\n-- [ERROR: Local Certificate Rejected!] --\n")
                        exit()
                    else:
                        extracted_key, integrity = extract_key(ciphertext_b, skA, pkB) # Begin ciphertext decryption process: Extract symmetric key and check intergrity of message
                        if integrity == True:
                            #------------------------------------------------ [Stage 10: Send Encrypted "hello"]
                            print("\n-- [CIPHERTEXT DECRYPTION COMPLETE] --\n")
                            shared_key = xor_aes_keys(extracted_key, get_key(local_sym_key, "AES")) # XOR extracted symmetric key with local symmetric key to produce shared session key
                            connect(b_addr, b_port, aes_encryption(b"hello", shared_key)) # Connect to remote socket and send "hello" message, encrypted with shared session key
                            #------------------------------------------------ [Stage 11: Listen for Encrypted "hello"]
                            hello = listen(local_addr, local_port, 6) # Open listening socket to get certificate A, timeout duration = 6 seconds
                            if hello:
                                if hello == b"cipher-reject": # If local ciphertext is rejected b"cipher-reject" will be sent instead of encrypted "hello", so notify user and exit
                                    print("\n-- [ERROR: Local Ciphertext Rejected!] --\n")
                                    exit()
                                else:
                                    msg = aes_decryption(hello, shared_key) # Decrypt message recieved
                                    if msg == b"hello": # Mutually authenticated secure communicaiton channel has been established
                                        #------------------------------------------------ [Stage 13: Send ack]
                                        connect(b_addr, b_port, aes_encryption(b"ack", shared_key)) # Connect to remote socket and send "ack" acknowledgment message, encrypted with shared session key
                                        print("\n-- [REMOTE ENCRYPTION SUCCESSFUL] --\n")
                                        print("\n-- [SECURE CHANNEL ESTABLISHED] --\n")
                                        #------------------------------------------------ [Encrypted Communication]
                                        print("\n-- TIP: Type 'end' to Terminate Communication\n")
                                        while True: # Infinite loop, repeat until user closes channel
                                            recieved = listen(local_addr, local_port, 40) # Open listening socket, timeout duration = 40 seconds
                                            if aes_decryption(recieved, shared_key) == b"end": # Close channel if remote user sends "end"
                                                print("\n-- [CLOSING SECURE CHANNEL] --\n")
                                                exit()
                                            print(f"\n-- [Recieved] {recieved}") # Print message recieved before decryption
                                            print(f"   [Decryption] {aes_decryption(recieved, shared_key).decode()}") # Print message recieved after decryption
                                            if recieved:
                                                send = input("\n-- [Sent] ") # Send encrypted message
                                                if send == "end": # Close secure channel
                                                        connect(b_addr, b_port, aes_encryption("end".encode(), shared_key)) # Send encrypted "end" message to notify remote user that local user wants to close the channel
                                                        print("\n-- [CLOSING SECURE CHANNEL] --\n")
                                                        exit()
                                                connect(b_addr, b_port, aes_encryption(send.encode(), shared_key)) # Send encrypted message input by user
                                    else:
                                        print("\n-- [ERROR: Host Used Incorrect Encryption Key] --\n")
                                        exit()
                                        #------------------------------------------------ [END]
                        else: # Executed if remote ciphertext has been manipulated
                            print("\n-- [ERROR: Remote Ciphertext Integrity Check Failed!] --\n")
                            connect(b_addr, b_port, b"cipher-reject") # If local ciphertext has not been manipulated but remote ciphertext has, send rejection message to remote host
                            exit()

main()