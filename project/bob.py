# File containing protocol steps for Bob - Execute this file before executing alice.py to begin listening for user "Alice"

from utils import listen, connect, get_cert, verify_cert, get_cert_pk, cert_to_obj, xor_aes_keys, aes_decryption, aes_encryption, get_key, create_key_cipher, extract_key
import pathlib

def main():
    cwd = pathlib.Path(__file__).parent.resolve() # Find the path to the current working directory
    local_addr = "localhost"  # Local IP address
    local_port = 65432   # The port used by localhost
    a_addr = "localhost"  # The remote hosts's IP address
    a_port = 65431   # The port used by the server

    local_sk = f"{cwd}/bob/RSAprivate.pem" # Path to local secret/private key
    local_cert = f"{cwd}/bob/certificate.crt" # Path to local certificate
    local_sym_key = f"{cwd}/bob/AES.txt" # Path to local symmetric key
    ca_cert = f"{cwd}/ca/root.crt" # Path to local CA certificate

    #------------------------------------------------ [Stage 1: Listen for Connection]
    comm = listen(local_addr, local_port, 6) # Open listening socket to start communication, timeout duration = 6 seconds
    if comm:
        print("\n-- [CONNECTION ACTIVE: Protocol Initiating...] --\n")
        #------------------------------------------------ [Stage 4: Send Certificate]
        try:
            connect(a_addr, a_port, get_cert(local_cert).encode()) # Connect to remote socket and send local certificate
        except FileNotFoundError: # If local certificate cannot be found
            print("\n-- [ERROR: User Certificate Not Found!] --\n") 
            exit()
        #------------------------------------------------ [Stage 5: Listen for Certificate and Ciphertext]
        cert_a = listen(local_addr, local_port, 6) # Open listening socket to get certificate A, timeout duration = 6 seconds
        if cert_a:
            if cert_a == b"cert-b-reject": # If user A rejects local cert b"cert-b-reject" will be sent and so user will be notified and exit program
                print("\n-- [ERROR: Local Certificate Rejected!] --\n")
                exit()
            else:
                ciphertext_a = listen(local_addr, local_port, 6) # Open listening socket to get ciphertext A, timeout duration = 6 seconds
                if ciphertext_a:
                    try:
                        verification = verify_cert(cert_a.decode(), get_cert(ca_cert)) # Verify certificate recieved using local TTP cerificate
                    except FileNotFoundError: # If local CA certificate cannot be found
                        print("\n-- [ERROR: Root Certificate Not Found!] --\n") 
                        exit()
                    except: # If local user/CA certificate does not meet X.509 format standards
                        print("\n-- [ERROR: Local User/CA Certificate Does Not Meet X.509 Standards!] --\n") 
                        exit()
                    if verification == False:
                        print("\n-- [ERROR: Remote Certificate Verification Failed] --\n") 
                        connect(a_addr, a_port, b"cert-a-reject") # Connect to remote socket to notify remote host that their certificate has failed verification
                        exit()
                    else:
                        #------------------------------------------------ [Stage 8: Send Ciphertext]
                        print("\n-- [REMOTE CERTIFICATE VERIFIED] --\n")
                        pkA = get_cert_pk(cert_to_obj(cert_a)) # Extract host's public key from certificate recieved
                        skB = get_key(local_sk, "RSA") # Get local private/secret key
                        ciphertext_b = create_key_cipher(skB, pkA, local_sym_key) # Create ciphertext B
                        connect(a_addr, a_port, ciphertext_b) # Connect to remote socket and send ciphertext B
                        extracted_key, integrity = extract_key(ciphertext_a, skB, pkA)  # Begin ciphertext decryption process: Extract symmetric key and check intergrity of message
                        if integrity == True:
                            #------------------------------------------------ [Stage 9: Listen for Encrypted "Hello"]
                            print("\n-- [CIPHERTEXT DECRYPTION COMPLETE] --\n") 
                            hello = listen(local_addr, local_port, 6) # Open listening socket, timeout duration = 6 seconds
                            if hello:
                                shared_key = xor_aes_keys(extracted_key, get_key(local_sym_key, "AES")) # XOR extracted symmetric key with local symmetric key to produce shared session key
                                if hello == b"cipher-reject": # If local ciphertext is rejected b"cipher-reject" will be sent instead of encrypted "hello", so notify user and exit
                                    print("\n-- [ERROR: Local Ciphertext Rejected!] --\n") 
                                    exit()
                                else:
                                    msg = aes_decryption(hello, shared_key) # Decrypt message recieved
                                    if msg == b"hello": # Mutually authenticated secure communicaiton channel has been established
                                        #------------------------------------------------ [Stage 12: Send Encrypted "hello"]
                                        print("\n-- [REMOTE ENCRYPTION SUCCESSFUL] --\n")
                                        connect(a_addr, a_port, aes_encryption(b"hello", shared_key)) # Connect to remote socket and send "hello" message, encrypted with shared session key
                                        #------------------------------------------------ [Stage 13: Listen for ack]
                                        ack = listen(local_addr, local_port, 6) # Open listening socket, timeout duration = 6 seconds
                                        if ack: # Both sides have aknowledged establishment of secure channel
                                            print("\n-- [SECURE CHANNEL ESTABLISHED] --\n")
                                            #------------------------------------------------ [Encrypted Communication]
                                            print("\n-- TIP: Type 'end' to Terminate Communication\n")
                                            send = input("\n-- [Sent] ") # Send first encrypted message
                                            if send == "end": # Close secure channel
                                                    connect(a_addr, a_port, aes_encryption("end".encode(), shared_key)) # Send encrypted "end" message to notify remote user that local user wants to close the channel
                                                    print("\n-- [CLOSING SECURE CHANNEL] --\n")
                                                    exit()
                                            connect(a_addr, a_port, aes_encryption(send.encode(), shared_key)) # Send encrypted message input by user
                                            while True: # Infinite loop, repeat until user closes channel
                                                recieved = listen(local_addr, local_port, 40) # Open listening socket, timeout duration = 40 seconds
                                                if aes_decryption(recieved, shared_key) == b"end":  # Close channel if remote user sends "end"
                                                    print("\n-- [CLOSING SECURE CHANNEL] --\n")
                                                    exit()
                                                print(f"\n-- [Recieved] {recieved}") # Print message recieved before decryption
                                                print(f"   [Decryption] {aes_decryption(recieved, shared_key).decode()}") # Print message recieved after decryption
                                                send = input("\n-- [Sent] ") # Sending message, same as line 76-81
                                                if send == "end":
                                                    connect(a_addr, a_port, aes_encryption("end".encode(), shared_key))
                                                    print("\n-- [CLOSING SECURE CHANNEL] --\n")
                                                    exit()
                                                connect(a_addr, a_port, aes_encryption(send.encode(), shared_key))
                                            #------------------------------------------------ [END]
                                    else: # If decryption doesn't produces "hello", both hosts have not established shared key
                                        print("\n-- [ERROR: Host Used Incorrect Encryption Key] --\n") 
                                        exit()
                        else: # Executed if remote ciphertext has been manipulated
                            print("\n-- [ERROR: Remote Ciphertext Integrity Check Failed!] --\n") 
                            hello = listen(local_addr, local_port, 6) # Open socket to listen for local ciphertext rejection, timeout duration = 6 seconds
                            if hello == b'cipher-reject': # Remote user has rejected local ciphertext (Both ciphertext have been manipulated)
                                exit()
                            else:
                                connect(a_addr, a_port, b"cipher-reject") # If local ciphertext has not been manipulated but remote ciphertext has, send rejection message to remote host
                                exit()

main()