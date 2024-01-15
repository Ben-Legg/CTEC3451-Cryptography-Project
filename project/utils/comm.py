import socket


def listen(host, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # Set attributes to use IP (addr+port) + for TCP Communication
        try:
            s.settimeout(timeout) # Set 6 second connection timeout
            s.bind((host, port)) # Bind local socket (host & port = self)
            s.listen() # Listen incoming connections
            conn, addr = s.accept() # Once accepted accept() will return conn (new socket that can be used) and addr (address bound to the socket on the other end of the connection)
            with conn:
                #print(f"Connected by {addr}") # Get communicator IP
                data = conn.recv(2048) # Save data recieved [NOTE: 1024bit maximum]
                #print("DATA RECIEVED: ", data)
                s.close()
                return data
        except socket.timeout: # Close socket if no hosts connect
            print("\n-- [TIMEOUT: Host Did Not Connect!] --\n")
            s.close()


def connect(host, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #Set attributes to use IP (addr+port) + for TCP comms 
        if message: # If message is not empty connect to host described
            try:
                s.connect((host, port)) # Connect to remote host at host addr and port: Host, Port
                s.sendall(message) # Data to send [NOTE: Must be sent as type byte]
                #print("DATA SENT: ", message)
                return message
            except ConnectionRefusedError:
                print("\n-- [CONNECTION REFUSED: Port Closed!] --\n") 
                exit()
        else: # If message is empty raise exception
            print("\n-- [ERROR: Message Empty!] --\n")
            exit()

def listen_long(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # Set attributes to use IP (addr+port) + for TCP Communication
        try:
            s.settimeout(40) # Set 40 second connection timeout
            s.bind((host, port)) # Bind local socket (host & port = self)
            s.listen() # Listen incoming connections
            conn, addr = s.accept() # Once accepted accept() will return conn (new socket that can be used) and addr (address bound to the socket on the other end of the connection)
            with conn:
                #print(f"Connected by {addr}") # Get communicator IP
                data = conn.recv(2048) # Save data recieved [NOTE: 1024bit maximum]
                #print("DATA RECIEVED: ", data)
                s.close()
                return data
        except socket.timeout: # Close socket if no hosts connect
            print("\n-- [TIMEOUT: Host Did Not Connect!] --\n")
            s.close()