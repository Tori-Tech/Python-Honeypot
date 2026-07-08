import socket
import threading
import datetime
import sys
import time
import json
import os

#Config

#ports to listen on:

ports = [21, 22, 80, 443, 8080, 11434, 4444, 3389]
BIND_IP = "0.0.0.0"
log_file = "honeypot.json"


#logging function

def log_activity(client_ip, client_port, port_targeted, data):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    #try decoding data, fall back to hex representation if it's binary or something malicious

    try:
        payload = data.decode('utf-8').strip()
    except UnicodeDecodeError:
        payload = data.hex()
        # Create a structured dictionary for the SIEM

    log_entry = {
        "timestamp": timestamp,
        "event_type": "honeypot_alert",
        "source_ip": client_ip,
        "source_port": client_port,
        "dest_port": port_targeted,
        "payload": payload
    }

    #print message to console
    print(f"[{timestamp}] ALERT: Port {port_targeted} from {client_ip}:{client_port}")


    # if file doesn't exist/is empty, create it as an empty array
    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        with open(log_file, "w") as f:
            f.write("[]")

    # open in read/write mode to modify the end of the file safely
    with open(log_file, "r+") as f:
        f.seek(0, os.SEEK_END)
        position = f.tell()
        
        # Back up past the closing square bracket
        while position > 0:
            position -= 1
            f.seek(position)
            char = f.read(1)
            if char == ']':
                f.seek(position)
                break
        
        #checks for emptiness
        is_empty = (position <= 2) or (f.tell() <= 2)

        if not is_empty:
            f.write(",\n" + json.dumps(log_entry, indent=4) + "]")
        else:
            f.write("\n" + json.dumps(log_entry, indent=4) + "]")

#thread handler for individual client connections.

def handle_client(client_socket, client_ip, client_port, port_targeted):
    try:
        #recieve up to 4096 bytes of the payload
        data = client_socket.recv(4096)
        #log the capture
        log_activity(client_ip, client_port, port_targeted, data)
        #send a banner
        client_socket.send(b"Error: Access denied.\n")
    except Exception as e:
        pass #fail silently to keep the listener clean
    finally:
        client_socket.close()


#port listener thread

def start_listener(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((BIND_IP, port))
        server_socket.listen(5)
        print(f"[*] Service actively listening on port: {port}")
    except Exception as e:
        print(f"[!] Error binding to port {port}: {e}")
        return  
    while True:
        try:
            client_socket, client_address = server_socket.accept()
            client_ip, client_port = client_address

           #spawn a new thread per connection so the listener never blocks
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_ip, client_port, port),
                daemon=True
            )
            client_thread.start()

        except Exception as e:
            print(f"[!] Error handling connection on port {port}: {e}")


#main part of the program

def main():
    print("Starting Service....") #generic deceptive messages
    print(f"[*] Logs will be saved to: {log_file}")

    threads = []
    for port in ports:
        thread = threading.Thread(target=start_listener, args=(port,), daemon=True)
        threads.append(thread)
        thread.start()

    #keep the daemon threads running

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n [-] Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()


