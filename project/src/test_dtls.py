import subprocess
import time
import socket
import logging
from client import DTLS13Client

# Disable logging for the test script to keep output clean
logging.basicConfig(level=logging.ERROR)

def test_dtls_echo():
    print("Starting DTLS Echo Server...")
    server_proc = subprocess.Popen(['python3', 'src/server.py', '--verbose'], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
    
    # Give server time to bind
    time.sleep(2)
    
    try:
        print("Starting DTLS Client...")
        client = DTLS13Client("127.0.0.1", 4433, verbose=True)
        
        if not client.connect():
            print("FAILED: Client could not connect")
            return False
        
        print("Connection established. Testing echo...")
        
        test_messages = ["Hello DTLS!", "Testing 123", "Secure Echo Test"]
        for msg in test_messages:
            print(f"Sending: {msg}")
            client.send_message(msg)
            response = client.receive_message()
            print(f"Received: {response}")
            if response != f"Echo: {msg}":
                print(f"FAILED: Expected 'Echo: {msg}', got '{response}'")
                return False
        
        print("All echo tests passed!")
        client.close()
        return True
        
    except Exception as e:
        print(f"An error occurred during testing: {e}")
        return False
    finally:
        print("Shutting down server...")
        server_proc.terminate()
        server_proc.wait()

if __name__ == "__main__":
    if test_dtls_echo():
        print("\nVERIFICATION SUCCESSFUL")
        exit(0)
    else:
        print("\nVERIFICATION FAILED")
        exit(1)