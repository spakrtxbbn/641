import socket
import logging
import argparse
import sys
from dtls_common import DTLSCommon, DTLSState, RECORD_TYPE_HANDSHAKE, RECORD_TYPE_APPLICATION_DATA, HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO, HANDSHAKE_FINISHED

def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s [%(levelname)s] %(message)s')

class DTLS13Client:
    def __init__(self, host: str, port: int, verbose: bool, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.state = DTLSState()
        self.server_address = (host, port)

    def log_packet(self, direction, data):
        if self.verbose:
            logging.debug(f"Packet {direction}: {data.hex(' ')}")

    def connect(self):
        logging.info(f"Initiating DTLS 1.3 connection to {self.host}:{self.port}...")
        
        # 1. Send ClientHello
        client_pub_key = self.state.public_key
        ch_msg = DTLSCommon.create_handshake_msg(HANDSHAKE_CLIENT_HELLO, client_pub_key)
        record = DTLSCommon.create_record(self.state.epoch, self.state.write_seq, RECORD_TYPE_HANDSHAKE, ch_msg)
        
        self.log_packet("SEND", record)
        self.sock.sendto(record, self.server_address)
        self.state.write_seq += 1

        # 2. Receive ServerHello
        try:
            data, addr = self.sock.recvfrom(4096)
            self.log_packet("RECV", data)
            record = DTLSCommon.parse_record(data)
            if not record:
                raise Exception("Invalid record received")
            
            epoch, seq, record_type, payload = record
            if record_type != RECORD_TYPE_HANDSHAKE:
                raise Exception("Expected handshake record")
            
            msg_type, msg_payload = DTLSCommon.parse_handshake_msg(payload)
            if msg_type != HANDSHAKE_SERVER_HELLO:
                raise Exception("Expected ServerHello")
            
            logging.info("Received ServerHello. Processing key exchange...")
            server_pub_key = msg_payload[:32]
            self.state.compute_shared_secret(server_pub_key)
            
            # Derive keys (Simplified for demo)
            self.state.read_key = self.state.shared_secret[:32]
            self.state.write_key = self.state.shared_secret[:32]
            
            # 3. Send Finished
            logging.info("Sending Finished...")
            fin_msg = DTLSCommon.create_handshake_msg(HANDSHAKE_FINISHED, b"FINISHED")
            record = DTLSCommon.create_record(self.state.epoch, self.state.write_seq, RECORD_TYPE_HANDSHAKE, fin_msg)
            
            self.log_packet("SEND", record)
            self.sock.sendto(record, self.server_address)
            self.state.write_seq += 1
            
            # Transition to application epoch
            self.state.epoch += 1
            self.state.write_seq = 0
            logging.info("DTLS 1.3 Handshake complete. Secure channel established.")
            
        except socket.timeout:
            logging.error("Connection timed out.")
            return False
        except Exception as e:
            logging.error(f"Handshake failed: {e}")
            return False
        
        return True

    def send_message(self, message: str):
        payload = message.encode('utf-8')
        # Encrypt using the client's write sequence number
        encrypted = self.state.encrypt(payload, self.state.write_key, self.state.write_seq)
        record = DTLSCommon.create_record(self.state.epoch, self.state.write_seq, RECORD_TYPE_APPLICATION_DATA, encrypted)
        
        self.log_packet("SEND", record)
        self.sock.sendto(record, self.server_address)
        self.state.write_seq += 1

    def receive_message(self):
        try:
            data, addr = self.sock.recvfrom(4096)
            self.log_packet("RECV", data)
            record = DTLSCommon.parse_record(data)
            if not record:
                return None
            
            epoch, seq, record_type, payload = record
            if record_type == RECORD_TYPE_APPLICATION_DATA:
                # Decrypt using the sequence number of the received record
                decrypted = self.state.decrypt(payload, self.state.read_key, seq)
                return decrypted.decode('utf-8')
        except socket.timeout:
            return None
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            return None

    def close(self):
        logging.info("Closing UDP socket.")
        self.sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    client = DTLS13Client(args.host, args.port, args.verbose)
    
    if client.connect():
        print("\n--- Secure Connection Established ---")
        print("Type your message and press Enter. Type 'exit' or 'quit' to leave.\n")
        try:
            while True:
                msg = input("> ")
                if msg.lower() in ['exit', 'quit']:
                    break
                if not msg:
                    continue
                
                client.send_message(msg)
                response = client.receive_message()
                if response:
                    print(f"Server: {response}")
                else:
                    print("No response from server.")
        except KeyboardInterrupt:
            pass
        finally:
            client.close()
    else:
        logging.error("Could not establish secure connection.")
        sys.exit(1)