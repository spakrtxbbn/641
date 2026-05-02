import socket
import logging
import argparse
from dtls_common import DTLSCommon, DTLSState, RECORD_TYPE_HANDSHAKE, RECORD_TYPE_APPLICATION_DATA, HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO, HANDSHAKE_FINISHED

def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s [%(levelname)s] %(message)s')

class DTLSEchoServer:
    def __init__(self, host: str, port: int, verbose: bool):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.state = DTLSState()
        self.client_address = None

    def log_packet(self, direction, data):
        if self.verbose:
            logging.debug(f"Packet {direction}: {data.hex(' ')}")

    def run(self):
        logging.info(f"DTLS 1.3 Echo Server listening on {self.host}:{self.port}...")
        
        while True:
            data, addr = self.sock.recvfrom(4096)
            self.client_address = addr
            self.log_packet("RECV", data)

            record = DTLSCommon.parse_record(data)
            if not record:
                continue
            
            epoch, seq, record_type, payload = record

            if record_type == RECORD_TYPE_HANDSHAKE:
                self.handle_handshake(payload)
            elif record_type == RECORD_TYPE_APPLICATION_DATA:
                self.handle_application_data(payload, seq)

    def handle_handshake(self, payload):
        msg_type, msg_payload = DTLSCommon.parse_handshake_msg(payload)
        
        if msg_type == HANDSHAKE_CLIENT_HELLO:
            logging.info("Received ClientHello. Processing key exchange...")
            # Extract client public key
            client_pub_key = msg_payload[:32]
            self.state.compute_shared_secret(client_pub_key)
            
            # Derive keys
            self.state.read_key = self.state.shared_secret[:16]
            self.state.write_key = self.state.shared_secret[:16]
            
            # Send ServerHello
            logging.info("Sending ServerHello...")
            server_pub_key = self.state.public_key
            sh_msg = DTLSCommon.create_handshake_msg(HANDSHAKE_SERVER_HELLO, server_pub_key)
            record = DTLSCommon.create_record(self.state.epoch, self.state.write_seq, RECORD_TYPE_HANDSHAKE, sh_msg)
            
            self.log_packet("SEND", record)
            self.sock.sendto(record, self.client_address)
            self.state.write_seq += 1

        elif msg_type == HANDSHAKE_FINISHED:
            logging.info("Handshake Finished. Connection established.")
            self.state.epoch += 1
            self.state.write_seq = 0

    def handle_application_data(self, payload, seq):
        try:
            # Decrypt using the sequence number of the received record
            decrypted = self.state.decrypt(payload, self.state.read_key, seq)
            message = decrypted.decode('utf-8')
            logging.info(f"Received message: {message}")

            # Echo back
            response = f"Echo: {message}".encode('utf-8')
            # Encrypt using the server's write sequence number
            encrypted = self.state.encrypt(response, self.state.write_key, self.state.write_seq)
            
            record = DTLSCommon.create_record(self.state.epoch, self.state.write_seq, RECORD_TYPE_APPLICATION_DATA, encrypted)
            self.log_packet("SEND", record)
            self.sock.sendto(record, self.client_address)
            self.state.write_seq += 1
        except Exception as e:
            logging.error(f"Error handling application data: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    server = DTLSEchoServer(args.host, args.port, args.verbose)
    server.run()