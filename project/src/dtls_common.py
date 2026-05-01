import os
import struct
import logging
from crypto_primitives import SHA256, HMAC, HKDF, X25519, AESGCM

# DTLS 1.3 Record Types
RECORD_TYPE_HANDSHAKE = 22
RECORD_TYPE_APPLICATION_DATA = 23
RECORD_TYPE_ALERT = 21

# DTLS 1.3 Handshake Types
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_ENCRYPTED_EXTENSIONS = 8
HANDSHAKE_CERTIFICATE = 11
HANDSHAKE_CERTIFICATE_VERIFY = 15
HANDSHAKE_FINISHED = 20

class DTLSCommon:
    @staticmethod
    def create_record(epoch, seq, record_type, payload):
        # Header: Epoch (2), Seq (6), Type (1), Length (2)
        header = struct.pack(">H", epoch) + struct.pack(">Q", seq)[2:] + struct.pack(">B H", record_type, len(payload))
        return header + payload

    @staticmethod
    def parse_record(data):
        if len(data) < 11:
            return None
        epoch = struct.unpack(">H", data[0:2])[0]
        seq = int.from_bytes(data[2:8], 'big')
        record_type = struct.unpack(">B", data[8:9])[0]
        length = struct.unpack(">H", data[9:11])[0]
        payload = data[11:11+length]
        return epoch, seq, record_type, payload

    @staticmethod
    def derive_key(secret, salt, info, length=32):
        prk = HKDF.extract(salt, secret)
        return HKDF.expand(prk, info, length)

    @staticmethod
    def create_handshake_msg(msg_type, payload):
        # Handshake Header: Type (1), Length (3)
        header = struct.pack(">B", msg_type) + struct.pack(">I", len(payload))[1:]
        return header + payload

    @staticmethod
    def parse_handshake_msg(data):
        if len(data) < 4:
            return None
        msg_type = struct.unpack(">B", data[0:1])[0]
        length = int.from_bytes(data[1:4], 'big')
        payload = data[4:4+length]
        return msg_type, payload

class DTLSState:
    def __init__(self):
        self.epoch = 0
        self.write_seq = 0
        self.private_key, self.public_key = X25519.generate_keypair()
        self.shared_secret = None
        self.handshake_secret = None
        self.client_handshake_traffic_secret = None
        self.server_handshake_traffic_secret = None
        self.client_application_traffic_secret = None
        self.server_application_traffic_secret = None
        self.write_key = None
        self.write_iv = None
        self.read_key = None
        self.read_iv = None

    def compute_shared_secret(self, peer_public_key_bytes):
        self.shared_secret = X25519.shared_secret(self.private_key, peer_public_key_bytes)
        return self.shared_secret

    def encrypt(self, payload, key, seq):
        # In DTLS 1.3, the nonce is derived from IV and sequence number
        nonce = seq.to_bytes(12, 'big') # Simplified nonce
        cipher = AESGCM(key)
        return cipher.encrypt(nonce, payload, b"")
    
    def decrypt(self, ciphertext, key, seq):
        nonce = seq.to_bytes(12, 'big')
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, ciphertext, b"")

def get_logger(name):
    logger = logging.getLogger(name)
    return logger