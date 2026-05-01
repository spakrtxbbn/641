# DTLS 1.3 Demonstration Implementation

This project provides a functional demonstration of the **Datagram Transport Layer Security (DTLS) 1.3** protocol. It implements a simple echo server and client that communicate over UDP, establishing a secure channel before exchanging application data.

## DTLS 1.3 Protocol Basics

DTLS 1.3 (RFC 9147) is designed to provide security for datagram-based transport (UDP), similar to how TLS 1.3 secures TCP. Because UDP is unreliable (packets can be lost or reordered), DTLS includes mechanisms to handle these issues while maintaining the security properties of TLS.

### Key Features Demonstrated in this Implementation:

1.  **Streamlined Handshake**: 
    The implementation demonstrates the 1-RTT handshake:
    - **ClientHello**: The client sends its public key share.
    - **ServerHello**: The server responds with its own public key share.
    - **Key Derivation**: Both parties use Elliptic Curve Diffie-Hellman (X25519) to derive a shared secret, which is then used to generate symmetric keys for encryption.
    - **Finished**: A final handshake message confirms that the secure channel is established.

2.  **Record Layer**:
    Every packet is wrapped in a DTLS record. The header includes:
    - **Epoch**: Indicates the current state of the keys (e.g., handshake keys vs. application keys).
    - **Sequence Number**: Prevents replay attacks and is used as part of the nonce for encryption.
    - **Type**: Distinguishes between Handshake, Application Data, and Alert records.

3.  **AEAD Encryption**:
    The implementation uses **AES-GCM** (Authenticated Encryption with Associated Data). This ensures that the data is not only encrypted (confidentiality) but also that any modification to the ciphertext is detected (integrity).

---

## Running the Demonstration

### Prerequisites

Ensure you have Python 3.10+ installed. 

**Note:** This implementation is written in pure Python and does not require any external cryptographic libraries, fulfilling the academic requirement for manual primitive implementation.

### Step 1: Start the Server
Run the server script. It will listen on `127.0.0.1:4433` by default.

```bash
python3 src/server.py
```

### Step 2: Start the Client
In a separate terminal, run the client script:

```bash
python3 src/client.py
```

Once the connection is established, you can type messages into the client console, and the server will echo them back securely.

---

## Command Line Options

Both the client and server support the following flags:

| Flag | Description |
| :--- | :--- |
| `--host <address>` | Specify the IP address to bind to or connect to (Default: `127.0.0.1`). |
| `--port <port>` | Specify the UDP port (Default: `4433`). |
| `--verbose` | **Verbose Mode**: Logs raw packet hex dumps and detailed protocol state transitions. |

---

## Sample Output

### Normal Mode
**Server:**
```text
2026-04-30 22:30:01 [INFO] DTLS 1.3 Echo Server listening on 127.0.0.1:4433...
2026-04-30 22:30:05 [INFO] Received ClientHello. Processing key exchange...
2026-04-30 22:30:05 [INFO] Sending ServerHello...
2026-04-30 22:30:05 [INFO] Handshake Finished. Connection established.
2026-04-30 22:30:10 [INFO] Received message: Hello DTLS!
```

**Client:**
```text
2026-04-30 22:30:05 [INFO] Initiating DTLS 1.3 connection to 127.0.0.1:4433...
2026-04-30 22:30:05 [INFO] Received ServerHello. Processing key exchange...
2026-04-30 22:30:05 [INFO] Sending Finished...
2026-04-30 22:30:05 [INFO] DTLS 1.3 Handshake complete. Secure channel established.

--- Secure Connection Established ---
Type your message and press Enter. Type 'exit' or 'quit' to leave.

> Hello DTLS!
Server: Echo: Hello DTLS!
```

### Verbose Mode (`--verbose`)
When running with `--verbose`, you will see the raw bytes being transmitted:

**Client/Server Log:**
```text
2026-04-30 22:30:05 [DEBUG] Packet SEND: 0000 000000000000 16 0018 ... (ClientHello)
2026-04-30 22:30:05 [DEBUG] Packet RECV: 0000 000000000000 16 0018 ... (ServerHello)