# Research Paper Outline: DTLS 1.3 Implementation & Analysis

Formal paper will be written in an actual document. Mardown is being used for drafting/outlining.

## Abstract

- Brief overview of the project: implementing DTLS 1.3 in Python to evaluate its security and performance enhancements over predecessor protocols.

## Introduction & Background

- The role of DTLS in securing datagram transport (UDP).

- The historical context and limitations of DTLS 1.2 (e.g., latency, older cryptographic flaws).

## Technical Advancements in DTLS 1.3

- Streamlined Handshake: Explain the reduction from a 2-RTT (Round Trip Time) to a 1-RTT handshake, and the introduction of 0-RTT data for immediate application data transmission upon session resumption.

- Record Layer & Unified Header: Discuss the removal of superfluous fields in the DTLSCiphertext structure and the shift away from TLS-layer fragmentation in favor of a specialized ACK message to handle UDP packet loss/reordering.

## Security Enhancements

- Mandatory AEAD Ciphers: Detail the deprecation of older MAC-then-Encrypt ciphers. DTLS 1.3 strictly uses Authenticated Encryption with Associated Data (AEAD) to guarantee ciphertext integrity natively.

- Encrypted Sequence Numbers: Explain how DTLS 1.3 obfuscates epoch and sequence numbers in the record header to prevent traffic analysis and tracking by middleboxes.

## Proposed Python Implementation Approach

- Architecture of the custom DTLS state machine.

- Integration of the cryptography library for handling the HKDF (HMAC-based Extract-and-Expand Key Derivation Function) primitive and cryptographic state.

- VI. Evaluation & Limitations

- Discussion of the challenges in building datagram security in Python (e.g., handling asynchronous packet drops without the OS TCP stack).

## Conclusion

- Summary of findings regarding the protocol's efficiency and modern security posture.

## Resources 

> E. Rescorla, H. Tschofenig, and N. Modadugu, "The Datagram Transport Layer Security (DTLS) Protocol Version 1.3," RFC 9147, Apr. 2022. [Online]. Available: https://datatracker.ietf.org/doc/rfc9147/

> Y. Sheffer, R. Holz, and P. Saint-Andre, "Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)," RFC 9325, Nov. 2022. [Online]. Available: https://datatracker.ietf.org/doc/rfc9325/

> M. Serafin, M. Díaz, A. Laya, and V. Fodor, "Low-Power IoT Communication Security: On the Performance of DTLS and TLS 1.3," arXiv preprint arXiv:2011.12035, Nov. 2020.

> F. Günther et al., "Robust Channels: Handling Unreliable Networks in the Record Layers of QUIC and DTLS 1.3," Journal of Cryptology, Jan. 2024.

> M. Hell et al., "Hidden Stream Ciphers and TMTO Attacks on TLS 1.3, DTLS 1.3, QUIC, and Signal," IACR Cryptology ePrint Archive, Report 2023/913, 2023.
