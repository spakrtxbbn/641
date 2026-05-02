import struct
import os

class SHA256:
    """
    implementation of SHA-256 as per FIPS 180-4.
    """
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80f756fb, 0x983e5152, 0xa831c66d,
        0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xca62c1d6, 0xdf645504, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
        0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0x1fb6c351, 0xaa3d4a4c, 0x39494be1, 0x4881d049, 0x7d9d0ad7, 0x17850342, 0x85848993, 0x5b548d5a,
        0x6b133733, 0x810638b8, 0x8cc70208, 0x90befffa, 0xa452e980, 0xbebf0be0, 0xc67178f2, 0xca273ece,
        0x2b164ed6, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6ca6351e, 0xf400391d, 0x3b61e222, 0x163fade6,
        0x5f171839, 0x0682efc1, 0xa4946bcb, 0xefc19dc6, 0x8b0cced6, 0x9d6432d1, 0x1462b583, 0x510e527f
    ]

    @staticmethod
    def _rotr(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def hash(data):
        orig_len_bits = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
        data += b'\x80'
        while (len(data) * 8) % 512 != 448:
            data += b'\x00'
        data += struct.pack(">Q", orig_len_bits)

        h0, h1, h2, h3, h4, h5, h6, h7 = SHA256.H

        for i in range(0, len(data), 64):
            chunk = data[i:i+64]
            w = list(struct.unpack(">16I", chunk)) + [0] * 48
            for j in range(16, 64):
                s0 = SHA256._rotr(w[j-15], 7) ^ SHA256._rotr(w[j-15], 18) ^ (w[j-15] >> 3)
                s1 = SHA256._rotr(w[j-2], 17) ^ SHA256._rotr(w[j-2], 19) ^ (w[j-2] >> 10)
                w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF

            a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

            for j in range(64):
                S1 = SHA256._rotr(e, 6) ^ SHA256._rotr(e, 11) ^ SHA256._rotr(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + S1 + ch + SHA256.K[j] + w[j]) & 0xFFFFFFFF
                S0 = SHA256._rotr(a, 2) ^ SHA256._rotr(a, 13) ^ SHA256._rotr(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xFFFFFFFF

                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF

            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF
            h5 = (h5 + f) & 0xFFFFFFFF
            h6 = (h6 + g) & 0xFFFFFFFF
            h7 = (h7 + h) & 0xFFFFFFFF

        return struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7)

class HMAC:
    @staticmethod
    def compute(key, msg):
        block_size = 64
        if len(key) > block_size:
            key = SHA256.hash(key)
        if len(key) < block_size:
            key = key + b'\x00' * (block_size - len(key))
        
        o_key_pad = bytes([b ^ 0x5c for b in key])
        i_key_pad = bytes([b ^ 0x36 for b in key])
        
        return SHA256.hash(o_key_pad + SHA256.hash(i_key_pad + msg))

class HKDF:
    @staticmethod
    def extract(salt, ikm):
        if salt is None:
            salt = b'\x00' * 32
        return HMAC.compute(salt, ikm)

    @staticmethod
    def expand(prk, info, length):
        t = b""
        okm = b""
        i = 1
        while len(okm) < length:
            t = HMAC.compute(prk, t + info + bytes([i]))
            okm += t
            i += 1
        return okm[:length]

class X25519:
    """
    implementation of X25519 Diffie-Hellman.
    """
    P = 2**255 - 19
    A24 = 121665 # (486662 * 2) % P

    @staticmethod
    def _clamp(scalar):
        s = bytearray(scalar)
        s[0] &= 248
        s[31] &= 127
        s[31] |= 64
        return bytes(s)

    @staticmethod
    def scalar_mult(n, u):
        x_1 = u
        x_2, z_2 = 1, 0
        x_3, z_3 = u, 1
        
        scalar_int = int.from_bytes(n, 'little')
        for i in range(254, -1, -1):
            bit = (scalar_int >> i) & 1
            if bit:
                x_2, x_3 = x_3, x_2
                z_2, z_3 = z_3, z_2
            
            A = (x_2 + z_2) % X25519.P
            B = (x_2 - z_2) % X25519.P
            C = (x_3 + z_3) % X25519.P
            D = (x_3 - z_3) % X25519.P
            
            AA = (A * A) % X25519.P
            BB = (B * B) % X25519.P
            E = (AA - BB) % X25519.P
                
            x_3 = ((C * B + D * A) ** 2) % X25519.P
            z_3 = (x_1 * (C * B - D * A) ** 2) % X25519.P
            x_2 = (AA * BB) % X25519.P
            z_2 = (E * (BB + (X25519.A24 * E))) % X25519.P
            
            if bit:
                x_2, x_3 = x_3, x_2
                z_2, z_3 = z_3, z_2
                
        return (x_2 * pow(z_2, X25519.P - 2, X25519.P)) % X25519.P

    @staticmethod
    def generate_keypair():
        priv = os.urandom(32)
        clamped = X25519._clamp(priv)
        pub_int = X25519.scalar_mult(clamped, 9)
        pub = pub_int.to_bytes(32, 'little')
        return clamped, pub

    @staticmethod
    def shared_secret(priv, pub):
        clamped = X25519._clamp(priv)
        u = int.from_bytes(pub, 'little')
        secret_int = X25519.scalar_mult(clamped, u)
        return secret_int.to_bytes(32, 'little')

class AES:
    """
    implementation of AES-128.
    """
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xbb, 0x70, 0x4a, 0x9d,
        0x2c, 0x58, 0xc7, 0x45, 0xb0, 0xca, 0x34, 0xa5, 0xe5, 0xf1, 0x73, 0xcc, 0x47, 0x77, 0x60, 0x81,
        0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
        0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81, 0x06, 0xca, 0x62, 0x73, 0x42, 0x89, 0xfa, 0x58, 0xab,
        0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7, 0x11, 0x8a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde,
        0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81, 0x06, 0xca, 0x62, 0x73,
        0x42, 0x89, 0xfa, 0x58, 0xab, 0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7, 0x11, 0x8a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16,
        0x81, 0x06, 0xca, 0x62, 0x73, 0x42, 0x89, 0xfa, 0x58, 0xab, 0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac,
        0xb7, 0x11, 0x8a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a,
        0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81, 0x06, 0xca, 0x62, 0x73, 0x42, 0x89, 0xfa, 0x58, 0xab, 0xbe,
        0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7, 0x11, 0x8a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e,
        0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81, 0x06, 0xca, 0x62, 0x73, 0x42,
        0x89, 0xfa, 0x58, 0xab, 0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7, 0x11, 0x8a, 0x90, 0x88, 0x46,
        0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81,
        0x06, 0xca, 0x62, 0x73, 0x42, 0x89, 0xfa, 0x58, 0xab, 0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7
    ]
    
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xbb, 0x70, 0x4a, 0x9d,
        0x2c, 0x58, 0xc7, 0x45, 0xb0, 0xca, 0x34, 0xa5, 0xe5, 0xf1, 0x73, 0xcc, 0x47, 0x77, 0x60, 0x81,
        0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
        0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81, 0x06, 0xca, 0x62, 0x73, 0x42, 0x89, 0xfa, 0x58, 0xab,
        0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7, 0x11, 0x8a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde,
        0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81, 0x06, 0xca, 0x62, 0x73,
        0x42, 0x89, 0xfa, 0x58, 0xab, 0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7, 0x11, 0x8a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16,
        0x81, 0x06, 0xca, 0x62, 0x73, 0x42, 0x89, 0xfa, 0x58, 0xab, 0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac,
        0xb7, 0x11, 0x8a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a,
        0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81, 0x06, 0xca, 0x62, 0x73, 0x42, 0x89, 0xfa, 0x58, 0xab, 0xbe,
        0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7, 0x11, 0x8a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e,
        0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81, 0x06, 0xca, 0x62, 0x73, 0x42,
        0x89, 0xfa, 0x58, 0xab, 0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7, 0x11, 0x8a, 0x90, 0x88, 0x46,
        0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0f, 0x43, 0x2d, 0xcb, 0x16, 0x81,
        0x06, 0xca, 0x62, 0x73, 0x42, 0x89, 0xfa, 0x58, 0xab, 0xbe, 0xbc, 0x13, 0x27, 0xc7, 0xac, 0xb7
    ]

    @staticmethod
    def _sub_bytes(state):
        for i in range(16):
            state[i] = AES.SBOX[state[i]]

    @staticmethod
    def _shift_rows(state):
        s = state[:]
        state[1] = s[5]; state[5] = s[9]; state[9] = s[13]; state[13] = s[1]
        state[2] = s[10]; state[6] = s[14]; state[10] = s[2]; state[14] = s[6]
        state[3] = s[15]; state[7] = s[11]; state[11] = s[3]; state[15] = s[7]

    @staticmethod
    def _mix_columns(state):
        for i in range(0, 16, 4):
            a = state[i]; b = state[i+1]; c = state[i+2]; d = state[i+3]
            state[i] = (AES._galois_mul(a, 2) ^ AES._galois_mul(b, 3) ^ c ^ d) & 0xFF
            state[i+1] = (a ^ AES._galois_mul(b, 2) ^ AES._galois_mul(c, 3) ^ d) & 0xFF
            state[i+2] = (a ^ b ^ AES._galois_mul(c, 2) ^ AES._galois_mul(d, 3)) & 0xFF
            state[i+3] = (AES._galois_mul(a, 3) ^ b ^ c ^ AES._galois_mul(d, 2)) & 0xFF

    @staticmethod
    def _galois_mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set: a ^= 0x1b
            b >>= 1
        return p

    @staticmethod
    def _key_expansion(key):
        words = list(struct.unpack(">4I", key))
        rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        for i in range(4, 44):
            temp = words[i-1]
            if i % 4 == 0:
                # RotWord + SubWord + Rcon
                temp = ((AES.SBOX[(temp >> 0) & 0xFF] << 24) | 
                        (AES.SBOX[(temp >> 8) & 0xFF] << 16) | 
                        (AES.SBOX[(temp >> 16) & 0xFF] << 8) | 
                        (AES.SBOX[(temp >> 24) & 0xFF])) ^ (rcon[i//4 - 1] << 24)
            words.append(words[i-4] ^ temp)
        
        expanded = []
        for w in words:
            expanded.extend(struct.pack(">I", w))
        return bytes(expanded)

    @staticmethod
    def encrypt_block(plaintext, key):
        expanded_key = AES._key_expansion(key)
        state = list(plaintext)
        
        # Initial round
        for i in range(16): state[i] ^= expanded_key[i]
        
        for round_idx in range(1, 10):
            AES._sub_bytes(state)
            AES._shift_rows(state)
            AES._mix_columns(state)
            for i in range(16): state[i] ^= expanded_key[round_idx*16 + i]
            
        AES._sub_bytes(state)
        AES._shift_rows(state)
        for i in range(16): state[i] ^= expanded_key[160 + i]
        
        return bytes(state)

    @staticmethod
    def decrypt_block(ciphertext, key):
        # Decryption is the inverse. For this project, we use AES in CTR mode,
        # so we only need the encrypt_block function.
        return AES.encrypt_block(ciphertext, key)

class AESGCM:
    """
    implementation of AES-GCM.
    """
    def __init__(self, key):
        self.key = key

    def _ghash(self, h_bytes, data):
        h = int.from_bytes(h_bytes, 'big')
        y = 0
        for i in range(0, len(data), 16):
            block = data[i:i+16].ljust(16, b'\x00')
            val = int.from_bytes(block, 'big')
            y ^= val
            # Multiplication in GF(2^128)
            res = 0
            for bit in range(127, -1, -1):
                if (y >> bit) & 1:
                    res ^= h
                y = (y << 1) & ((1 << 128) - 1)
                if y & (1 << 128):
                    y ^= 0xe1000000000000000000000000000000
            y = res
        return y.to_bytes(16, 'big')

    def encrypt(self, nonce, plaintext, associated_data):
        # 1. Generate H = AES(key, 0^128)
        h = AES.encrypt_block(b'\x00' * 16, self.key)
        
        # 2. CTR Mode Encryption
        ciphertext = b""
        counter = int.from_bytes(nonce + b'\x00\x00\x00\x01', 'big')
        for i in range(0, len(plaintext), 16):
            keystream = AES.encrypt_block(counter.to_bytes(16, 'big'), self.key)
            block = plaintext[i:i+16]
            ciphertext += bytes([p ^ k for p, k in zip(block, keystream)])
            counter += 1
            
        # 3. Authentication Tag (GHASH)
        # len(AAD) || len(C)
        len_aad = (len(associated_data) * 8).to_bytes(8, 'big')
        len_ct = (len(ciphertext) * 8).to_bytes(8, 'big')
        auth_data = associated_data.ljust((len(associated_data) + 15) // 16 * 16, b'\x00')
        auth_data += ciphertext.ljust((len(ciphertext) + 15) // 16 * 16, b'\x00')
        auth_data += len_aad + len_ct
        
        tag_hash = self._ghash(h, auth_data)
        # Mask tag with AES(key, nonce || 0^31 || 1)
        j0 = AES.encrypt_block(nonce + b'\x00' * 3 + b'\x01', self.key)
        tag = bytes([t ^ j for t, j in zip(tag_hash, j0)])
        
        return ciphertext + tag

    def decrypt(self, nonce, ciphertext_with_tag, associated_data):
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        # 1. Verify Tag
        h = AES.encrypt_block(b'\x00' * 16, self.key)
        len_aad = (len(associated_data) * 8).to_bytes(8, 'big')
        len_ct = (len(ciphertext) * 8).to_bytes(8, 'big')
        auth_data = associated_data.ljust((len(associated_data) + 15) // 16 * 16, b'\x00')
        auth_data += ciphertext.ljust((len(ciphertext) + 15) // 16 * 16, b'\x00')
        auth_data += len_aad + len_ct
        
        tag_hash = self._ghash(h, auth_data)
        j0 = AES.encrypt_block(nonce + b'\x00' * 3 + b'\x01', self.key)
        expected_tag = bytes([t ^ j for t, j in zip(tag_hash, j0)])
        
        if tag != expected_tag:
            raise Exception("Authentication failed")
            
        # 2. CTR Mode Decryption
        plaintext = b""
        counter = int.from_bytes(nonce + b'\x00\x00\x00\x01', 'big')
        for i in range(0, len(ciphertext), 16):
            keystream = AES.encrypt_block(counter.to_bytes(16, 'big'), self.key)
            block = ciphertext[i:i+16]
            plaintext += bytes([c ^ k for c, k in zip(block, keystream)])
            counter += 1
            
        return plaintext