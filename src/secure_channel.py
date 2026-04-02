import hashlib
import hmac as hmac_mod

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import Point as ECPoint

from .protocol import MAC_SIZE


class SecureChannel:
    def __init__(self):
        self.my_pub_x = b""
        self._sk: SigningKey | None = None
        self.remote_pub_x = b""
        self._hmac_key = b""
        self._enc = None
        self._dec = None
        self.out_on = False
        self.in_on = False

    def generate_nonce(self) -> bytes:
        signing_key = SigningKey.generate(curve=SECP256k1)
        point = signing_key.verifying_key.pubkey.point
        if point.y() % 2 != 0:
            signing_key = SigningKey.from_secret_exponent(
                SECP256k1.order - int.from_bytes(signing_key.to_string(), "big"),
                curve=SECP256k1,
            )
            point = signing_key.verifying_key.pubkey.point

        self._sk = signing_key
        self.my_pub_x = point.x().to_bytes(32, "big")
        return self.my_pub_x

    def derive_keys(self, remote_x: bytes):
        if self._sk is None:
            raise RuntimeError("secure channel nonce was not generated")

        self.remote_pub_x = remote_x
        modulus = SECP256k1.curve.p()
        x_coord = int.from_bytes(remote_x, "big")
        y_squared = (pow(x_coord, 3, modulus) + 7) % modulus
        y_coord = pow(y_squared, (modulus + 1) // 4, modulus)
        if y_coord % 2 != 0:
            y_coord = modulus - y_coord

        remote_point = ECPoint(SECP256k1.curve, x_coord, y_coord, SECP256k1.order)
        scalar = int.from_bytes(self._sk.to_string(), "big")
        shared = remote_point * scalar
        shared_point = shared.x().to_bytes(32, "big") + bytes([shared.y() % 2])
        secret = hashlib.sha256(shared_point).digest()

        self._hmac_key = secret
        out_iv = hashlib.sha256(secret + self.remote_pub_x).digest()[16:]
        in_iv = hashlib.sha256(secret + self.my_pub_x).digest()[16:]
        self._enc = Cipher(algorithms.AES(secret), modes.CTR(out_iv)).encryptor()
        self._dec = Cipher(algorithms.AES(secret), modes.CTR(in_iv)).decryptor()

    def encrypt(self, data: bytes) -> bytes:
        return self._enc.update(data) if self.out_on else data

    def decrypt(self, data: bytes) -> bytes:
        return self._dec.update(data) if self.in_on else data

    def mac(self, header: bytes, body: bytes) -> bytes:
        return hmac_mod.new(self._hmac_key, header + body, hashlib.sha256).digest()[
            -MAC_SIZE:
        ]