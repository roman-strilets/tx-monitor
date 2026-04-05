"""Encrypted secure channel for the Beam peer-to-peer protocol.

Implements the ECDH key-exchange and AES-CTR / HMAC-SHA256 encryption
layer used by Beam's ``SChannelInitiate`` / ``SChannelReady`` handshake.
All cryptographic operations are performed in-place on raw byte strings so
that :class:`~src.connection.BeamConnection` can encrypt outgoing frames
and decrypt incoming ones transparently.
"""
import hashlib
import hmac as hmac_mod

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import Point as ECPoint

from .protocol import MAC_SIZE


class SecureChannel:
    """ECDH-negotiated AES-CTR + HMAC-SHA256 channel for the Beam protocol.

    Call :meth:`generate_nonce` to produce the local public key (sent as the
    ``SChannelInitiate`` payload), then :meth:`derive_keys` once the remote
    public key has been received.  After that, set :attr:`out_on` /
    :attr:`in_on` to start encrypting outgoing / decrypting incoming frames.
    """

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
        """Generate a fresh ECDH key-pair and return the public X-coordinate.

        The generated signing key is stored internally for use by
        :meth:`derive_keys`.  If the resulting Y-coordinate is odd the key is
        negated to produce an even-Y (compressed) public key.

        Returns:
            32-byte big-endian X-coordinate of the local public key.
        """
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
        """Derive shared AES and HMAC keys from the remote public X-coordinate.

        Recovers the remote public key (assuming even Y), performs scalar
        multiplication to obtain the shared secret, then derives the HMAC key
        and two AES-CTR IVs (one per direction) via SHA-256.

        Args:
            remote_x: 32-byte big-endian X-coordinate of the remote public key
                as received in the ``SChannelInitiate`` reply.

        Raises:
            RuntimeError: If :meth:`generate_nonce` has not been called.
        """
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
        """Encrypt *data* with AES-CTR if outgoing encryption is enabled.

        Args:
            data: Plaintext bytes to encrypt.

        Returns:
            Ciphertext bytes, or *data* unchanged when :attr:`out_on` is
            ``False``.
        """
        return self._enc.update(data) if self.out_on else data

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt *data* with AES-CTR if incoming decryption is enabled.

        Args:
            data: Ciphertext bytes to decrypt.

        Returns:
            Plaintext bytes, or *data* unchanged when :attr:`in_on` is
            ``False``.
        """
        return self._dec.update(data) if self.in_on else data

    def mac(self, header: bytes, body: bytes) -> bytes:
        """Compute the 8-byte HMAC-SHA256 authentication tag for a frame.

        The tag is the last :data:`~src.protocol.MAC_SIZE` bytes of
        ``HMAC-SHA256(key, header + body)``.

        Args:
            header: 8-byte frame header.
            body: Frame payload (plaintext).

        Returns:
            8-byte MAC tag.
        """
        return hmac_mod.new(self._hmac_key, header + body, hashlib.sha256).digest()[
            -MAC_SIZE:
        ]