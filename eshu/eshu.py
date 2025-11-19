import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from toolbox.dot_env import get_env
from toolbox.utils import debug


class EshuError(Exception):
    pass


class Eshu:
    def __init__(self, key_id=None, secret=None, region=None):
        self._secret_source = get_env("ENCRYPTION", None)
        self._use_sm = get_env("ENCRYPTION_SM", False)
        self._passphrase = None

        debug(self._secret_source, "Eshu::secret source", lvl=2)
        debug(self._use_sm, "Eshu::use secrets manager", lvl=2)

        self._key_id = key_id
        self._secret = secret
        self._region = region

    def _derive_key(self, salt: bytes, passphrase: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

    def _fetch_passphrase(self):
        if self._use_sm and self._secret_source:
            from eshu.sm import get_secret

            key_id = self._key_id or get_env("AWS_KEY_ID", None)
            aws_secret = self._secret or get_env("AWS_SECRET", None)
            region = self._region or get_env("AWS_REGION", "ap-southeast-1")

            secret = get_secret(
                self._secret_source,
                key_id=key_id,
                secret=aws_secret,
                region=region,
            )
            if not secret:
                raise EshuError(
                    "Failed to get secret from AWS Secrets Manager. Set AWS credentials as env or pass as args."
                )
            self._passphrase = secret

        elif self._secret_source:
            self._passphrase = self._secret_source
        else:
            raise EshuError("Passphrase source not configured. Set ENCRYPTION env variable.")

    def _get_passphrase(self) -> str:
        if not self._passphrase:
            self._fetch_passphrase()
        return self._passphrase

    def encrypt(self, text: str) -> str:
        passphrase = self._get_passphrase()
        salt = os.urandom(16)
        key = self._derive_key(salt, passphrase)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text.encode())
        return base64.urlsafe_b64encode(salt + encrypted).decode().rstrip("=")

    def decrypt(self, token: str) -> str:
        passphrase = self._get_passphrase()
        try:
            stripped = len(token) % 4
            if stripped:
                token += "=" * (4 - stripped)
            decoded_token = base64.urlsafe_b64decode(token.encode())
            salt = decoded_token[:16]
            encrypted_text = decoded_token[16:]
            key = self._derive_key(salt, passphrase)
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted_text)
            return decrypted.decode()
        except Exception as e:
            raise EshuError(f"Decryption failed: {e}")
