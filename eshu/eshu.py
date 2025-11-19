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
        secret_config = get_env("ESHU_SECRET", None)
        if not secret_config:
            secret_val = get_env("ENCRYPTION", None)
            if get_env("ENCRYPTION_SM", False):
                secret_config = f"aws-sm:{secret_val}"
            else:
                secret_config = secret_val
        debug(secret_config, "eshu::secret_config", lvl=2)
        self._secret_config = secret_config
        self._passphrase = None
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
        if not self._secret_config:
            raise EshuError(
                "Passphrase source not configured. Set ESHU_SECRET env variable."
            )
        if self._secret_config.startswith("aws-sm:"):
            from eshu.sm import get_secret, SecretsManagerError

            secret_name = self._secret_config[7:]
            key_id = self._key_id or get_env("AWS_KEY_ID", None)
            aws_secret = self._secret or get_env("AWS_SECRET", None)
            region = self._region or get_env("AWS_REGION", "ap-southeast-1")
            try:
                secret = get_secret(
                    secret_name,
                    key_id=key_id,
                    secret=aws_secret,
                    region=region,
                )
            except SecretsManagerError as e:
                raise EshuError(
                    f"Failed to retrieve secret from AWS Secrets Manager: {e}"
                )

            if not secret:
                raise EshuError(
                    "Failed to get secret from AWS Secrets Manager. "
                    "Set AWS credentials as env variables or pass them as args."
                )
            self._passphrase = secret
        else:
            self._passphrase = self._secret_config

    def _get_passphrase(self) -> str:
        if not self._passphrase:
            self._fetch_passphrase()
        return self._passphrase

    def encrypt(self, text: str) -> str:
        passphrase = self._get_passphrase()
        try:
            salt = os.urandom(16)
            key = self._derive_key(salt, passphrase)
            fernet = Fernet(key)
            encrypted = fernet.encrypt(text.encode())
            return base64.urlsafe_b64encode(salt + encrypted).decode().rstrip("=")
        except Exception as e:
            raise EshuError(f"Encryption failed: {e}")

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
