import json
import boto3
from toolbox.utils import get_env
from botocore.exceptions import ClientError


class SecretsManagerError(Exception):
    pass


class SecretsManager:
    _instances = {}

    def __new__(
        cls, aws_access_key_id=None, aws_secret_access_key=None, region_name=None
    ):
        key_id = aws_access_key_id or get_env("AWS_KEY_ID")
        secret = aws_secret_access_key or get_env("AWS_SECRET")
        region = region_name or get_env("AWS_REGION", "ap-southeast-1")

        instance_key = (key_id, secret, region)
        if instance_key not in cls._instances:
            instance = super(SecretsManager, cls).__new__(cls)
            instance._instance_key = instance_key
            cls._instances[instance_key] = instance
            instance._initialized = False
        return cls._instances[instance_key]

    def __init__(
        self, aws_access_key_id=None, aws_secret_access_key=None, region_name=None
    ):
        if hasattr(self, "_initialized") and self._initialized:
            return

        key_id, secret_key, region = self._instance_key

        try:
            session = boto3.Session(
                aws_access_key_id=key_id,
                aws_secret_access_key=secret_key,
                region_name=region,
            )
            self.client = session.client("secretsmanager")
        except Exception as e:
            raise SecretsManagerError(f"Failed to initialize AWS Secrets Manager client: {e}")
        self._initialized = True

    def get_secret(self, secret_name: str):
        if not self.client:
            raise SecretsManagerError("Secrets Manager client is not initialized.")

        try:
            response = self.client.get_secret_value(SecretId=secret_name)
        except ClientError as e:
            raise SecretsManagerError(
                f"Couldn't get secret {secret_name}: {e.response['Error']['Code']}: "
                f"{e.response['Error']['Message']}"
            )

        secret_string = response.get("SecretString")
        if not secret_string:
            return None

        try:
            return json.loads(secret_string)
        except json.JSONDecodeError:
            return secret_string


def get_secret(secret_name: str, key_id=None, secret=None, region=None):
    """
    Retrieves a secret from AWS Secrets Manager using a singleton client.
    """
    sm_client = SecretsManager(
        aws_access_key_id=key_id, aws_secret_access_key=secret, region_name=region
    )
    return sm_client.get_secret(secret_name)
