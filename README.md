# Eshu

A simple tool for symmetric encryption and decryption.

It's named after Eshu, a messenger and trickster deity who serves as the interpreter between the Orishas (gods) and humanity.

## Installation

To install the package directly from GitHub, run the following command:

```bash
pip install git+https://github.com/Valcrist/eshu.git
```

This will install the package and its dependencies listed in `setup.py`.

## Configuration

`Eshu` is configured through environment variables.

- `ENCRYPTION`: This is the primary secret key. It can be a passphrase you provide directly. If you are using AWS Secrets Manager, this variable should be the name of the secret to be fetched.

- `ENCRYPTION_SM`: Set this to `true` if you want to use AWS Secrets Manager to fetch the secret key. If this is not set or is `false`, `Eshu` will use the value of `ENCRYPTION` directly as the passphrase.

### AWS Secrets Manager

If you set `ENCRYPTION_SM=true`, `Eshu` will attempt to connect to AWS Secrets Manager. For this to work, you must have your AWS credentials configured. You can do this either by setting the `AWS_KEY_ID`, and `AWS_SECRET` environment variables, or by passing them as parameters when you initialize the `Eshu` class.

## Usage

Here is a simple example of how to use `Eshu` without Secrets Manager

```
# Set environment variables
ENCRYPTION_SM=False
ENCRYPTION=my-super-secret-passphrase
```

```python
import os
from eshu import Eshu, EshuError


try:
    # Initialize Eshu
    eshu = Eshu()

    # Encrypt a message
    original_text = "This is a secret message."
    encrypted_token = eshu.encrypt(original_text)

    print(f"Encrypted: {encrypted_token}")

    # Decrypt a message
    decrypted_text = eshu.decrypt(encrypted_token)

    print(f"Decrypted: {decrypted_text}")

    assert original_text == decrypted_text

except EshuError as e:
    print(f"An Eshu error occurred: {e}")
```

### With AWS Secrets Manager

If you are using a secret stored in AWS Secrets Manager

```
# Set environment variables
ENCRYPTION_SM=True
ENCRYPTION=name-of-your-secret-in-sm

# Make sure your AWS credentials are also configured in the environment
AWS_KEY_ID="your-api-key"
AWS_SECRET="your-secret-key"
# Optional (deafults to ap-southeast-1)
AWS_REGION="ap-southeast-1"
```

```python
import os
from eshu import Eshu, EshuError


try:
    # Initialize Eshu
    eshu = Eshu()

    # Encrypt and Decrypt
    original_text = "Another secret message."
    encrypted_token = eshu.encrypt(original_text)
    decrypted_text = eshu.decrypt(encrypted_token)

    assert original_text == decrypted_text

except EshuError as e:
    print(f"An Eshu error occurred: {e}")
```

Alternatively, you can pass the AWS credentials directly to the `Eshu` constructor. This is useful if you prefer not to set them as environment variables.

```
# Set environment variables
ENCRYPTION_SM=True
ENCRYPTION=name-of-your-secret-in-sm
```

```python
from eshu import Eshu, EshuError


try:
    # Initialize Eshu with credentials
    eshu = Eshu(
        key_id="your-api-key",
        secret="your-secret-key",
        region="ap-southeast-1"
    )

    # Encrypt and Decrypt
    original_text = "A third secret message."
    encrypted_token = eshu.encrypt(original_text)
    decrypted_text = eshu.decrypt(encrypted_token)

    assert original_text == decrypted_text

except EshuError as e:
    print(f"An Eshu error occurred: {e}")
```