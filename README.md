<h1 align="center">Eshu</h1>

<p align="center">
  <strong>A simple tool for symmetric encryption and decryption.</strong>
</p>

<p align="center">
  Named after Eshu - a messenger and trickster deity, interpreter between the Orishas (gods) and humanity.
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/github/v/tag/Valcrist/eshu?style=flat&label=version&color=brightgreen" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-polyform--nc-orange?style=flat" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/github/languages/top/Valcrist/eshu?style=flat" alt="Top Language"></a>
  <a href="https://peps.python.org/pep-0008/"><img src="https://img.shields.io/badge/code%20style-pep8-73e?style=flat" alt="Code Style"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/req:python-3.10%2B-c47?style=flat" alt="Python Version"></a>
  <a href="https://github.com/Valcrist/eshu/activity"><img src="https://img.shields.io/badge/status-active-green?style=flat" alt="Status"></a>
</p>

---



## Installation

To install the package directly from GitHub, run the following command:

```bash
pip install git+https://github.com/Valcrist/eshu.git
```

This will install the package and its dependencies listed in `setup.py`.

## Configuration

`Eshu` is configured through environment variables.

- `ESHU_SECRET`: This variable holds the secret or a URI to the secret.
    - If you provide a direct value (e.g., `my-super-secret-passphrase`), it will be used as the passphrase.
    - If you are using AWS Secrets Manager, the value should be `aws-sm:<secret-name>`, where `<secret-name>` is the name of the secret to be fetched.

### AWS Secrets Manager

If you set `ESHU_SECRET` to `aws-sm:<secret-name>`, `Eshu` will attempt to connect to AWS Secrets Manager. For this to work, you must have your AWS credentials configured. You can do this either by setting the `AWS_KEY_ID`, and `AWS_SECRET` environment variables, or by passing them as parameters when you initialize the `Eshu` class.

## Usage

Here is a simple example of how to use `Eshu` without Secrets Manager

```
# Set environment variables
ESHU_SECRET=my-super-secret-passphrase
```

```python
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
ESHU_SECRET=aws-sm:name-of-your-secret-in-sm

# Make sure your AWS credentials are also configured in the environment
AWS_KEY_ID=your-api-key
AWS_SECRET=your-secret-key
# Optional (defaults to ap-southeast-1)
AWS_REGION=ap-southeast-1
```

```python
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
ESHU_SECRET=aws-sm:name-of-your-secret-in-sm
```

```python
from eshu import Eshu, EshuError


try:
    # Initialize Eshu with AWS credentials
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