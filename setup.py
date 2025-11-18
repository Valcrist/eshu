from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="eshu",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "boto3",
        "toolbox @ git+https://github.com/Valcrist/toolbox.git#egg=toolbox",
    ],
    url="https://github.com/Valcrist/eshu",
    author="Valcrist",
    author_email="github@valcrist.com",
    description="Tool for encryption and decryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
)
