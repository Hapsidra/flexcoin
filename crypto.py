from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

def generateKey():
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,
        backend=default_backend()
    )
    # Write private key to disk for safe keeping
    with open("private_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"flexcoin"),
        ))
    return key

def existFile(filename):
    try:
        with open(filename, "rb") as f:
            f2 = f.fileno()
            return True
    except:
        return False

def readKey(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b"flexcoin",
            backend=default_backend()
        )
    return private_key

def checkAndCreateKey():
    if not existFile("private_key.pem"):
        key = generateKey()
    else:
        key = readKey("private_key.pem")
    return key

def printBytes(s):
    return s.hex()

def readBytes(s):
    return bytes(bytearray.fromhex(s))

def printPublicKey(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    spem = printBytes(pem)
    print('public key: ' + spem)

def sign(private_key, _message):
    message = _message.encode('utf-8')
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify(public_key, _message, signature):
    message = _message.encode('utf-8')
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature OK")
    except InvalidSignature:
        print("Invalid signature")

private_key = checkAndCreateKey()
public_key = private_key.public_key()
printPublicKey(public_key)

sign = sign(private_key, "flexx")
verify(public_key, "flexx", sign)