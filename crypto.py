from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


def generate_key():
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


def exist_file(filename):
    try:
        with open(filename, "rb") as f:
            f2 = f.fileno()
            return True
    except:
        return False


def read_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b"flexcoin",
            backend=default_backend()
        )
    return private_key


def get_private_key():
    if not exist_file("private_key.pem"):
        key = generate_key()
    else:
        key = read_key("private_key.pem")
    return key


def bytes_to_hex(s):
    return s.hex()


def hex_to_bytes(s):
    return bytes(bytearray.fromhex(s))


def public_key_to_pem(private_key):
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return bytes_to_hex(pem)


def pem_to_public_key(_pem):
    pem = hex_to_bytes(_pem)
    public_key = serialization.load_pem_public_key(
        pem,
        backend=default_backend()
    )
    return public_key


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
    return bytes_to_hex(signature)


def verify(public_key, _message, _signature):
    message = _message.encode('utf-8')
    signature = hex_to_bytes(_signature)
    try:
        pem_to_public_key(public_key).verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


private_key = get_private_key()
my_address = public_key_to_pem(private_key)
while True:
    cmd = input('enter command: ')
    if cmd == 'sign':
        message = input('enter message: ')
        signature = sign(private_key, message)
        print(signature)
    else:
        print('unsupported command')

# private_key = get_private_key()
# public_key = private_key.public_key()
# printPublicKey(public_key)

# sign = sign(private_key, "flexx")
# verify(public_key, "flexx", sign)