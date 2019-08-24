from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


# генерация приватного ключа
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
    with open("public_key.pem", "w") as f:
        f.write(public_key_to_pem(key))
    return key

# проверка файла на существование
def exist_file(filename):
    try:
        with open(filename, "rb") as f:
            f2 = f.fileno()
            return True
    except:
        return False


# сериализация приватного ключа
def encode_private(ps: str):
    private_key = serialization.load_pem_private_key(
        ps.encode('utf-8'),
        password=b"flexcoin",
        backend=default_backend()
    )
    return private_key

# чтение приватного ключа из файла
def read_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b"flexcoin",
            backend=default_backend()
        )
    return private_key


# чтение либо создание приватного ключа
def get_private_key():
    if not exist_file("private_key.pem"):
        key = generate_key()
    else:
        key = read_key("private_key.pem")
    return key


# преобразование байтов в строку
def bytes_to_hex(s):
    return s.hex()


# преобразование строки в байты
def hex_to_bytes(s):
    return bytes(bytearray.fromhex(s))


# получение публичного ключа в формате PEM
def public_key_to_pem(private_key):
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return bytes_to_hex(pem)


# получение объекта публичного ключа из строки формата PEM
def pem_to_public_key(_pem):
    pem = hex_to_bytes(_pem)
    public_key = serialization.load_pem_public_key(
        pem,
        backend=default_backend()
    )
    return public_key


# функция подписи строки
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


# функция верификации строки
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

# private_key = get_private_key()
# public_key = private_key.public_key()
# printPublicKey(public_key)

# sign = sign(private_key, "flexx")
# verify(public_key, "flexx", sign)