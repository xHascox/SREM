from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64encode, b64decode

def gen_key(length=4096):
    return RSA.generate(length)

def write_key(key, fn="private_key.pem"):
    try:
        with open(fn, "wb") as f:
            f.write(key.export_key())
    except Exception as e:
        print(e)
        return False
    return True

def print_key(key):
    print(key.export_key())

def read_key(fn="private_key.pem"):
    with open(fn, "rb") as f:
        x = RSA.import_key(f.read())
        print("----", x is None)
        return x
def der_pub(key):
    try:
        return key.publickey()
    except:
        return None

def fromobj(key):
    return key.export_key()

def encrypt_rsa(data, key):
    data=data.encode("utf-8")
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    print("______")
    print("C:", ciphertext)
    print("ESK:", enc_session_key)
    print("nonce:", cipher_aes.nonce)
    print("tag:", tag)
    return str(b64encode(enc_session_key))[2:-1] + "\n" + str(b64encode(cipher_aes.nonce))[2:-1] + "\n" + str(b64encode(tag))[2:-1] + "\n" + str(b64encode(ciphertext))[2:-1]

def decrypt_rsa(data, key):
    data=data.split("\n")
    data = [b64decode(x) for x in data]
    enc_session_key, nonce, tag, ciphertext =  data

    print("______")
    print("C:", ciphertext)
    print("ESK:", enc_session_key)
    print("nonce:", nonce)
    print("tag:", tag)

    #data = data[0]+data[1]+data[2]+data[3]
    #enc_session_key, nonce, tag, ciphertext = [ f.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]
    
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))
    return data.decode("utf-8")

if __name__ == "__main__":
    #encrypt with public key of receiver
    data = "this is an example message".encode("utf-8")
    key = gen_key()
    pub = key.publickey()
    priv = key
    session_key = get_random_bytes(16)
    #encrypt session key with pub rsa key
    cipher_rsa = PKCS1_OAEP.new(pub)
    enc_session_key = cipher_rsa.encrypt(session_key)
    #encrypt data with aes session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    with open("encrypted_data.bin", "wb") as f:
        [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    print((enc_session_key, cipher_aes.nonce, ciphertext))

    #decrypt with priv key
    priv = key
    with open("encrypted_data.bin", "rb") as f:
        enc_session_key, nonce, tag, ciphertext = [ f.read(x) for x in (priv.size_in_bytes(), 16, 16, -1) ]
    #decrypt ses
    cipher_rsa = PKCS1_OAEP.new(priv)
    session_key = cipher_rsa.decrypt(enc_session_key)
    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))