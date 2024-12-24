from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import  hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def rsa_encryption(public_rsa_key, input):
    return public_rsa_key.encrypt(input, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()), algorithm=hashes.SHA512(), label=None))

def rsa_decryption(private_rsa_key, cipher):
    return private_rsa_key.decrypt(cipher, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA512(),label=None))

def gen_aes_key(aes_password, aes_iv):
    return Cipher(algorithms.AES256(aes_password), modes.CTR(aes_iv))

def aes_encryption(aes_key, input):
    aes_encryptor = aes_key.encryptor()
    return aes_encryptor.update(input) + aes_encryptor.finalize()

def aes_decryption(aes_key, cipher):
    aes_decryptor = aes_key.decryptor()
    return aes_decryptor.update(cipher) + aes_decryptor.finalize()