import socket, time, os, dotenv
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import Cryptography.encrypt_or_decrypt
import Transport.send_or_recive


def client_trasnport(HOST, PORT, END_COMMAMD, TOKEN, client_csr_file):
    BUFFER_SIZE = 4096  # Buffer size for sending

    client_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=8192, backend=default_backend()
    )
    client_public_key = client_private_key.public_key()
    client_public_key_bytes = client_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #####Connection Setup
        s.connect((HOST, PORT))
        
        s.sendall(client_public_key_bytes) # send publi
        s.sendall(END_COMMAMD)

        aes_key_password_from_server_encrypted = Transport.send_or_recive.recive(s, END_COMMAMD, BUFFER_SIZE)
        aes_key_iv_from_server_encrypted = Transport.send_or_recive.recive(s, END_COMMAMD, BUFFER_SIZE)

        
        aes_password = Cryptography.encrypt_or_decrypt.rsa_decryption(client_private_key, aes_key_password_from_server_encrypted)
        aes_iv = Cryptography.encrypt_or_decrypt.rsa_decryption(client_private_key, aes_key_iv_from_server_encrypted)

        aes_key = Cryptography.encrypt_or_decrypt.gen_aes_key(aes_password, aes_iv)

        cipher_token = Cryptography.encrypt_or_decrypt.aes_encryption(aes_key, TOKEN)
        s.sendall(cipher_token)
        time.sleep(0.1)
        s.sendall(END_COMMAMD)
        

        #####File_Transport
        cipher_client_csr_file = Cryptography.encrypt_or_decrypt.aes_encryption(aes_key, client_csr_file)
        s.sendall(cipher_client_csr_file)
        s.sendall(END_COMMAMD)

        cipher_client_cert = Transport.send_or_recive.recive(s, END_COMMAMD, BUFFER_SIZE)
        return Cryptography.encrypt_or_decrypt.aes_decryption(aes_key, cipher_client_cert)