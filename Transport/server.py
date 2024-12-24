#!/bin/python3
import socket, os, cryptography, time, dotenv
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import Cryptography.encrypt_or_decrypt
import Transport.send_or_recive

def gen_server(HOST, PORT, END_COMMAMD, CORRECT_TOKEN, env_file, function, function_args):
    BUFFER_SIZE = 4096  # Buffer size for receiving

    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            print("new_bind")
            s.listen()
            while True:

                print(f'Waiting for connection at {HOST}:{PORT}')
                conn, addr = s.accept()
                with conn:
                    # gen AES KEYs
                    aes_password = os.urandom(32)
                    aes_iv = os.urandom(16)
                    aes_key = Cryptography.encrypt_or_decrypt.gen_aes_key(aes_password, aes_iv)

                    #####Connection Setup
                    client_public_key_pem = Transport.send_or_recive.recive(conn, END_COMMAMD, BUFFER_SIZE)
                    
                    client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())

                    aes_key_password_for_client_encrypted = Cryptography.encrypt_or_decrypt.rsa_encryption(client_public_key, aes_password)
                    aes_key_iv_for_client_encrypted = Cryptography.encrypt_or_decrypt.rsa_encryption(client_public_key, aes_iv)
        
                    conn.sendall(aes_key_password_for_client_encrypted)
                    conn.sendall(END_COMMAMD)
                    time.sleep(0.1)

                    conn.sendall(aes_key_iv_for_client_encrypted)
                    conn.sendall(END_COMMAMD)

                    
                    cipher = Transport.send_or_recive.recive(conn, END_COMMAMD, BUFFER_SIZE)
                    #print(cipher)
                    recieved_token = Cryptography.encrypt_or_decrypt.aes_decryption(aes_key, cipher)
                    #print(recieved_token)
                    if recieved_token != CORRECT_TOKEN:
                        s.shutdown(socket.SHUT_RD)
                        print("Connection invalid")
                        break
                    else:
                        print("Connection valid")

                    #####Sign
                    cipher_client_csr_file = Transport.send_or_recive.recive(conn, END_COMMAMD, BUFFER_SIZE)
                    client_csr_file = Cryptography.encrypt_or_decrypt.aes_decryption(aes_key, cipher_client_csr_file)
                    client_cert = function(client_csr_file, env_file, function_args)
                    cipher_client_cert = Cryptography.encrypt_or_decrypt.aes_encryption(aes_key, client_cert)

                    conn.sendall(cipher_client_cert)
                    conn.sendall(END_COMMAMD)
                conn.close()