import Cryptography.certificata_req
import Cryptography.new_acces_token
import dotenv
import os
import getpass


def handeling_new_acces_token():
    return Cryptography.new_acces_token.new_acces_token()


def handeling_new_ca(env_file):
    dotenv.load_dotenv(env_file
    )
    #######Ask for the CA Password#####
    CA_password = getpass.getpass("Enter a secure password for the CA private key: ")

    ######Define CA Variables######
    CA_priv_key_filename = os.getenv("ENV_CA_priv_key_filename")
    CA_cert_filename = os.getenv("ENV_CA_cert_filename")
    RAW_CA_subjects = eval(os.getenv("ENV_CA_subjects"))

    CA_alternative_names = eval(os.getenv("ENV_CA_alternative_names"))


    CA_subject = Cryptography.certificata_req.build_X509_Name(RAW_CA_subjects)
    Cryptography.certificata_req.gen_ca(CA_subject, CA_priv_key_filename, CA_cert_filename, CA_password, CA_alternative_names)

def handeling_new_csr(env_file):
    dotenv.load_dotenv(env_file)
    ######Define CA Variables######
    Client_priv_key_filename = os.getenv("ENV_Client_priv_key_filename")
    Client_csr_filename = os.getenv("ENV_Client_csr_filename")
    Client_cert_filename = os.getenv("ENV_Client_cert_filename")
    RAW_Client_subjects = eval(os.getenv("ENV_Client_subjects"))

    Client_alternative_names = eval(os.getenv("ENV_Client_alternative_names"))


    ####BUILD####
    Client_subject = subject = Cryptography.certificata_req.build_X509_Name(RAW_Client_subjects)

    return Cryptography.certificata_req.gen_csr(Client_subject, Client_priv_key_filename, Client_csr_filename, Client_alternative_names)

def handeling_new_cert_from_csr(client_csr_file, env_file, CA_password):
    dotenv.load_dotenv(env_file)

    ######Define Cert Variables######
    CA_priv_key_filename = os.getenv("ENV_CA_priv_key_filename")
    CA_cert_filename = os.getenv("ENV_CA_cert_filename")


    ####BUILD####
    return Cryptography.certificata_req.sign_csr(CA_priv_key_filename, CA_cert_filename, CA_password, client_csr_file)
