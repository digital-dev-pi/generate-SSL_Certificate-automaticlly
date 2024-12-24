import Transport.client
import Transport.server
import dotenv
import os
import getpass

def handling_server(function, env_file):

    #######Ask for the CA Password#####
    CA_password = getpass.getpass("Enter the password of the CA private key: ")

    dotenv.load_dotenv(env_file)
    HOST = os.getenv("ENV_HOST")
    PORT = int(os.getenv("ENV_PORT"))
    END_COMMAMD = os.getenv("ENV_END_COMMAMD").encode("utf-8")
    CORRECT_TOKEN = bytes.fromhex(os.getenv("ENV_CORRECT_TOKEN"))
    return Transport.server.gen_server(HOST, PORT, END_COMMAMD, CORRECT_TOKEN, env_file, function, CA_password)

def handeling_client_transport(client_csr_file, env_file):
    dotenv.load_dotenv(env_file)
    HOST = os.getenv("ENV_HOST")
    PORT = int(os.getenv("ENV_PORT"))
    END_COMMAMD = os.getenv("ENV_END_COMMAMD").encode("utf-8")
    TOKEN = bytes.fromhex(os.getenv("ENV_CORRECT_TOKEN"))

    Client_cert_filename = os.getenv("ENV_Client_cert_filename")

    Client_cert = Transport.client.client_trasnport(HOST, PORT, END_COMMAMD, TOKEN, client_csr_file)

    with open(Client_cert_filename, "wb") as f:
        f.write(Client_cert)