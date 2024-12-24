import os

def new_acces_token():
    return os.urandom(32).hex()