#!/bin/python3
import Handler.handler_transport
import Handler.handling_cryptrography
import sys

def help():
    print("""Help:
    Usage: python main.py [options...]

    Options:

        -h, --help    This Help

        --new_Token   Generate new acces Token
        --new_CA      Generate new CA
        --server      Start the server component
        --client      Start the client component
        
        Optional:
            add after --server and --client the config file:
                e.g. --server /any/path/config.env
                default is: ./config.env""")
    exit()

def save_file(name, content):
    with open(name, "wb") as f:
        f.write(content)

def main(args):
    arg = args[1]

    if len(args) != 3:
        env_file = "./config.env"
    else:
        env_file = args[2]


    if arg == "--new_Token":
        print(Handler.handling_cryptrography.handeling_new_acces_token())
    elif arg == "--new_CA":
        Handler.handling_cryptrography.handeling_new_ca(env_file)
   
    elif arg == "--server":
        Handler.handler_transport.handling_server(Handler.handling_cryptrography.handeling_new_cert_from_csr, env_file)
    elif arg == "--client":
        client_csr_file = Handler.handling_cryptrography.handeling_new_csr(env_file)
        Handler.handler_transport.handeling_client_transport(client_csr_file, env_file)
        print("fertig")
    else:
        help()
    
        

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        main(sys.argv)
    else:
        help()