# generate-SSL_Certificate-automaticlly
This script provides a server and client component to generate a self-signed SSL certificate with a self-generated Certificate Authority (CA).

## Use

### The needed python packages are:

```
cryptography
dotenv
getpass
datetime

sys
os
```

### Configure the ```config.env``` file

First set all the necessary values for the certificate in the ```config.env``` file. 

**Note:**  There is to set an access token. This can be generated with ```python main.py --new_Token```.
            The token is required to authenticate the client at the server. This authentication mechanism prevents the signing of forged certificates.

### Generate a new Certification Authority (CA):

Before generating a new certificate, you need to creat a new CA with following command: ```python main.py --new_CA```

The public and private key will be stored at the CA folder. 

### Start the program:

1. Server: Start the server component on the computer that will act as your CA. The CA keys must be stored on this machine.

  ```python main.py --server```

2. Client: Start the client component on the machine that will receive the signed certificate.

  ```python main.py --client```

Finally, you have a certificate that is signed by your own CA. When you import your CA certificate at your end devices, the webserver using the client certificate will now have a trusted certificate

<hr>

```
Help:
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
                default is: ./config.env
```
