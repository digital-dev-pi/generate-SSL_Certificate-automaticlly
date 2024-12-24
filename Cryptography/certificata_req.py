#!/bin/python3

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509

import datetime, dotenv, os

def build_X509_Name(Subjects):
    return x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, Subjects["COUNTRY_NAME"]),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, Subjects["STATE_OR_PROVINCE_NAME"]),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, Subjects["LOCALITY_NAME"]),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, Subjects["ORGANIZATION_NAME"]),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, Subjects["ORGANIZATIONAL_UNIT_NAME"]),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, Subjects["COMMON_NAME"]),
    ])

def gen_ca(CA_subject, CA_priv_key_filename, CA_cert_filename, CA_password, CA_alternative_names, CA_time_to_expiration=365, CA_priv_key_size=8192):
    CA_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=CA_priv_key_size, backend=default_backend()
    )

    CA_cert_builder = (  
        x509.CertificateBuilder()
        .subject_name(CA_subject)
        .issuer_name(CA_subject)
        .public_key(CA_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=CA_time_to_expiration))
        .add_extension(
            x509.extensions.BasicConstraints(ca=True, path_length=5),
            critical=True,
            )
    )

    CA_cert_builder = CA_cert_builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in CA_alternative_names]), critical=False)
    CA_cert = CA_cert_builder.sign(CA_private_key, hashes.SHA256(), default_backend())
    
       # Write the certificate to PEM format
    with open(CA_cert_filename, "wb") as pem_file:
        pem_file.write(CA_cert.public_bytes(encoding=serialization.Encoding.PEM))

    # Write the private key to PEM format (unencrypted)
    with open(CA_priv_key_filename, "wb") as pem_file:
        pem_file.write(
            CA_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(CA_password.encode("utf-8")),
            )
        )



def gen_csr(Client_subject, Client_priv_key_filename, Client_csr_filename, Client_alternative_names, Client_priv_key_size=8192):
    Client_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=Client_priv_key_size, backend=default_backend()
    )

    Client_csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(Client_subject)
        .add_extension(
                x509.extensions.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
    )

    Client_csr_builder = Client_csr_builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in Client_alternative_names]), critical=False)
    Client_csr = Client_csr_builder.sign(Client_private_key, hashes.SHA256(), default_backend())

    with open(Client_priv_key_filename, "wb") as pem_file:
        pem_file.write(
            Client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    return Client_csr.public_bytes(encoding=serialization.Encoding.PEM)



def sign_csr(CA_priv_key_filename, CA_cert_filename, CA_password, Client_csr_file, Client_time_to_expiration=60):

    # Load the CSR, CA certificate, and CA private key
    Client_csr = x509.load_pem_x509_csr(Client_csr_file, default_backend())

    with open(CA_cert_filename, "rb") as f:
        CA_cert_data = f.read()
    CA_cert = x509.load_pem_x509_certificate(CA_cert_data, default_backend())

    with open(CA_priv_key_filename, "rb") as f:
        CA_priv_key_data = f.read()

    CA_priv_key = serialization.load_pem_private_key(
        CA_priv_key_data,
        password=CA_password.encode("utf-8"),  # If the CA private key is password-protected, provide the password here
        backend=default_backend(),
    )
    
    # Create a certificate builder and set the issuer, subject, public key, serial number, and validity period
    Client_cert_builder = (
        x509.CertificateBuilder()
        .issuer_name(CA_cert.subject)
        .subject_name(Client_csr.subject)
        .public_key(Client_csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=Client_time_to_expiration))
    )

    # Add any extensions from the CSR to the certificate builder
    for extension in Client_csr.extensions:
        Client_cert_builder = Client_cert_builder.add_extension(extension.value, extension.critical)

    Client_cert = Client_cert_builder.sign(private_key=CA_priv_key, algorithm=hashes.SHA256(), backend=default_backend())

    return Client_cert.public_bytes(encoding=serialization.Encoding.PEM)