# This file contains all the initialisation steps, used to set up the cryptographic environment.
# File will not be executed as part of the communication protocol and so the keys/certs will be distributed offline.
# Once initilisation is complete Alice and Bob will individually have access to:
#   1) Their own private/secret key (RSAprivate.pem)
#   2) Their own public key (RSApublic.pem)
#   3) Their digital certificate, signed by the CA (certificate.crt)

from project import ss_cert_gen, user_cert_gen, rsa_key_gen, get_key
import pathlib

cwd = pathlib.Path(__file__).parent.resolve()

def key_init(user): # Function to generate asymmetric keys for user specified
    rsa_key_gen(f"{cwd}/project/{user}") # Generate RSA key pair and save in user folder
    print(f"\n-- {user.upper()} CRYPTOGRAPHIC KEY GENERATION [COMPLETE] --\n")
    sk = get_key(f"{cwd}/project/{user}/RSAprivate.pem", "RSA") # Get secret key from user folder
    pk = get_key(f"{cwd}/project/{user}/RSApublic.pem", "RSA") # Get public key from user folder
    return sk, pk # Return keys (PEM)

def ca_init(pkA, pkB): # Function to create certificates
    skCA, pkCA = key_init("ca") # Create CA keys
    ss_cert_gen(
        emailAddress="Trusted3rdParty@my365.dmu.ac.uk",
        commonName="TTP",
        countryName="UK",
        organizationName="CA",
        serialNumber=0,
        validityEndInSeconds=10*365*24*60*60,
        CERT_DESTINATION=f"{cwd}/project/ca/root.crt",
        sk = skCA,
        pk = pkCA
        ) # Generate self-signed certificate
    user_cert_gen(
        emailAddress="alice@my365.dmu.ac.uk",
        commonName="Alice",
        countryName="UK",
        organizationName="DMU",
        serialNumber=1001,
        validityEndInSeconds=10*365*24*60*60,
        CERT_DESTINATION=f"{cwd}/project/alice/certificate.crt",
        sk=skCA,
        pk=pkA
        ) # Generate certificate for Alice, signed by CA
    user_cert_gen(
        emailAddress="bob@my365.dmu.ac.uk",
        commonName="Bob",
        countryName="UK",
        organizationName="DMU",
        serialNumber=1002,
        validityEndInSeconds=10*365*24*60*60,
        CERT_DESTINATION=f"{cwd}/project/bob/certificate.crt",
        sk=skCA,
        pk=pkB
        ) # Generate certificate for Bob, signed by CA
    print("\n-- DIGITAL CERTIFICATE GENERATION [COMPLETE] --\n")


skA, pkA = key_init("alice") # Create keys for Alice
skB, pkB = key_init("bob") # Create keys for Bob
ca_init(pkA, pkB) # Certificate generation