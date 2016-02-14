#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import argparse

def newCA (name, template='ca-template', expire='363'):
    target_directory = 'ca-{name}'.format(name=name)
    try:
        #shutil.copytree(template, target_directory)
        os.mkdir(target_directory)
    except Error as err:
        print("Could not create directory", err)
        sys.exit(1)

    # target_directory is our base
    os.chdir(target_directory)

    # file paths
    ca_config_file = 'openssl-ca.cnf'
    ca_cacert_pem = 'cacert.pem'

    # write configs
    f = open(ca_config_file, 'a')
    f.write(getOpenSSLCAConf())
    f.close()

    # openssl req -x509 -config openssl-ca.cnf -newkey rsa:4096 -sha256 -nodes -out cacert.pem -outform PEM
    cmd_new_cakey = ['openssl', 'req', '-x509', '-config', ca_config_file, '-newkey', 'rsa:4096', '-sha256', '-nodes', '-out', ca_cacert_pem, '-outform', 'PEM']
    proc_new_cakey = subprocess.run(cmd_new_cakey)

    # openssl x509 -in cacert.pem -text -noout
    cmd_out_cakey = ['openssl', 'x509', '-in', ca_cacert_pem, '-text', '-noout']
    proc_out_cakey = subprocess.run(cmd_out_cakey)

    # openssl x509 -purpose -in cacert.pem -inform PEM
    cmd_purpose_cakey = ['openssl', 'x509', '-purpose', '-in', ca_cacert_pem, '-inform', 'PEM']
    subprocess.run(cmd_purpose_cakey)

def newCert(name):

    # target_directory is our base
    target_directory = 'ca-{name}'.format(name=name)
    os.chdir(target_directory)

    # file paths
    server_cert_req_conf = 'openssl-server.cnf'
    ca_config_file = 'openssl-ca.cnf'
    ca_cacert_pem = 'cacert.pem'
    server_cert_req = 'servercert.csr'
    server_cert_pem = 'servercert.pem'
    server_cert_index_file = 'index.txt'
    server_cert_serial_file = 'serial.txt'

    # delete old conf
    try:
        os.remove(server_cert_req_conf)
    except OSError as err:
        print("No existing config to remove", err)

    # write config
    f = open(server_cert_req_conf, 'a')
    f.write(getOpenSSLServerConf())
    f.close()

    # openssl req -config openssl-server.cnf -newkey rsa:2048 -sha256 -nodes -out servercert.csr -outform PEM
    cmd_cert_req = ['openssl', 'req', '-config', server_cert_req_conf, '-newkey', 'rsa:2048', '-sha256', '-nodes', '-out', server_cert_req, '-outform', 'PEM']
    print("\n#### REQUEST ####\n" + " ".join(cmd_cert_req))
    proc_server_cert_req = subprocess.run(cmd_cert_req)

    # openssl req -text -noout -verify -in servercert.csr
    cmd_out_server_cert_req = ['openssl', 'req', '-text', '-noout', '-verify', '-in', server_cert_req]
    print("\n#### REQUEST CHECK ####\n" + " ".join(cmd_out_server_cert_req))
    subprocess.run(cmd_out_server_cert_req)

    # make sure serial file exists
    if not os.path.exists(server_cert_serial_file):
        open(server_cert_serial_file, 'a').close()
        serial_file = open(server_cert_serial_file, 'a')
        serial_file.write('01')
        serial_file.close()

    # make sure index file exists
    if not os.path.exists(server_cert_index_file):
        index_file = open(server_cert_index_file, 'a')
        index_file.write('01')
        index_file.close()

    # sign req
    # $ openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out servercert.pem -infiles servercert.csr
    cmd_sign_server_req = ['openssl', 'ca', '-config', ca_config_file, '-policy',
     'signing_policy', '-extensions', 'signing_req', '-out', server_cert_pem, '-infiles', server_cert_req]
    print("\n#### REQUEST SIGN ####\n" + " ".join(cmd_sign_server_req))
    subprocess.run(cmd_sign_server_req)

    # inspect cert
    # openssl x509 -in servercert.pem -text -noout
    cmd_out_server_cert = ['openssl', 'x509', '-in', server_cert_pem, '-text', '-noout']
    print("\n#### REQUEST CERT INSPECT ####\n" + " ".join(cmd_out_server_cert))
    subprocess.run(cmd_out_server_cert)


def argument_parser():
    config = argparse.ArgumentParser ('Quick\'n Dirty CA for dev\'n what not.')
    config.add_argument('-ca', '--createca', action="store_true", help="createca, deleteca, createcert")
    config.add_argument('-cert', '--createcert', action="store_true", help="createca, deleteca, createcert")
    config.add_argument('name', type=str, help="CA Name")
    return config.parse_args()

def getOpenSSLCAConf():
    return """
    HOME            = .
    RANDFILE        = $ENV::HOME/.rnd

    ####################################################################
    [ ca ]
    default_ca  = CA_default        # The default ca section

    [ CA_default ]

    base_dir    = .
    certificate = $base_dir/cacert.pem  # The CA certifcate
    private_key = $base_dir/cakey.pem   # The CA private key
    new_certs_dir   = $base_dir     # Location for new certs after signing
    database    = $base_dir/index.txt   # Database index file
    serial      = $base_dir/serial.txt  # The current serial number

    unique_subject  = no            # Set to 'no' to allow creation of
                    # several certificates with same subject.


    default_days    = 1000          # how long to certify for
    default_crl_days= 30            # how long before next CRL
    default_md  = sha256        # use public key default MD
    preserve    = no            # keep passed DN ordering

    x509_extensions = ca_extensions     # The extensions to add to the cert

    email_in_dn = no            # Don't concat the email in the DN
    copy_extensions = copy          # Required to copy SANs from CSR to cert


    ####################################################################
    [ req ]
    default_bits        = 4096
    default_keyfile     = cakey.pem
    distinguished_name  = ca_distinguished_name
    x509_extensions     = ca_extensions
    string_mask         = utf8only

    ####################################################################
    [ ca_distinguished_name ]
    countryName         = Country Name (2 letter code)
    countryName_default     = US

    stateOrProvinceName     = State or Province Name (full name)
    stateOrProvinceName_default = Maryland

    localityName            = Locality Name (eg, city)
    localityName_default        = Baltimore

    organizationName            = Organization Name (eg, company)
    organizationName_default    = Test CA, Limited

    organizationalUnitName  = Organizational Unit (eg, division)
    organizationalUnitName_default  = Server Research Department

    commonName          = Common Name (e.g. server FQDN or YOUR name)
    commonName_default      = Test CA

    emailAddress            = Email Address
    emailAddress_default        = test@example.com

    ####################################################################
    [ ca_extensions ]

    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid:always, issuer
    basicConstraints = critical, CA:true
    keyUsage = keyCertSign, cRLSign

    ####################################################################
    [ signing_policy ]
    countryName     = optional
    stateOrProvinceName = optional
    localityName        = optional
    organizationName    = optional
    organizationalUnitName  = optional
    commonName      = supplied
    emailAddress        = optional

    ####################################################################
    [ signing_req ]
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid,issuer

    basicConstraints = CA:FALSE
    keyUsage = digitalSignature, keyEncipherment
    """

def getOpenSSLServerConf():
    return """
    HOME            = .
    RANDFILE        = $ENV::HOME/.rnd

    ####################################################################
    [ req ]
    default_bits        = 2048
    default_keyfile     = serverkey.pem
    distinguished_name  = server_distinguished_name
    req_extensions      = server_req_extensions
    string_mask         = utf8only

    ####################################################################
    [ server_distinguished_name ]
    countryName         = Country Name (2 letter code)
    countryName_default     = US

    stateOrProvinceName     = State or Province Name (full name)
    stateOrProvinceName_default = MD

    localityName            = Locality Name (eg, city)
    localityName_default        = Baltimore

    organizationName            = Organization Name (eg, company)
    organizationName_default    = Test CA, Limited

    commonName          = Common Name (e.g. server FQDN or YOUR name)
    commonName_default      = Test CA

    emailAddress            = Email Address
    emailAddress_default        = test@example.com

    ####################################################################
    [ server_req_extensions ]

    subjectKeyIdentifier        = hash
    basicConstraints        = CA:FALSE
    keyUsage            = digitalSignature, keyEncipherment
    subjectAltName          = @alternate_names
    nsComment           = "OpenSSL Generated Certificate"

    ####################################################################
    [ alternate_names ]

    DNS.1       = localhost
    DNS.2       = www.example.com
    DNS.3       = mail.example.com
    DNS.4       = ftp.example.com
    """

def main():
    config = argument_parser()
    if config.createca:
        newCA(config.name)
    if config.createcert:
        newCert(config.name)
    exit()

def exit():
    sys.exit(0)

if __name__== "__main__":
    main()
