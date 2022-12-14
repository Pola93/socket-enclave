# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

# !/usr/local/bin/env python3
import boto3
import argparse
import socket
import json
import sys
import requests
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class OrdinarySockListener:
    # Server
    def __init__(self, conn_backlog=128):
        self.conn_backlog = conn_backlog

    def bind(self, port):
        # Bind and listen for connections on the specified port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(self.conn_backlog)

    def recv_data(self):
        # Receive data from a remote endpoint
        while True:
            try:
                print("Let's accept stuff")
                (from_client, remote_adr) = self.sock.accept()
                print("Connection from " + str(from_client) + str(remote_adr))

                query = from_client.recv(1024).decode()
                print("Message received from java client: " + query)
                # Send back the response
                # from_client.send(str(response).encode())
                #
                # from_client.close()
                # print("Client call closed")
                return query, from_client
            except Exception as ex:
                print(ex)


# To call the client, you have to pass: CID of the enclave, Port for remote server,
# and Query string that will be processed in the Nitro Enclave. For Example:
# $ python3 client.py client 19 5005 "us-east-1"
class VsockStream:
    # Client
    def __init__(self, conn_timeout=30):
        self.conn_timeout = conn_timeout

    def connect(self, endpoint):
        # Connect to the remote endpoint with CID and PORT specified.
        try:
            self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            self.sock.settimeout(self.conn_timeout)
            self.sock.connect(endpoint)
        except ConnectionResetError as e:
            print("Caught error ", str(e.strerror), " ", str(e.errno))

    def send_data(self, data):
        # Send data to the remote endpoint
        print(str(self.sock))
        # encode data before sending
        self.sock.send(data)
        print("Data Sent enclave server: ", data.decode())
        # receiving responce back
        resp = self.sock.recv(8192).decode()  # receive response
        print("Received from enclave server: ", resp)  # show in terminal
        self.sock.close()
        return resp

def get_identity_document():
    """
    Get identity document for current EC2 Host
    """
    r = requests.get(
        "http://169.254.169.254/latest/dynamic/instance-identity/document")
    return r


def get_region(identity):
    """
    Get account of current instance identity
    """
    region = identity.json()["region"]
    return region


def get_account(identity):
    """
    Get account of current instance identity
    """
    account = identity.json()["accountId"]
    return account

def set_identity():
    identity = get_identity_document()
    region = get_region(identity)
    account = get_account(identity)
    return region, account

REGION, ACCOUNT = set_identity()

def prepare_server_request(ciphertext, enc_sk):
    """
    Get the AWS credential from EC2 instance metadata
    """
    r = requests.get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    instance_profile_name = r.text

    r = requests.get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/%s" %
        instance_profile_name)
    response = r.json()

    print(ciphertext)

    credential = {
        'access_key_id': response['AccessKeyId'],
        'secret_access_key': response['SecretAccessKey'],
        'token': response['Token'],
        'region': REGION,
        'ciphertext': ciphertext.decode(),
        'enc_sk': enc_sk.decode()
    }

    return credential

def encrypt_message(message):
    kms = boto3.client("kms", region_name=REGION)
    data_key_pair = kms.generate_data_key_pair_without_plaintext(
        KeyId='8b739852-ed54-4b0c-bbf2-334c3232611d',
        KeyPairSpec='RSA_4096'
    )
    private_key_blob = data_key_pair["PrivateKeyCiphertextBlob"]
    public_key_blob = data_key_pair["PublicKey"]

    print("message plain " + message)
    print("Private Key " + private_key_blob.hex())
    print("Public Key " + public_key_blob.hex())
    print("Public Key base64 " + base64.b64encode(public_key_blob).decode())

    # the_blob = bytes.fromhex("30820222300d06092a864886f70d01010105000382020f003082020a0282020100e3940b83c55108362e1b8e5727892278724c14d95561a347d127977a9b6d8abf7e8bfff2feaad28d9edd961f927f1bf069b0f29905a5ab2e8e731fbc3c8159f301439b909233f5be430956ec24bc5a0895a070555b2613e89c9c4659584c2280599fd68266f1d1ddacf7e93fe6080a97f9e3ec5b36514a0a7661f928310bd7e4a014df62151355ea1635fbcc2c60f5c91fe20b426a7603c95827d17530977c4161e8543017cc875b91b47c01f4024d12b7886280eab7f5429318f6cd70211249ea14ee0723d0bc50c527a9629adefcd716383173e40bcebf627c7926d7f9324dcaeadc543ae9ac3cb3f5494b93b0038eb73d12f630bcd98b4d90e1b36ad0f13936ffaf6bb4a889f64c4985940f12659afaf51cb8058054a0949e594385b14a8e4a86fea3f797b5788d7cde950fed682d50742dec5c01eb64f5b54d0c640a487c2eacba26f59f50aae00b53b1092816b20a31b7262c967a858b150f34e6d0c2ba5bbcf2fa567243c81c44e70e1f7f67abe3cee633a2950ca10c6684f44c9ed3ebfd42d3bbde526285a9b9f460f589dce1bfd440fbad59275e25c1858e1a62983d0ae7d466b0b18b2d49c10bbfb9793448222491346488de44f94d5ff7848f99ae629267fae623b6bc5109cd17eb3cd79c41eacc27493cdafc524dc23ae9c128990266d2b05bc33e168d4239e09aec528c5749fa7371b9846cb3d097e901787fbf0203010001")

    pem_public_key = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(public_key_blob).decode() + "\n-----END PUBLIC KEY-----"
    pk = load_pem_public_key(pem_public_key.encode("ascii"), default_backend())
    encrypted_message = pk.encrypt(message.encode(), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    print("Public Key pem " + pem_public_key)

    print("Encrypted: " + encrypted_message.decode())

    return encrypted_message, private_key_blob


def client_handler(args):
    print("Start Python Client")
    server = OrdinarySockListener()
    server.bind(args.serverPort)
    print("Started ordinary listening to port : ", str(args.serverPort))
    (message, ordinary_client) = server.recv_data()

    (encrypted_message, private_key_blob) = encrypt_message(message)
    request_decryption = prepare_server_request(encrypted_message, private_key_blob)
    print("request_decryption: " + json.dumps(request_decryption))

    # creat socket tream to the Nitro Enclave
    client = VsockStream()
    endpoint = (args.cid, args.port)
    print("Endpoint Arguments ", str(args.cid), str(args.port))
    client.connect(endpoint)
    # Send provided query and handle the response
    enclave_response = client.send_data(str.encode(json.dumps(request_decryption)))
    ordinary_client.send(enclave_response.encode())
    ordinary_client.close()

def main():
    # Handling of input parameters
    parser = argparse.ArgumentParser(prog='vsock-sample')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")

    client_parser = subparsers.add_parser("client", description="Client",
                                          help="Connect to a given cid and port.")
    client_parser.add_argument("cid", type=int, help="The remote endpoint CID.")
    client_parser.add_argument("port", type=int, help="The remote endpoint port.")
    client_parser.add_argument("query", type=str, help="Query to send.")
    client_parser.add_argument("serverPort", type=int, help="The Server receiving on ordinary port port.")

    # Assign handler function
    client_parser.set_defaults(func=client_handler)

    # Argument count validation
    if len(sys.argv) < 3:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
