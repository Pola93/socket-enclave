# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

# !/usr/local/bin/env python3
import boto3
import argparse
import socket
import sys
import requests
import rsa


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
        self.sock.send(data.encode())
        print("Data Sent enclave server", data)
        # receiving responce back
        resp = self.sock.recv(1024).decode()  # receive response
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

    public_key = rsa.PublicKey.load_pkcs1(public_key_blob)
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    print("Encrypted: " + encrypted_message.hex())


def client_handler(args):
    server = OrdinarySockListener()
    server.bind(args.serverPort)
    print("Started ordinary listening to port : ", str(args.serverPort))
    (message, ordinary_client) = server.recv_data()

    encrypt_message(message)

    # creat socket tream to the Nitro Enclave
    client = VsockStream()
    endpoint = (args.cid, args.port)
    print("Endpoint Arguments ", str(args.cid), str(args.port))
    client.connect(endpoint)
    # Send provided query and handle the response
    enclave_response = client.send_data(message)
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
