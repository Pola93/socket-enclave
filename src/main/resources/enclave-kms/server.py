# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0
import argparse
import socket
import sys
import base64
import json
import urllib.request
import subprocess
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

KMS_PROXY_PORT="8000"

class OrdinaryStream:
    # Client
    def __init__(self, conn_timeout=30):
        self.conn_timeout = conn_timeout

    def connect(self, port):
        # Connect to the remote endpoint PORT specified.
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.conn_timeout)
            print("Send from python client to java server on port: ", port)
            self.sock.connect(("127.0.0.1", port))
        except ConnectionResetError as e:
            print("Caught error ", str(e.strerror), " ", str(e.errno))

    def send_data(self, data):
        # Send data to the remote endpoint
        print(str(self.sock))
        # encode data before sending
        self.sock.send(data.encode())
        print("Data passed to java server ", data)
        # receiving responce back
        data = self.sock.recv(1024).decode()  # receive response
        print('Received from java server: ' + data)  # show in terminal
        self.sock.close()
        return data


# Running server you have pass port the server  will listen to. For Example:
# $ python3 /app/server.py server 5005
class VsockListener:
    # Server
    def __init__(self, conn_backlog=128):
        self.conn_backlog = conn_backlog

    def bind(self, port):
        # Bind and listen for connections on the specified port
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)

    def recv_data(self):
        # Receive data from a remote endpoint
        while True:
            try:
                print("Let's accept stuff")
                (from_client, (remote_cid, remote_port)) = self.sock.accept()
                print("Connection from " + str(from_client) + str(remote_cid) + str(remote_port))

                query = from_client.recv(8192)
                print("Message received from python client: " + query.decode())

                # Call the external URL
                # for our scenario we will download list of published ip ranges and return list of S3 ranges for porvided region.
                # response = get_s3_ip_by_region(query)

                # Send back the response                 
                # from_client.send(str(response).encode())

                # from_client.close()
                return query, from_client
            except Exception as ex:
                print(ex)


def get_plaintext(credentials):
    access = credentials['access_key_id']
    secret = credentials['secret_access_key']
    token = credentials['token']
    ciphertext = credentials['ciphertext']
    enc_sk = credentials['enc_sk']
    region = credentials['region']
    creds = decrypt_message(access, secret, token, ciphertext, enc_sk, region)
    return creds

def decrypt_message(access, secret, token, ciphertext, enc_sk, region):
    print("Python Enclave Received encrypted message: " + ciphertext)
    print("Python Enclave Received encrypted sk: " + enc_sk)
    proc = subprocess.Popen(
        [
            "/opt/app/kmstool_enclave_cli",
            "--region", region,
            "--proxy-port", KMS_PROXY_PORT,
            "--aws-access-key-id", access,
            "--aws-secret-access-key", secret,
            "--aws-session-token", token,
            "--ciphertext", enc_sk.encode(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    ret = proc.communicate()

    if ret[0]:
        b64text = proc.communicate()[0].decode()
        sk = base64.b64decode(b64text)

        pk = load_pem_private_key(sk, default_backend())
        decrypted_message = pk.decrypt(bytes.fromhex(ciphertext), padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

        return decrypted_message.decode()
    else:
        return "KMS Error. Decryption Failed. ->" + ret[1].decode()


def server_handler(args):
    print("Python server_handler")
    server = VsockListener()
    server.bind(args.port)
    print("Started listening to port : ", str(args.port))
    (request_decryption, vsock_client) = server.recv_data()

    plain_text = get_plaintext(json.loads(request_decryption.decode()))
    print("Decrypted Message " + plain_text)

    # ordinary_client = OrdinaryStream()
    # ordinary_client.connect(args.serverPort)
    # server_response = ordinary_client.send_data(plain_text)
    vsock_client.send(plain_text.encode())
    vsock_client.close()


def main():
    parser = argparse.ArgumentParser(prog='vsock-sample')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")

    server_parser = subparsers.add_parser("server", description="Server",
                                          help="Listen on a given port.")
    server_parser.add_argument("port", type=int, help="The local port to listen on.")
    server_parser.add_argument("serverPort", type=int, help="The local port to java server.")
    server_parser.set_defaults(func=server_handler)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
