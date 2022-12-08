# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0
import argparse
import socket
import sys
import json
import urllib.request


class OrdinaryStream:
    # Client
    def __init__(self, conn_timeout=30):
        self.conn_timeout = conn_timeout

    def connect(self, port):
        # Connect to the remote endpoint PORT specified.
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.conn_timeout)
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

                query = from_client.recv(1024).decode()
                print("Message received from python client: " + query)

                # Call the external URL
                # for our scenario we will download list of published ip ranges and return list of S3 ranges for porvided region.
                # response = get_s3_ip_by_region(query)

                # Send back the response                 
                # from_client.send(str(response).encode())

                # from_client.close()
                return query, from_client
            except Exception as ex:
                print(ex)


def server_handler(args):
    server = VsockListener()
    server.bind(args.port)
    print("Started listening to port : ", str(args.port))
    (message, vsock_client) = server.recv_data()

    ordinary_client = OrdinaryStream()
    ordinary_client.connect(args.serverPort)
    server_response = ordinary_client.send_data(message)
    vsock_client.send(server_response.encode())
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
