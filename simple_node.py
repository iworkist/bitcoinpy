import socket
import network


def handshake(sock, stream, testnet=False):
    """Do a handshake with the other node.
    Handshake is sending a version message and getting a verack back."""
    # create a version payload
    payload = network.gen_version()

    # generate msg
    # needs to change to generate message dynamically with its type.
    msg = network.gen_msg(b'version', network.serialize_version(payload), True)
    msg_bytes = network.serialize_msg(msg)

    # send msg
    sock.sendall(msg_bytes)

    # wait for a verack message
    msg = wait_for(sock, stream, {b'verack'}, True)
    payload = network.payload_parsers[b'verack'](msg['payload_bytes'])
    print(payload)


def wait_for(sock, stream, commands, testnet=False):
    """Wait for one of the messages in the list"""
    # initialize the command we have, which should be None
    command = None
    # loop until the command is in the commands we want
    while command not in commands:
        # get the next network message
        msg = network.parse_msg(stream, testnet)
        # set the command to be evaluated
        command = msg['command']
        # we know how to respond to version and ping, handle that here
        if command == b'version':
            # send verack
            msg_bytes = network.serialize_verack(network.gen_verack())
            sock.sendall(msg_bytes)
        elif command == b'ping':
            # send pong
            msg_bytes = network.serialize_verack(network.gen_pong(msg['payload_bytes']))
            sock.sendall(msg_bytes)

    return msg


def connect(host, port=None, testnet=False):
    if port is None:
        if testnet:
            port = 18333
        else:
            port = 8333
    # connect to socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # create a stream that we can use with the rest of the library
    r_file = sock.makefile('rb', None)
    # w_file = sock.makefile('wb', None)
    return sock, r_file


sock, r_file = connect('testnet.programmingbitcoin.com', testnet=True)
handshake(sock, r_file, testnet=True)
