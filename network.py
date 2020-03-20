import util
import block
import time
import merkletree as mt
import bloomfilter
from random import randint

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4

MAINNET_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_MAGIC = b'\x0b\x11\x09\x07'


def gen_msg(command, payload_bytes, testnet=False):
    msg = {}
    if testnet:
        msg['magic'] = TESTNET_MAGIC
    else:
        msg['magic'] = MAINNET_MAGIC
    msg['command'] = command
    msg['payload_bytes'] = payload_bytes

    return msg


def print_msg(msg):
    return '{}: {}'.format(
        msg['command'].decode('ascii'),
        msg['payload_bytes'].hex()
    )


def parse_msg(s, testnet=False):
    """Takes a stream and creates a NetworkEnvelope"""
    # check the network magic
    magic = s.read(4)
    if magic == b'':
        raise RuntimeError('Connection reset!')
    if testnet:
        expected_magic = TESTNET_MAGIC
    else:
        expected_magic = MAINNET_MAGIC
    if magic != expected_magic:
        raise RuntimeError('magic is not right {} vs {}'.format(magic.hex(), expected_magic.hex()))
    # command 12 bytes
    command = s.read(12)
    # strip the trailing 0's
    command = command.strip(b'\x00')
    # payload length 4 bytes, little endian
    payload_length = util.little_endian_to_int(s.read(4))
    # checksum 4 bytes, first four of hash256 of payload
    checksum = s.read(4)
    # payload is of length payload_length
    payload_bytes = s.read(payload_length)
    # verify checksum
    calculated_checksum = util.hash256(payload_bytes)[:4]
    if calculated_checksum != checksum:
        raise RuntimeError('checksum does not match')

    # return msg
    return {
        "magic": magic,
        "command": command,
        "payload_bytes": payload_bytes
    }


def serialize_msg(msg):
    """Returns the byte serialization of the entire network message"""
    # add the network magic
    result = msg['magic']
    # command 12 bytes
    # fill with 0's
    result += msg['command'] + b'\x00' * (12 - len(msg['command']))
    # payload length 4 bytes, little endian
    result += util.int_to_little_endian(len(msg['payload_bytes']), 4)
    # checksum 4 bytes, first four of hash256 of payload
    result += util.hash256(msg['payload_bytes'])[:4]
    # payload
    result += msg['payload_bytes']
    return result


def gen_version(
        version=70015,
        services=0,
        timestamp=None,
        receiver_services=0,
        receiver_ip=b'\x00\x00\x00\x00',
        receiver_port=8333,
        sender_services=0,
        sender_ip=b'\x00\x00\x00\x00',
        sender_port=8333,
        nonce=None,
        user_agent=b'/bitcoinpy:0.1/',
        latest_block=0,
        relay=False):
    payload = {}
    payload['version'] = version
    payload['services'] = services
    if timestamp is None:
        payload['timestamp'] = int(time.time())
    else:
        payload['timestamp'] = timestamp
    payload['receiver_services'] = receiver_services
    payload['receiver_ip'] = receiver_ip
    payload['receiver_port'] = receiver_port
    payload['sender_services'] = sender_services
    payload['sender_ip'] = sender_ip
    payload['sender_port'] = sender_port
    if nonce is None:
        payload['nonce'] = util.int_to_little_endian(randint(0, 2 ** 64), 8)
    else:
        payload['nonce'] = nonce
    payload['user_agent'] = user_agent
    payload['latest_block'] = latest_block
    payload['relay'] = relay

    return payload


def parse_version(s):
    return None


def serialize_version(payload):
    """Serialize this message to send over the network"""
    # version is 4 bytes little endian
    result = util.int_to_little_endian(payload['version'], 4)
    # services is 8 bytes little endian
    result += util.int_to_little_endian(payload['services'], 8)
    # timestamp is 8 bytes little endian
    result += util.int_to_little_endian(payload['timestamp'], 8)
    # receiver services is 8 bytes little endian
    result += util.int_to_little_endian(payload['receiver_services'], 8)
    # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
    result += b'\x00' * 10 + b'\xff\xff' + payload['receiver_ip']
    # receiver port is 2 bytes, big endian
    result += payload['receiver_port'].to_bytes(2, 'big')
    # sender services is 8 bytes little endian
    result += util.int_to_little_endian(payload['sender_services'], 8)
    # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
    result += b'\x00' * 10 + b'\xff\xff' + payload['sender_ip']
    # sender port is 2 bytes, big endian
    result += payload['sender_port'].to_bytes(2, 'big')
    # nonce should be 8 bytes
    result += payload['nonce']
    # useragent is a variable string, so varint first
    result += util.encode_varint(len(payload['user_agent']))
    result += payload['user_agent']
    # latest block is 4 bytes little endian
    result += util.int_to_little_endian(payload['latest_block'], 4)
    # relay is 00 if false, 01 if true
    if payload['relay']:
        result += b'\x01'
    else:
        result += b'\x00'

    return result


# command = b'verack'
def gen_verack():
    return b''


def parse_verack(s):
    return b''


def serialize_verack(payload):
    return payload


# command = b'ping'
def gen_ping(nonce):
    return nonce


def parse_ping(s):
    nonce = s.read(8)
    return nonce


def serialize_ping(payload):
    return payload


# command = b'pong'
def gen_pong(nonce):
    return nonce


def parse_pong(s):
    nonce = s.read(8)
    return nonce


def serialize_pong(payload):
    return payload


# command = b'getheaders'
def gen_getheaders(version=70015, num_hashes=1, start_block=None, end_block=None):
    if start_block is None:
        raise RuntimeError('a start block is required')
    if end_block is None:
        end_block = b'\x00' * 32
    return {
        'version': version,
        'num_hashes': num_hashes,
        'start_block': start_block,
        'end_block': end_block
    }


def parse_getheaders(s):
    raise NotImplementedError


def serialize_getheaders(payload):
    """Serialize this message to send over the network"""
    # protocol version is 4 bytes little-endian
    result = util.int_to_little_endian(payload['version'], 4)
    # number of hashes is a varint
    result += util.encode_varint(payload['num_hashes'])
    # start block is in little-endian
    result += payload['start_block'][::-1]
    # end block is also in little-endian
    result += payload['end_block'][::-1]
    return result


# command = b'headers'
def gen_headers(blocks):
    return {
        'blocks': blocks
    }


def parse_headers(s):
    # number of headers is in a varint
    num_headers = util.read_varint(s)
    # initialize the blocks array
    blocks = []
    # loop through number of headers times
    for _ in range(num_headers):
        # add a block to the blocks array by parsing the stream
        blocks.append(block.parse(s))
        # read the next varint (num_txs)
        num_txs = util.read_varint(s)
        # num_txs should be 0 or raise a RuntimeError
        if num_txs != 0:
            raise RuntimeError('number of txs not 0')

    return {
        'blocks': blocks
    }


def serialize_header(payload):
    raise NotImplementedError


# command = b'getdata'
def gen_getdata():
    return {
        'data': []
    }


def parse_getdata(s):
    return


def serialize_getdata(payload):
    # start with the number of items as a varint
    result = util.encode_varint(len(payload['data']))
    # loop through each tuple (data_type, identifier) in self.data
    for data_type, identifier in payload['data']:
        # data type is 4 bytes Little-Endian
        result += util.int_to_little_endian(data_type, 4)
        # identifier needs to be in Little-Endian
        result += identifier[::-1]
    return result


payload_parsers = {
    b'verack': parse_verack
}


# command = b'merkleblock'
def gen_merkleblock(version, prev_block_hash, merkle_root, timestamp, bits, nonce, total, hashes, flags):
    return {
        'version': version,
        'prev_block_hash': prev_block_hash,
        'merkle_root': merkle_root,
        'timestamp': timestamp,
        'bits': bits,
        'nonce': nonce,
        'total': total,
        'hashes': hashes,
        'flags': flags
    }


def parse_merkleblock(s):
    """Takes a byte stream and parses a merkle block. Returns a Merkle Block object"""
    # version - 4 bytes, Little-Endian integer
    version = util.little_endian_to_int(s.read(4))
    # prev_block - 32 bytes, Little-Endian (use [::-1])
    prev_block_hash = s.read(32)[::-1]
    # merkle_root - 32 bytes, Little-Endian (use [::-1])
    merkle_root = s.read(32)[::-1]
    # timestamp - 4 bytes, Little-Endian integer
    timestamp = util.little_endian_to_int(s.read(4))
    # bits - 4 bytes
    bits = s.read(4)
    # nonce - 4 bytes
    nonce = s.read(4)
    # total transactions in block - 4 bytes, Little-Endian integer
    total = util.little_endian_to_int(s.read(4))
    # number of transaction hashes - varint
    num_hashes = util.read_varint(s)
    # each transaction is 32 bytes, Little-Endian
    hashes = []
    for _ in range(num_hashes):
        hashes.append(s.read(32)[::-1])
    # length of flags field - varint
    flags_length = util.read_varint(s)
    # read the flags field
    flags = s.read(flags_length)

    return {
        'version': version,
        'prev_block_hash': prev_block_hash,
        'merkle_root': merkle_root,
        'timestamp': timestamp,
        'bits': bits,
        'nonce': nonce,
        'total': total,
        'hashes': hashes,
        'flags': flags
    }


def is_valid_merkleblock(merkleblock):
    """Verifies whether the merkle tree information validates to the merkle root"""
    # convert the flags field to a bit field
    flag_bits = bloomfilter.bytes_to_bit_field(merkleblock['flags'])
    # reverse self.hashes for the merkle root calculation
    hashes = [h[::-1] for h in merkleblock['hashes']]
    # initialize the merkle tree
    merkle_tree = mt.MerkleTree(merkleblock['total'])
    # populate the tree with flag bits and hashes
    merkle_tree.populate_tree(flag_bits, hashes)
    # check if the computed root reversed is the same as the merkle root
    return merkle_tree.root()[::-1] == merkleblock['merkle_root']


def serialize_filterload(payload, flag=1):
    """Return the filterload message"""
    # start the payload with the size of the filter in bytes
    result = util.encode_varint(payload['size'])
    # next add the bit field using self.filter_bytes()
    result += bloomfilter.bit_field_to_bytes(payload['bit_field'])
    # function count is 4 bytes little endian
    result += util.int_to_little_endian(payload['function_count'], 4)
    # tweak is 4 bytes little endian
    result += util.int_to_little_endian(payload['tweak'], 4)
    # flag is 1 byte little endian
    result += util.int_to_little_endian(flag, 1)
    return result
