import network
from io import BytesIO


def test_gen_msg():
    # generate version payload
    payload = network.gen_version(timestamp=0, nonce=b'\x00' * 8)

    # test
    payload_bytes = network.serialize_version(payload)
    print(payload_bytes.hex())
    assert payload_bytes.hex() == '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d00000000000000000f2f626974636f696e70793a302e312f0000000000'

    # generate message
    msg = network.gen_msg('version', payload_bytes, testnet=True)

    # send(msg) # // serialize
    # read() # // read and parse


def test_parse_msg():
    msg_bytes = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
    msg = network.parse_msg(BytesIO(msg_bytes))
    assert msg['command'] == b'verack'
    assert msg['payload_bytes'] == b''

    msg_bytes = bytes.fromhex(
        'f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
    msg = network.parse_msg(BytesIO(msg_bytes))
    assert msg['command'] == b'version'
    assert msg['payload_bytes'] == msg_bytes[24:]


def test_serialize_msg():
    msg_bytes = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
    msg = network.parse_msg(BytesIO(msg_bytes))
    assert network.serialize_msg(msg) == msg_bytes

    msg_bytes = bytes.fromhex(
        'f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
    msg = network.parse_msg(BytesIO(msg_bytes))
    assert network.serialize_msg(msg) == msg_bytes


def test_serialize_getheaders():
    block_hex = '0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3'
    payload = network.gen_getheaders(start_block=bytes.fromhex(block_hex))
    payload_bytes = network.serialize_getheaders(payload)
    assert payload_bytes.hex() == '7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000'


def test_parse_headers():
    hex_msg = '0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600'
    stream = BytesIO(bytes.fromhex(hex_msg))
    payload = network.parse_headers(stream)
    assert len(payload['blocks']) == 2
    for b in payload['blocks']:
        print(b)


def test_serialize_getdata():
    hex_msg = '020300000030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000030000001049847939585b0652fba793661c361223446b6fc41089b8be00000000000000'
    payload = network.gen_getdata()
    block1 = bytes.fromhex('00000000000000cac712b726e4326e596170574c01a16001692510c44025eb30')
    payload['data'].append((network.FILTERED_BLOCK_DATA_TYPE, block1))
    block2 = bytes.fromhex('00000000000000beb88910c46f6b442312361c6693a7fb52065b583979844910')
    payload['data'].append((network.FILTERED_BLOCK_DATA_TYPE, block2))
    assert network.serialize_getdata(payload).hex() == hex_msg


test_gen_msg()
test_parse_msg()
test_serialize_msg()
test_serialize_getheaders()
test_parse_headers()

test_serialize_getdata()
