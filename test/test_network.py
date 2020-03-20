import network
import bloomfilter
import util
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


def test_parse_merkleblock():
    hex_merkle_block = '00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635'
    mb = network.parse_merkleblock(BytesIO(bytes.fromhex(hex_merkle_block)))
    assert mb['version'] == 0x20000000
    merkle_root_hex = 'ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4'
    merkle_root = bytes.fromhex(merkle_root_hex)[::-1]
    assert mb['merkle_root'] == merkle_root
    prev_block_hash_hex = 'df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000'
    prev_block_hash = bytes.fromhex(prev_block_hash_hex)[::-1]
    assert mb['prev_block_hash'] == prev_block_hash
    timestamp = util.little_endian_to_int(bytes.fromhex('dc7c835b'))
    assert mb['timestamp'] == timestamp
    bits = bytes.fromhex('67d8001a')
    assert mb['bits'] == bits
    nonce = bytes.fromhex('c157e670')
    assert mb['nonce'] == nonce
    total = util.little_endian_to_int(bytes.fromhex('bf0d0000'))
    assert mb['total'] == total
    hex_hashes = [
        'ba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a',
        '7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d',
        '34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2',
        '158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cba',
        'ee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763ce',
        'f8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097',
        'c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d',
        '6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543',
        'd1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274c',
        'dfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb62261',
    ]
    hashes = [bytes.fromhex(h)[::-1] for h in hex_hashes]
    mb['hashes'] == hashes
    flags = bytes.fromhex('b55635')
    assert mb['flags'] == flags


def test_is_valid_merkleblock():
    hex_merkle_block = '00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635'
    mb = network.parse_merkleblock(BytesIO(bytes.fromhex(hex_merkle_block)))
    assert network.is_valid_merkleblock(mb) == True


def test_filterload():
    bf = bloomfilter.init(10, 5, 99)
    item = b'Hello World'
    bf = bloomfilter.add(bf, item)
    msg = network.gen_msg(b'filterload', network.serialize_filterload(bf), True)
    msg_bytes = network.serialize_msg(msg)
    msg_bytes_hex = msg_bytes.hex()
    expected = '0000000a080000000140'
    print(msg_bytes_hex)
    print(expected)
    print(expected in msg_bytes_hex)
    assert (expected in msg_bytes_hex) is True

    item = b'Goodbye!'
    bf = bloomfilter.add(bf, item)
    msg = network.gen_msg(b'filterload', network.serialize_filterload(bf), True)
    msg_bytes = network.serialize_msg(msg)
    msg_bytes_hex = msg_bytes.hex()
    expected = '4000600a080000010940'
    assert (expected in msg_bytes_hex) is True


test_parse_merkleblock()
test_is_valid_merkleblock()
test_filterload()

