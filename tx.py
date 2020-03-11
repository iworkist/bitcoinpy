import util
import script
import copy
import requests
import ecc
from io import BytesIO
from logging import getLogger

LOGGER = getLogger(__name__)


def parse_txi(s):
    txi = {
        "txid": 0,  # 32bytes, not hex value.
        "idx": 0,
        "script.len": 0,
        "script": [],
        "seq.no": 0,
        "wits": []
    }
    txi["txid"] = s.read(32)[::-1]  # prev_tx is 32 bytes, little endian // le to be
    txi["idx"] = util.little_endian_to_int(s.read(4))  # prev_index is an integer in 4 bytes, little endian
    txi["script.len"], txi["script"] = script.parse(s)  # parse script
    txi["seq.no"] = util.little_endian_to_int(s.read(4))  # sequence is an integer in 4 bytes, little-endian
    # wits: witness script
    return txi


def parse_txo(s):
    txo = {
        "amount": 0,
        "script.len": 0,
        "script": ""
    }
    # amount is an integer in 8 bytes, little endian (amount = satoshi * 10**8, 1 satoshi = 0.00000001btc)
    txo["amount"] = util.little_endian_to_int(s.read(8))
    txo["script.len"], txo["script"] = script.parse(s)  # lock script
    return txo


def parse_legacy(s):
    tx = {
        "version": 1,
        # "mark": None,
        # "flag": None,
        "txi.count": 0,
        "txis": [],
        "txo.count": 0,
        "txos": [],
        # "wits": None,
        "locktime": 0
    }
    tx["version"] = util.little_endian_to_int(s.read(4))
    tx["txi.count"] = util.read_varint(s)
    for _ in range(tx["txi.count"]):
        tx["txis"].append(parse_txi(s))
    tx["txo.count"] = util.read_varint(s)
    for _ in range(tx["txo.count"]):
        tx["txos"].append(parse_txo(s))
    tx["locktime"] = util.little_endian_to_int(s.read(4))  # locktime is an integer in 4 bytes, little-endian
    return tx


def parse_segwit(s):
    tx = {
        "version": 1,
        "mark": None,
        "flag": None,
        "txi.count": 0,
        "txis": [],
        "txo.count": 0,
        "txos": [],
        # "wits": append to each txi
        "locktime": 0,
        "hash_all": None
    }
    tx["version"] = util.little_endian_to_int(s.read(4))
    tx["mark"] = s.read(1)
    tx["flag"] = s.read(1)
    if tx["mark"] != b"\x00" and tx["flag"] != b"\x01":
        raise RuntimeError('not a segwit transaction {}'.format(tx["flag"]))
    tx["txi.count"] = util.read_varint(s)
    for _ in range(tx["txi.count"]):
        tx["txis"].append(parse_txi(s))
    tx["txo.count"] = util.read_varint(s)
    for _ in range(tx["txo.count"]):
        tx["txos"].append(parse_txo(s))
    # parse witness script
    for txi in tx["txis"]:
        count = util.read_varint(s)
        for _ in range(count):
            length = util.read_varint(s)
            if length == 0:  # ?
                txi["wits"].append(0)
            else:
                txi["wits"].append(s.read(length))
    tx["locktime"] = util.little_endian_to_int(s.read(4))  # locktime is an integer in 4 bytes, little-endian
    return tx


def parse(s):
    temp = s.read(5)
    s.seek(0, 0)
    if temp[4] == 0:  # txi.count can not be zero. so it's a segwit tx.
        return parse_segwit(s)
    else:
        return parse_legacy(s)


def serialize_txi(txi):
    result = txi["txid"][::-1]  # serialize prev_tx, little endian
    result += util.int_to_little_endian(txi["idx"], 4)  # serialize prev_index, 4 bytes, little endian
    result += script.serialize(txi["script"])  # serialize the unlock_script
    result += util.int_to_little_endian(txi["seq.no"], 4)  # serialize sequence, 4 bytes, little endian
    return result


def serialize_txo(txo):
    result = util.int_to_little_endian(txo["amount"], 8)  # serialize amount, 8 bytes, little endian
    result += script.serialize(txo["script"])  # serialize the script_pubkey
    return result


def serialize_legacy(tx):
    result = util.int_to_little_endian(tx["version"], 4)
    result += util.encode_varint(tx["txi.count"])
    for txi in tx["txis"]:
        result += serialize_txi(txi)
    result += util.encode_varint(tx["txo.count"])
    for txo in tx["txos"]:
        result += serialize_txo(txo)
    result += util.int_to_little_endian(tx["locktime"], 4)
    return result


def serialize_segwit(tx):
    result = util.int_to_little_endian(tx["version"], 4)
    result += tx["mark"]
    result += tx["flag"]
    result += util.encode_varint(tx["txi.count"])
    for txi in tx["txis"]:
        result += serialize_txi(txi)
    result += util.encode_varint(tx["txo.count"])
    for txo in tx["txos"]:
        result += serialize_txo(txo)
    for txi in tx["txis"]:
        result += util.int_to_little_endian(len(txi["wits"]), 1)
        for item in txi["wits"]:
            if type(item) == int:
                result += util.int_to_little_endian(item, 1)
            else:
                result += util.encode_varint(len(item)) + item
    result += util.int_to_little_endian(tx["locktime"], 4)
    return result


def serialize(tx):
    if "flag" in tx:
        return serialize_segwit(tx)
    else:
        return serialize_legacy(tx)


def get_txid(tx):
    return util.hash256(serialize_legacy(tx))[::-1]  # return 32bytes, not hex value.
    # return hash256(serialize(tx))[::-1].hex()


def fetch(txid, testnet=False):
    if testnet:
        url = 'http://testnet.programmingbitcoin.com'
    else:
        url = 'http://mainnet.programmingbitcoin.com'
    url = '{}/tx/{}.hex'.format(url, txid.hex())
    response = requests.get(url)
    try:
        raw = bytes.fromhex(response.text.strip())
    except ValueError:
        raise ValueError('unexpected response: {}'.format(response.text))
    tx = parse(BytesIO(raw))
    if get_txid(tx) != txid:
        raise ValueError('not the same id: {} vs {}'.format(get_txid(tx), txid))
    return tx


def fee(tx, testnet=False):
    sum_i, sum_o = 0, 0  # initialize input sum and output sum
    for txi in tx["txis"]:
        prev_tx = fetch(txi["txid"], testnet)
        sum_i += prev_tx["txos"][txi["idx"]]["amount"]
    for txo in tx["txos"]:
        sum_o += txo["amount"]
    return sum_i - sum_o  # fee is input sum - output sum


def sig_hash(tx, idx, lock_script):
    tx4sig = copy.deepcopy(tx)
    for i, txi in enumerate(tx4sig['txis']):
        if i != idx:
            # script.len is calculated when it is serialized.
            # txi["script.len"] = 0
            txi["script"] = []
        else:
            # script.len is calculated when it is serialized.
            # script = serialize_script(script_unlock)
            # txi["script.len"] = len(script)
            txi["script"] = lock_script
    s = serialize(tx4sig)
    s += util.int_to_little_endian(util.SIGHASH_ALL, 4)
    h256 = util.hash256(s)
    return int.from_bytes(h256, 'big')


def hash_all_txis(tx):
    if tx["hash_all"] is None:
        all_prevouts = b''
        all_sequence = b''
        for txi in tx["txis"]:
            all_prevouts += txi["txid"][::-1] + util.int_to_little_endian(txi["idx"], 4)
            all_sequence += util.int_to_little_endian(txi["seq.no"], 4)
        tx["hash_all"] = (util.hash256(all_prevouts), util.hash256(all_sequence))
    return tx["hash_all"]


def hash_all_txos(tx):
    all_txo = b''
    for txo in tx["txos"]:
        all_txo += serialize_txo(txo)
    return util.hash256(all_txo)


def sig_hash_bip143(prev_tx, tx, txi, redeem_script=None, witness_script=None, testnet=False):
    """
    bip143
    1:04LE       version
    2:32         hash prevouts
    3:32         hash sequence
    4:32+4LE     outpoint
    5:*          script_code of the input
    6:08LE       value of output spent
    7:04LE       n_sequence of the input
    8:32         hash outputs
    9:4LE        n_locktime
    10:4LE       sighash
    """
    s = util.int_to_little_endian(tx["version"], 4)  # 1
    hash_all_prevouts, hash_all_sequence = hash_all_txis(tx)
    s += hash_all_prevouts + hash_all_sequence  # 2,3
    s += txi["txid"][::-1] + util.int_to_little_endian(txi["idx"], 4)  # 4

    # 5
    if witness_script:
        script_code = script.serialize(witness_script)
    elif redeem_script:
        script_code = script.serialize(script.p2pkh_script(redeem_script[1]))
    else:
        script_code = script.serialize(script.p2pkh_script(prev_tx["txos"][txi["idx"]]["script"][1]))
    s += script_code

    s += util.int_to_little_endian(prev_tx["txos"][txi["idx"]]["amount"], 8)  # 6
    s += util.int_to_little_endian(txi["seq.no"], 4)  # 7
    s += hash_all_txos(tx)  # 8
    s += util.int_to_little_endian(tx["locktime"], 4)  # 9
    s += util.int_to_little_endian(util.SIGHASH_ALL, 4)  # 10
    return int.from_bytes(util.hash256(s), 'big')


def verify_txi(tx, txi, idx, testnet=False):
    prev_tx = fetch(txi["txid"], testnet)
    lock_script = prev_tx["txos"][txi["idx"]]["script"]
    # check if p2sh-p2wpkh or p2sh-p2wsh, p2sh_pattern = [OP_HASH160(0xa9) <hash:20bytes> OP_EQUAL(0x87)]
    if len(lock_script) == 3 and lock_script[0] == 0xa9 and \
            type(lock_script[1]) == bytes and len(lock_script[1]) == 20 and lock_script[2] == 0x87:
        # the last cmd has to be the redeem_script
        raw_redeem_script = txi["script"][-1]
        # encode_varint로 변환해야 하는것 아닌가? 원소사이즈는 max 520bytes
        # 확인해보니 (지미송)코드에 문제 발견
        # script.parse에서도 length = util.read_varint(s)로 읽고 있음.
        # 그래서 encode_varint로 변경
        # 인코딩: https://github.com/jimmysong/programmingbitcoin/blob/2a6558263923214320bbdeb10826464fe24ef540/code-ch13/tx.py#L313
        # 디코딩: https://github.com/jimmysong/programmingbitcoin/blob/2a6558263923214320bbdeb10826464fe24ef540/code-ch13/script.py#L78
        # raw_redeem_script = util.int_to_little_endian(len(raw_redeem_script), 1) + raw_redeem_script
        raw_redeem_script = util.encode_varint(len(raw_redeem_script)) + raw_redeem_script
        _, redeem_script = script.parse(BytesIO(raw_redeem_script))  # (length, script)
        if script.is_p2wpkh(redeem_script):
            z = sig_hash_bip143(prev_tx, tx, txi, redeem_script=redeem_script, witness_script=None, testnet=testnet)
            witness = txi["wits"]
        elif script.is_p2wsh(redeem_script):
            raw_witness_script = txi["wits"][-1]  # wits:[,,,witness_script]
            raw_witness_script = util.encode_varint(len(raw_witness_script)) + raw_witness_script
            _, witness_script = script.parse(BytesIO(raw_witness_script))
            z = sig_hash_bip143(prev_tx, tx, txi, witness_script=witness_script)
            witness = txi["wits"]
        else:
            z = sig_hash(tx, idx, redeem_script)
            witness = None
    else:  # p2wpkh or p2wsh or ...
        if script.is_p2wpkh(lock_script):
            z = sig_hash_bip143(prev_tx, tx, txi)
            witness = txi["wits"]
        elif script.is_p2wsh(lock_script):
            raw_witness_script = txi["wits"][-1]
            raw_witness_script = util.encode_varint(len(raw_witness_script)) + raw_witness_script
            _, witness_script = script.parse(BytesIO(raw_witness_script))
            z = sig_hash_bip143(prev_tx, tx, txi, witness_script=witness_script)
            witness = txi["wits"]
        else:
            z = sig_hash(tx, idx, lock_script)
            witness = None
    commands = txi["script"] + lock_script
    return script.evaluate(commands, z, witness)


def verify(tx, testnet=False):
    if fee(tx, testnet) < 0:  # check that we're not creating money
        return False

    for i, txi in enumerate(tx["txis"]):  # check that each input has a valid unlock_script
        if not verify_txi(tx, txi, i, testnet):
            print("verification:fail", txi["idx"])
            return False
        else:
            print("verification:success", txi["idx"])
    return True