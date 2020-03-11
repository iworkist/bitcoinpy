import tx
import script
import util
import ecc
from io import BytesIO

# source transaction
"""
http://btc-testnet.horizontalsystems.xyz/tx/dd21423466a93ccca9ea5b548e0c19efcfc3aee41036a90102bca600cd9260fb
{
    "txid": "dd21423466a93ccca9ea5b548e0c19efcfc3aee41036a90102bca600cd9260fb",
    "hash": "fc590044c61ca77a649eddac8415e8b67f8df65528d5e3a4ebed78654f2330de",
    "size": 249,
    "vsize": 168,
    "version": 2,
    "locktime": 1664874,
    "vin": [
        {
            "txid": "5ef10110ddc3eb7f433ff5e96ec63d73f5e2539d4bae5489899f89dad75e74fb",
            "scriptSig": {
                "asm": "00145bbcf04653f3f782a060168801fd0687b3672ce2",
                "hex": "1600145bbcf04653f3f782a060168801fd0687b3672ce2"
            },
            "txinwitness": [
                "304402204f3934b856ee128dc25d2c5b825dd7d035911162bd8bf9f0a3dec1496c3cd32c0220324a0a2f9572573786ac5013e0db7fdeb92ee853ae1429901fe7cfd6242a98f201",
                "02bace1110a291ccaad9a3fdd14ce705a92336024e4f9e29b9e6014fa3afd3c777"
            ],
            "sequence": 4294967294,
            "vout": 0
        }
    ],
    "vout": [
        {
            "value": 66.3080424,
            "n": 0,
            "scriptPubKey": {
                "asm": "OP_HASH160 eb4b7c2b71ae0f6850cc2a58a92d53c9ab294d8c OP_EQUAL",
                "hex": "a914eb4b7c2b71ae0f6850cc2a58a92d53c9ab294d8c87",
                "type": "SCRIPTHASH",
                "reqSigs": 1,
                "addresses": [
                    "2NEhMDA2f9bBivvsFKp9VNXpSyvoC2koFE9"
                ]
            }
        },
        {
            "value": 0.01750649,
            "n": 1,
            "scriptPubKey": {
                "asm": "OP_DUP OP_HASH160 e4c8b088f49dbc6a2248400e5002d2a29aed6953 OP_EQUALVERIFY OP_CHECKSIG",
                "hex": "76a914e4c8b088f49dbc6a2248400e5002d2a29aed695388ac",
                "type": "PUBKEYHASH",
                "reqSigs": 1,
                "addresses": [
                    "n2Nemwy3hMdYMMcWi8PyeCCz7RfEpV6Qia"
                ]
            }
        }
    ],
    "blockhash": "00000000000000f42878928fac143b163504af52f072fa115d832592696600a1",
    "confirmations": 3670,
    "time": 1580797559,
    "blocktime": 1580797539,
    "hex": "02000000000101fb745ed7da899f898954ae4b9d53e2f5733dc66ee9f53f437febc3dd1001f15e00000000171600145bbcf04653f3f782a060168801fd0687b3672ce2feffffff02100b3a8b0100000017a914eb4b7c2b71ae0f6850cc2a58a92d53c9ab294d8c8779b61a00000000001976a914e4c8b088f49dbc6a2248400e5002d2a29aed695388ac0247304402204f3934b856ee128dc25d2c5b825dd7d035911162bd8bf9f0a3dec1496c3cd32c0220324a0a2f9572573786ac5013e0db7fdeb92ee853ae1429901fe7cfd6242a98f2012102bace1110a291ccaad9a3fdd14ce705a92336024e4f9e29b9e6014fa3afd3c7776a671900"
}
"""

# create a transaction (from alice to [alice, bob])
"""
input
    txid: dd21423466a93ccca9ea5b548e0c19efcfc3aee41036a90102bca600cd9260fb
    'sec_key': 947605268396919657983759089664,

output
    pub_key_address_compressed_testnet: mxFMySFd6tkjnomB1LgGC85i5hvwGtaFiW // alice
    pub_key_address_compressed_testnet: mtTt5dA1vbELiycUagedatkPQRm1QseoCa // bob
"""



def test_create_legacy_tx():
    # to_alice = total_amount - to_bob - fee

    txo_amount = 0.01750649
    tx_fee = 0.0005
    to_bob = 0.005

    sat_amount = int(txo_amount * 10 ** 8)
    sat_tx_fee = int(tx_fee * 10 ** 8)
    sat_to_bob = int(to_bob * 10 ** 8)
    sat_to_alice = sat_amount - sat_to_bob - sat_tx_fee

    # add txo: to alice
    alice = 'mxFMySFd6tkjnomB1LgGC85i5hvwGtaFiW'
    h160 = util.decode_base58(alice)
    print(h160.hex())
    lock_script = script.p2pkh_script(h160)
    txo_0 = {
        "amount": sat_to_alice,
        "script": lock_script
    }

    # add txo: to bob
    bob = "mtTt5dA1vbELiycUagedatkPQRm1QseoCa"
    h160 = util.decode_base58(bob)
    print(h160.hex())
    lock_script = script.p2pkh_script(h160)
    txo_1 = {
        "amount": sat_to_bob,
        "script": lock_script
    }

    # add_txi
    txid = "dd21423466a93ccca9ea5b548e0c19efcfc3aee41036a90102bca600cd9260fb"
    # "asm": "OP_DUP OP_HASH160 e4c8b088f49dbc6a2248400e5002d2a29aed6953 OP_EQUALVERIFY OP_CHECKSIG",

    # generate unlock script
    prev_tx = tx.fetch(bytes.fromhex(txid), True)
    print(prev_tx)
    for i, txo in enumerate(prev_tx['txos']):
        if script.is_p2pkh(txo['script']):
            print(i, "p2pkh")
        elif script.is_p2sh(txo['script']):
            print(i, "p2sh")
        elif script.is_p2wpkh(txo['script']):
            print(i, "p2wpkh")
        elif script.is_p2wsh(txo['script']):
            print(i, "pswsh")
    # lock_script: p2pkh

    txi_0 = {
        "txid": bytes.fromhex(txid),
        "idx": 1,
        "script": [],
        "seq.no": 0
    }

    tx_obj = {
        "version": 1,
        # "mark": None,
        # "flag": None,
        "txi.count": 1,
        "txis": [txi_0],
        "txo.count": 2,
        "txos": [txo_0, txo_1],
        # "wits": None,
        "locktime": 0
    }

    # alice's 'sec_key': 947605268396919657983759089664,
    sec_key = 947605268396919657983759089664
    z = tx.sig_hash(tx_obj, 0, prev_tx["txos"][1]["script"])
    print(z)

    sig = ecc.sig(sec_key, z)
    der = ecc.sig_der(sig)

    pub_key = ecc.ecc_mul(sec_key)
    sec = ecc.sec(pub_key[0], pub_key[1], False)
    print(sec)

    sig_with_type = der + util.SIGHASH_ALL.to_bytes(1, 'big')

    txi_0["script"] = [sig_with_type, sec]

    print(tx_obj)

    new_tx_bytes = tx.serialize(tx_obj)
    print(new_tx_bytes.hex())

    # tx verification
    stream = BytesIO(new_tx_bytes)
    tx_obj = tx.parse(stream)
    print(tx_obj)
    tx.verify(tx_obj, testnet=True)

    return new_tx_bytes


tx_bytes = test_create_legacy_tx()
print("legacy_tx_bytes_hex:", tx_bytes.hex())

print("broadcast tx_bytes_hex at https://tbtc.bitaps.com/broadcast")
