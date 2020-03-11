import op
import ecc
import util
from io import BytesIO
from logging import getLogger

LOGGER = getLogger(__name__)


def parse(s):
    length = util.read_varint(s)
    commands = []  # initialize the commands array
    count = 0  # initialize the number of bytes we've read to 0
    while count < length:  # loop until we've read length bytes
        temp = s.read(1)[0]  # get code
        count += 1  # increment the bytes we've read
        if 1 <= temp <= 75:  # if the current byte is between 1 and 75 inclusive
            commands.append(s.read(temp))  # add the next n bytes as an cmd
            count += temp  # increase the count by n
        elif temp == 76:  # op_pushdata1
            data_length = util.little_endian_to_int(s.read(1))
            commands.append(s.read(data_length))
            count += data_length + 1
        elif temp == 77:  # op_pushdata2
            data_length = util.little_endian_to_int(s.read(2))
            commands.append(s.read(data_length))
            count += data_length + 2
        else:  # we have an op_code. set the current byte to op_code
            commands.append(temp)  # add the op_code to the list of commands
    if count != length:
        raise SyntaxError('parsing script failed')

    return length, commands


def serialize(script):
    result = b''  # initialize what we'll send back
    for token in script:  # go through each token
        if type(token) == int:  # if the token is an integer, it's an opcode
            result += util.int_to_little_endian(token, 1)
        else:  # otherwise, this is an element
            length = len(token)  # get the length in bytes
            if length < 75:  # turn the length into a single byte integer
                result += util.int_to_little_endian(length, 1)
            elif 75 < length < 0x100:  # 76 is pushdata1
                result += util.int_to_little_endian(76, 1)
                result += util.int_to_little_endian(length, 1)
            elif 0x100 <= length <= 520:  # 77 is pushdata2
                result += util.int_to_little_endian(77, 1)
                result += util.int_to_little_endian(length, 2)
            else:
                raise ValueError('too long an token')
            result += token
    total = len(result)
    return util.encode_varint(total) + result


def is_p2pkh(script):
    # OP_DUP (0x76), OP_HASH160 (0xa9), <hash:20>, OP_EQUALVERIFY (0x88), OP_CHECKSIG (0xac)
    return len(script) == 5 and script[0] == 0x76 and script[1] == 0xa9 \
           and type(script[2]) == bytes and len(script[2]) == 20 \
           and script[3] == 0x88 and script[4] == 0xac


def is_p2sh(script):
    # OP_HASH160 (0xa9), <hash:20>, OP_EQUAL (0x87)
    return len(script) == 3 and script[0] == 0xa9 \
           and type(script[1]) == bytes and len(script[1]) == 20 \
           and script[2] == 0x87


def is_p2wpkh(script):  # [op_0, <hash:20>]
    return len(script) == 2 and script[0] == 0x00 and type(script[1]) == bytes and len(script[1]) == 20


def is_p2wsh(script):  # [op_0, <hash:32>]
    return len(script) == 2 and script[0] == 0x00 and type(script[1]) == bytes and len(script[1]) == 32


def p2pkh_script(h160):
    """
    0x76: OP_DUP
    0xa9: OP_HASH160
    h160: h160(pub_key)
    0x88: OP_EQUALVERIFY
    0xac: OP_CHECKSIG
    """
    return [0x76, 0xa9, h160, 0x88, 0xac]


def p2sh_script(h160):
    return [0xa9, h160, 0x87]


def p2wpkh_script(h160):
    return [0x00, h160]


def p2wsh_script(h256):
    return [0x00, h256]


def evaluate(commands, z, witness):
    cmds = commands[:]  # create a copy as we may need to add to this list if we have a redeem_script
    stack = []
    altstack = []
    while len(cmds) > 0:
        cmd = cmds.pop(0)
        if type(cmd) == int:
            # do what the opcode says
            operation = op.OP_CODE_FUNCTIONS[cmd]
            if cmd in (99, 100):
                # op_if/op_notif require the cmds array
                if not operation(stack, cmds):
                    LOGGER.info('bad op: {}'.format(op.OP_CODE_NAMES[cmd]))
                    return False
            elif cmd in (107, 108):
                # op_toaltstack/op_fromaltstack require the altstack
                if not operation(stack, altstack):
                    LOGGER.info('bad op: {}'.format(op.OP_CODE_NAMES[cmd]))
                    return False
            elif cmd in (172, 173, 174, 175):
                # these are signing operations, they need a sig_hash
                # to check against
                if not operation(stack, z):
                    LOGGER.info('bad op: {}'.format(op.OP_CODE_NAMES[cmd]))
                    return False
            else:
                if not operation(stack):
                    LOGGER.info('bad op: {}'.format(op.OP_CODE_NAMES[cmd]))
                    return False
        else:
            # add the cmd to the stack
            stack.append(cmd)
            # p2sh rule. if the next three cmds are:
            # OP_HASH160 <20 byte hash> OP_EQUAL this is the RedeemScript
            # OP_HASH160 == 0xa9 and OP_EQUAL == 0x87
            if len(cmds) == 3 and cmds[0] == 0xa9 \
                    and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
                    and cmds[2] == 0x87:
                # we execute the next three opcodes
                cmds.pop()
                h160 = cmds.pop()
                cmds.pop()
                if not op.op_hash160(stack):
                    return False
                stack.append(h160)
                if not op.op_equal(stack):
                    return False
                # final result should be a 1
                if not op.op_verify(stack):
                    LOGGER.info('bad p2sh h160')
                    return False
                raw_redeem_script = util.encode_varint(len(cmd)) + cmd
                _, redeem_script = parse(BytesIO(raw_redeem_script))
                cmds.extend(redeem_script)
            # witness program version 0 rule. if stack cmds are [0 <20 byte hash>] this is p2wpkh
            if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 20:
                h160 = stack.pop()
                stack.pop()
                cmds.extend(witness)
                cmds.extend(p2pkh_script(h160))
            # witness program version 0 rule. if stack cmds are:[0 <32 byte hash>] this is p2wsh
            if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 32:
                s256 = stack.pop()
                stack.pop()
                cmds.extend(witness[:-1])
                raw_witness_script = witness[-1]
                if s256 != util.sha256(raw_witness_script):
                    print('bad sha256 {} vs {}'.format(s256.hex(), util.sha256(raw_witness_script).hex()))
                    return False
                stream = BytesIO(util.encode_varint(len(raw_witness_script)) + raw_witness_script)
                cmds.extend(parse(stream))
    if len(stack) == 0:
        return False
    if stack.pop() == b'':
        return False
    return True
