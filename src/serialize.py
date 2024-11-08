from src.constants import SIGHASH_ALL

# The code in this file is inpired from the following source:
# http://karpathy.github.io/2021/06/21/blockchain/

def serialize_input(tx_input, override=None):
    serialized_input = []
    serialized_input += [bytes.fromhex(tx_input["txid"])[::-1]]  # Reversed txid
    serialized_input += [encode_int(tx_input["vout"], 4)]

    if override is None:
        # None = just use the actual script
        serialized_input += [serialize_script(bytes.fromhex(tx_input["scriptsig"]))]
    elif override is True:
        # True = override the script with the script_pubkey of the associated input
        serialized_input += [serialize_script(bytes.fromhex(tx_input["prevout"]["scriptpubkey"]))]
    elif override is False:
        # False = override with an empty script
        serialized_input += [serialize_script(bytes.fromhex(""))]
    else:
        raise ValueError("script_override must be one of None|True|False")

    serialized_input += [encode_int(tx_input["sequence"], 4)]

    return b''.join(serialized_input)

def encode_int(i, nbytes, encoding='little'):
    return i.to_bytes(nbytes, encoding)

def serialize_script(script):
    return b''.join([encode_varint(len(script)), script])

def serialize_output(output):
    serialized_output = []

    serialized_output += [encode_int(output["value"], 8)]
    serialized_output += [serialize_script(bytes.fromhex(output["scriptpubkey"]))]

    return b''.join(serialized_output)

def encode_int(i, nbytes, encoding='little'):
    """ encode integer i into nbytes bytes using a given byte ordering """
    return i.to_bytes(nbytes, encoding)

def encode_varint(i):
    """ encode a (possibly but rarely large) integer into bytes with a super simple compression scheme """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i < 0x100000000:
        return b'\xfe' + i.to_bytes(4, 'little')
    elif i < 0x10000000000000000:
        return b'\xff' + i.to_bytes(8, 'little')
    else:
        raise ValueError("integer too large: %d" % (i, ))

def serialize_transaction(transaction, index=-1, sighash_type=1, segwit=False):
    # for now for p2pkh
    out = []
    out += [encode_int(transaction["version"], 4)]

    if segwit:
        out += [b'\x00\x01'] # segwit marker

    # inputs
    out += [encode_varint(len(transaction["vin"]))]

    inputs = transaction["vin"]
    outputs = transaction["vout"]

    if index == -1:
        out += [serialize_input(tx_in) for tx_in in inputs]
    else:
        # used when crafting digital signature for a specific input index
        out += [serialize_input(tx_in, index == i) for i, tx_in in enumerate(inputs)]

    # outputs
    out += [encode_varint(len(transaction["vout"]))]
    out += [serialize_output(tx_out) for tx_out in outputs]

    # witness
    if segwit:
        for tx_in in inputs:
            if "witness" not in tx_in:
                break

            out += [encode_varint(len(tx_in["witness"]))]

            for item in tx_in["witness"]:
                item_bytes = bytes.fromhex(item)
                out += [encode_varint(len(item_bytes)), item_bytes]

    # encode rest of data
    out += [encode_int(transaction["locktime"], 4)]    
    out += [encode_int(SIGHASH_ALL, 4) if index != -1 else b'']

    return b''.join(out)
