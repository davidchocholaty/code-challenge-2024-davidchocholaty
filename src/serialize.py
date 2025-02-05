import re
from src.constants import SIGHASH_ALL

# The code in this file is inpired from the following source:
# http://karpathy.github.io/2021/06/21/blockchain/

def serialize_input(tx_input, override=None):
    serialized_input = []
    serialized_input += [bytes.fromhex(tx_input["txid"])[::-1]]  # Reversed txid

    #hex_string = b''.join(serialized_input).hex()
    #print("serialized: ", [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)])
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
    out = []
    out += [encode_int(transaction["version"], 4)]

    # Check if the transaction has witness data
    has_witness = segwit and any("witness" in tx_in and tx_in["witness"] for tx_in in transaction["vin"])
    if has_witness:
        out += [b'\x00\x01']  # SegWit marker and flag

    # Inputs
    out += [encode_varint(len(transaction["vin"]))]
    inputs = transaction["vin"]
    outputs = transaction["vout"]

    if index == -1:
        out += [serialize_input(tx_in) for tx_in in inputs]
    else:
        out += [serialize_input(tx_in, index == i) for i, tx_in in enumerate(inputs)]

    # Outputs
    out += [encode_varint(len(outputs))]
    out += [serialize_output(tx_out) for tx_out in outputs]

    # Witness data (only if SegWit is enabled and applicable)
    if has_witness:
        for tx_in in inputs:
            if "witness" in tx_in and tx_in["witness"]:
                out += [encode_varint(len(tx_in["witness"]))]
                for item in tx_in["witness"]:
                    item_bytes = bytes.fromhex(item)
                    out += [encode_varint(len(item_bytes)), item_bytes]
            else:
                out += [b'\x00']  # Explicitly encode an empty witness stack

    # Locktime
    out += [encode_int(transaction["locktime"], 4)]

    # Append sighash type if signing a specific input
    if index != -1:
        out += [encode_int(sighash_type, 4)]

    return b''.join(out)
