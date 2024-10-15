import argparse
import ecdsa
import hashlib
import os
import json
import time

from sha3 import sha3_224
from Crypto.Hash import RIPEMD160

TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"
TARGET_HEX = 0x0000ffff00000000000000000000000000000000000000000000000000000000

class MemPool:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.transaction_files = [os.path.join(self.root_dir, file) for file in os.listdir(self.root_dir) if file.endswith('.json')]
        self.transactions = [Transaction(file) for file in self.transaction_files]
        self.valid_transactions = [transaction.json_transaction for transaction in self.transactions if transaction.is_valid()]

# scriptpubkey_type can be: p2sh, p2pkh, v0_p2wsh, v1_p2tr, v0_p2wpkh.

def get_filename_without_extension(file_path):
    # Get the base filename from the path
    filename = os.path.basename(file_path)
    # Remove the extension
    filename_without_extension = os.path.splitext(filename)[0]
    return filename_without_extension

def valid_transaction_syntax(json_transaction):
    required = ["version", "locktime", "vin", "vout"]

    for field in required:
        if field not in json_transaction:
            print('Required field is missing')
            return False
        
    if not isinstance(json_transaction["version"], int):
        print('Invalid data type')
        return False
        
    if not isinstance(json_transaction["locktime"], int):
        print('Invalid data type')
        return False

    if not isinstance(json_transaction["vin"], list):
        print('Invalid data type')
        return False
    
    if not isinstance(json_transaction["vout"], list):
        print('Invalid data type')
        return False

    # Check inputs
    for input in json_transaction['vin']:
        if not isinstance(input, dict):
            print('Invalid data type')
            return False

        if 'txid' not in input or 'vout' not in input:
            print('Invalid data type')
            return False

    # Check outputs

    for output in json_transaction['vout']:
        if not isinstance(output, dict):
            print('Invalid data type')
            return False

        if 'scriptpubkey' not in output or 'value' not in output:
            print('Invalid data type')
            return False
        
    return True

def non_empty_vin_vout(vin, vout):
    # Make sure neither in or out lists are empty
    if not vin:
        print("vin is empty")
        return False
    if not vout:
        print("vout is empty")
        return False
    
    return True

def serialize_input(tx_input, override=None):
    serialized_input = []
    serialized_input += [bytes.fromhex(tx_input["txid"])[::-1]]  # Reversed txid
    serialized_input += [tx_input["vout"].to_bytes(4, byteorder="little")]

    if override is None:
        serialized_input += [serialize_script(bytes.fromhex(tx_input["scriptsig"]))]
    elif override is True:
        serialized_input += [serialize_script(bytes.fromhex(tx_input["prevout"]["scriptpubkey"]))]
    elif override is False:
        serialized_input += [serialize_script(bytes.fromhex(""))]

    serialized_input += [tx_input["sequence"].to_bytes(4, byteorder="little")]

    return b''.join(serialized_input)

def encode_int(i, nbytes, encoding='little'):
    return i.to_bytes(nbytes, encoding)

def serialize_script(script):
    return b''.join([encode_varint(len(script)), script])

def serialize_output(output):
    serialized_output = []

    serialized_output += [output["value"].to_bytes(8, byteorder="little")]
    serialized_output += [serialize_script(bytes.fromhex(output["scriptpubkey"]))]

    return b''.join(serialized_output)

def encode_varint(i):
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
    message = []
    message += [transaction["version"].to_bytes(4, byteorder="little")]

    if segwit:
        message += [b'\x00\x01'] # segwit marker

    # inputs
    message += [encode_varint(len(transaction["vin"]))]

    inputs = transaction["vin"]
    outputs = transaction["vout"]    

    if index == -1:
        message += [serialize_input(tx_in) for tx_in in inputs]
    else:
        message += [serialize_input(tx_in, index == i) for i, tx_in in enumerate(inputs)]

    # outputs
    message += [encode_varint(len(transaction["vout"]))]
    message += [serialize_output(tx_out) for tx_out in outputs]

    # witness
    if segwit:
        for tx_in in inputs:
            message += [encode_varint(len(tx_in["witness"]))]

            for item in tx_in["witness"]:
                item_bytes = bytes.fromhex(item)
                message += [encode_varint(len(item_bytes)), item_bytes]

    # encode rest of data
    message += [transaction["locktime"].to_bytes(4, byteorder="little")]
    hash_type = 1
    message += [hash_type.to_bytes(4, 'little') if index != -1 else b''] # 1 = SIGHASH_ALL

    return b''.join(message)

def parse_der_signature(der_signature_with_hash_type):
    # Remove the hash_type from the DER signature
    der_signature = der_signature_with_hash_type[:-2]
    
    # Parse the DER signature
    der_bytes = bytes.fromhex(der_signature)
    r_length = der_bytes[3]
    r = int.from_bytes(der_bytes[4:4 + r_length], 'big')
    s_length_index = 4 + r_length + 1
    s_length = der_bytes[s_length_index]
    s = int.from_bytes(der_bytes[s_length_index + 1:s_length_index + 1 + s_length], 'big')
    hash_type = der_bytes[-1]
    
    return r, s, hash_type

def verify_p2pkh_transaction(input_idx, json_transaction):
    #################
    # Pubkey script #
    #################    
    
    input_tx = json_transaction["vin"][input_idx]

    # Extract data from input transaction
    script_sig_asm = input_tx["scriptsig_asm"]

    # Parse scriptSig ASM to extract signature and public key
    script_parts = script_sig_asm.split(" ")
    signature_hex = script_parts[1]
    public_key_hex = script_parts[3]

    r, s, hash_type = parse_der_signature(signature_hex)

    r_hex = hex(r)[2:]
    s_hex = hex(s)[2:]

    der_len = len(signature_hex[:-2])
    signature_len = len(r_hex + s_hex) + 2 * 6
    
    if der_len != signature_len:        
        return False
    
    signature = bytes.fromhex(r_hex + s_hex)

    public_key = bytes.fromhex(public_key_hex)

    scriptpubkey = bytes.fromhex(input_tx['prevout']['scriptpubkey'])
    pubkey_hash = scriptpubkey[3:23]

    hashed_public_key = hashlib.sha256(public_key).digest()

    ripemd160 = RIPEMD160.new()
    ripemd160.update(hashed_public_key)
    pubkey_hash_calculated = ripemd160.digest()

    if pubkey_hash != pubkey_hash_calculated:
        return False


    ####################
    # Signature script #
    ####################

    data_signed = serialize_transaction(json_transaction, input_idx, int(hash_type))
    data_hash = hashlib.sha256(data_signed).digest()

    # Verify the signature
    verifying_key = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    try:
        verifying_key.verify(signature, data_hash, hashlib.sha256)
    except ecdsa.BadSignatureError:            
        return False

    return True


class Transaction:
    def __init__(self, transaction_json_file):
        # Parse transaction.
        with open(transaction_json_file) as transaction:
            json_transaction = json.load(transaction)
        
        # check jestli je valid
        if valid_transaction_syntax(json_transaction):
            self.transaction_name = get_filename_without_extension(transaction_json_file)
            self.version = json_transaction['version']
            self.locktime = json_transaction['locktime']
            self.vin = json_transaction['vin']
            self.vout = json_transaction['vout']
            self.json_transaction = json_transaction
        else:
            print('Invalid transaction syntax')

    def is_valid(self):
        if not non_empty_vin_vout(self.vin, self.vout):
            return False

        input_sum = 0
        for input in self.vin:
            input_sum = input_sum + input['prevout']['value']

        output_sum = 0
        for output in self.vout:
            output_sum = output_sum + output['value']

        if input_sum < output_sum:
            return False

        input_idx = 0
        for input in self.vin:
            if 'scriptsig' in input:
                scriptsig = input['scriptsig']

                scriptpubkey_type = input['prevout']['scriptpubkey_type']

                if scriptsig == "" or scriptpubkey_type not in ["p2pkh", "p2sh"]:
                    return False
                
                if scriptpubkey_type == 'p2pkh':
                    if not verify_p2pkh_transaction(input_idx, self.json_transaction):
                        return False
                else:
                    return False
            else:
                return False
            
            input_idx += 1

        return True

def is_valid_block_hash(block_hash, target):
    if block_hash == "":
        return False

    return block_hash < target

def calculate_bits(target_hex):
    leading_zeros = len(target_hex) - len(target_hex.lstrip('0'))
    exponent = (len(target_hex) - 1) // 2

    coefficient_hex = target_hex[leading_zeros:].rstrip('0')
    coefficient = int(coefficient_hex or '0', 16)

    bits = (exponent << 24) + coefficient

    return bits

def block_mining(transaction_hashes, version=4):
    # Calculate Merkle root hash of transactions
    merkle_root_hashed = calculate_merkle_root(transaction_hashes)
    prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    nonce = 0
    bits = calculate_bits(TARGET)
    timestamp = int(time.time())

    block_hash = ""

    block_header = []

    while not is_valid_block_hash(block_hash, TARGET):
        # Construct block header
        block_header = []
        block_header += [version.to_bytes(4, byteorder='little')]
        block_header += [bytes.fromhex(prev_block_hash)[::-1]]
        block_header += [bytes.fromhex(merkle_root_hashed)]
        block_header += [timestamp.to_bytes(4, byteorder='little')]
        block_header += [bits.to_bytes(4, byteorder='little')]
        block_header += [nonce.to_bytes(4, byteorder='little')]

        # Double sha256 and reverse
        block_hash = hashlib.sha256(hashlib.sha256(b''.join(block_header)).digest()).digest()
        block_hash = block_hash[::-1].hex()
        nonce += 1

    return b''.join(block_header)

def calculate_txid(transaction_content, coinbase=False):
    # Serialize the transaction content
    if coinbase:
        serialized_transaction = serialize_transaction(transaction_content, segwit=True) #json.dumps(transaction_content, sort_keys=True).encode()
    else:
        serialized_transaction = serialize_transaction(transaction_content) #json.dumps(transaction_content, sort_keys=True).encode()

    # Calculate double SHA-256 hash
    hash_result = hashlib.sha256(hashlib.sha256(serialized_transaction).digest()).digest()

    # Reverse byte order to obtain txid
    txid = hash_result[::-1].hex()
    
    return txid

def parse_arguments():
    parser = argparse.ArgumentParser(description='Simulation of the mining process of a block')
    parser.add_argument('--mempool', type=str, required=True, help='Path to the directory containing the JSON files with transactions.')
    return parser.parse_args()

def calculate_merkle_root(transactions):    
    transaction_hashes = []
    # reverse
    for tx in transactions:
        tx_bytes = bytes.fromhex(tx)
        reversed_tx_bytes = tx_bytes[::-1]
        transaction_hashes.append(reversed_tx_bytes.hex())

    while len(transaction_hashes) > 1:
        new_hashes = []

        for i in range(0, len(transaction_hashes), 2):
            if (i + 1 == len(transaction_hashes)):
                new_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(transaction_hashes[i] + transaction_hashes[i])).digest()).hexdigest()
            else:
                new_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(transaction_hashes[i] + transaction_hashes[i + 1])).digest()).hexdigest()
            new_hashes.append(new_hash)

        transaction_hashes = new_hashes

    return transaction_hashes[0]

def calculate_witness_commitment(wtxids):
    merkle_root = calculate_merkle_root(wtxids)    
    merkle_root_bytes = bytes.fromhex(merkle_root)
    witness_reserved_value = '0000000000000000000000000000000000000000000000000000000000000000'
    witness_reserved_value_bytes = bytes.fromhex(witness_reserved_value)    
    return hashlib.sha256(hashlib.sha256(b''.join([merkle_root_bytes,witness_reserved_value_bytes])).digest()).hexdigest()

def get_wtxid(transaction_hash):
    tx_bytes = bytes.fromhex(transaction_hash)
    reversed_tx_bytes = tx_bytes[::-1]
    return reversed_tx_bytes.hex()

if __name__ == '__main__':
    args = parse_arguments()

    if args.mempool is None:
        # TODO error
        pass

    mempool = MemPool(args.mempool)

    coinbase_transaction = {
    "version": 2,
    "locktime": 0xffffffff,
    "vin": [
        {
        "txid": "0000000000000000000000000000000000000000000000000000000000000000",
        "vout": 0xffffffff,
        "sequence": 0xffffffff,
        "is_coinbase": True,
        "scriptsig": "160014fd91039e25b0827748473fce351afd8ead4ecdce",
        "scriptsig_asm": "OP_PUSHBYTES_22 0014fd91039e25b0827748473fce351afd8ead4ecdce",
        "witness": [
            "0000000000000000000000000000000000000000000000000000000000000000",
        ]
        }
    ],
    "vout": [        
        {
            "scriptpubkey": "0014ad4cc1cc859c57477bf90d0f944360d90a3998bf",
            "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 ad4cc1cc859c57477bf90d0f944360d90a3998bf",
            "scriptpubkey_type": "v0_p2wpkh",
            "scriptpubkey_address": "bc1q44xvrny9n3t5w7lep58egsmqmy9rnx9lt6u0tc",
            "value": 100000
        },
        {
            "scriptpubkey": "",
            "scriptpubkey_type": "op_return",
            "value": 0
        }
    ]
    }

    block_transactions = [coinbase_transaction] + mempool.valid_transactions
    
    transaction_hashes = [calculate_txid(coinbase_transaction)] + [calculate_txid(json_transaction) for json_transaction in block_transactions[1:]]
    block_hash = block_mining(transaction_hashes).hex()

    wtxids =  ["0000000000000000000000000000000000000000000000000000000000000000"] + transaction_hashes[1:]

    witness_commitment = calculate_witness_commitment(wtxids)    
    scriptpubkey_wc = '6a24aa21a9ed' + witness_commitment

    coinbase_transaction["vout"][1]["scriptpubkey"] = scriptpubkey_wc

    coinbase_serialized = serialize_transaction(coinbase_transaction, segwit=True)

    print(block_hash)
    print(coinbase_serialized.hex())
    for transaction in transaction_hashes:
        print(transaction)

