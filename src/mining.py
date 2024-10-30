import hashlib
import time

from src.constants import TARGET

def calculate_witness_commitment(wtxids):
    merkle_root = calculate_merkle_root(wtxids)    
    merkle_root_bytes = bytes.fromhex(merkle_root)
    witness_reserved_value = '0000000000000000000000000000000000000000000000000000000000000000'
    witness_reserved_value_bytes = bytes.fromhex(witness_reserved_value)    
    return hashlib.sha256(hashlib.sha256(b''.join([merkle_root_bytes,witness_reserved_value_bytes])).digest()).hexdigest()

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
