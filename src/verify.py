import ecdsa
import hashlib

from Crypto.Hash import RIPEMD160
from src.serialize import serialize_transaction

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
