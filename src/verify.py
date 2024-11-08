def valid_transaction_syntax(json_transaction):
    required = ["version", "locktime", "vin", "vout"]

    for field in required:
        if field not in json_transaction:
            #print('Required field is missing')
            return False
        
    if not isinstance(json_transaction["version"], int):
        #print('Invalid data type')
        return False
        
    if not isinstance(json_transaction["locktime"], int):
        #print('Invalid data type')
        return False

    if not isinstance(json_transaction["vin"], list):
        #print('Invalid data type')
        return False
    
    if not isinstance(json_transaction["vout"], list):
        #print('Invalid data type')
        return False

    # Check inputs
    for input in json_transaction['vin']:
        if not isinstance(input, dict):
            #print('Invalid data type')
            return False

        if 'txid' not in input or 'vout' not in input:
            #print('Invalid data type')
            return False

    # Check outputs
    for output in json_transaction['vout']:
        if not isinstance(output, dict):
            #print('Invalid data type')
            return False

        if 'scriptpubkey' not in output or 'value' not in output:
            #print('Invalid data type')
            return False
        
    return True


def parse_der_signature_bytes(der_signature):
    # Parse the DER signature
    if der_signature[0] != 0x30:
        raise ValueError("Invalid DER signature format")

    length = der_signature[1]
    if length + 2 != len(der_signature):
        raise ValueError("Invalid DER signature length")

    if der_signature[2] != 0x02:
        raise ValueError("Invalid DER signature format")

    r_length = der_signature[3]
    r = der_signature[4:4 + r_length]

    if der_signature[4 + r_length] != 0x02:
        raise ValueError("Invalid DER signature format")

    s_length = der_signature[5 + r_length]
    s = der_signature[6 + r_length:6 + r_length + s_length]

    # Determine the hash type
    if len(der_signature) > 6 + r_length + s_length:
        hash_type = der_signature[-1]
    else:
        hash_type = 0x01  # Default to SIGHASH_ALL

    return r, s, hash_type
