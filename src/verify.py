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
