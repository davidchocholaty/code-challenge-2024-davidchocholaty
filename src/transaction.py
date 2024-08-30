import hashlib
import json

from src.serialize import serialize_transaction
from src.utils import get_filename_without_extension
from src.verify import  non_empty_vin_vout, valid_transaction_syntax, verify_p2pkh_transaction

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