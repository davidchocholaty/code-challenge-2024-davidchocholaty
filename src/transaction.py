import hashlib
import json

from ecdsa import VerifyingKey, SECP256k1, BadSignatureError

from src.script import Script, InvalidScriptException
from src.serialize import serialize_transaction
from src.utils import decode_hex, get_filename_without_extension, hash160
from src.verify import parse_der_signature_bytes, valid_transaction_syntax

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
            # TODO jestli nejakej error
            print('Invalid transaction syntax')

    def is_valid(self):
        # At least one input and one output.
        if not self.non_empty_vin_vout():
            return False

        # Basic locktime check.
        if not self.valid_locktime():
            return False

        if not self.check_input_output_sum():
            return False

        # Check each input validity.        
        for vin_idx, vin in enumerate(self.vin):
            if not self.valid_input(vin_idx, vin):
                return False

        # Check each output validity.
        for vout in self.vout:
            if not self.valid_output(vout):
                return False

        return True
    
    def non_empty_vin_vout(self):
        # Make sure neither in or out lists are empty
        if not self.vin:
            #print("vin is empty")
            return False
        if not self.vout:
            #print("vout is empty")
            return False
        
        return True
    
    def valid_locktime(self):
        return isinstance(self.locktime, int) and self.locktime >= 0

    def check_input_output_sum(self):
        input_sum = 0
        for input in self.vin:
            input_sum = input_sum + input['prevout']['value']

        output_sum = 0
        for output in self.vout:
            output_sum = output_sum + output['value']
        
        # Output sum can't be greater than the input sum.
        if input_sum < output_sum:
            return False
        
        return True

    def valid_input(self, vin_idx, vin):
        if vin.get("is_coinbase", False):
            return False
        
        prevout = vin.get("prevout", {})
        scriptpubkey_type = prevout.get("scriptpubkey_type", "")

        if scriptpubkey_type == "p2pkh":
            return self.validate_p2pkh(vin_idx, vin)
        elif scriptpubkey_type == "p2sh":
            pass
        elif scriptpubkey_type == "v0_p2wsh":
            pass
        elif scriptpubkey_type == "v1_p2tr":
            pass
        elif scriptpubkey_type == "v0_p2wpkh":
            return self.validate_p2wpkh(vin_idx, vin)
        
        # Unknown script type.
        return False        

    def valid_output(self, vout):
        scriptpubkey_type = vout.get("scriptpubkey_type", "")
        return scriptpubkey_type in ["v0_p2wpkh", "p2sh", "v0_p2wsh", "v1_p2tr", "p2pkh"]

    def validate_p2pkh(self, vin_idx, vin):
        #################
        # Pubkey script #
        #################
        scriptsig = decode_hex(vin.get("scriptsig", ""))
        if not scriptsig:
            return False
        prevout = vin.get("prevout", {})
        if not prevout:
            return False
        scriptpubkey = decode_hex(prevout.get("scriptpubkey", ""))

        # Combine and verify
        script = Script.combine_scripts(scriptsig, scriptpubkey, json_transaction=self.json_transaction)
        is_valid = script.execute()

        #print(is_valid)

        return is_valid

    def validate_p2wpkh(self, vin_idx, vin):
        """
        Validate a Pay-to-Witness-Public-Key-Hash (P2WPKH) transaction input
        
        Args:
            vin_idx (int): Index of the input being validated
            vin (dict): Input data containing witness information
            
        Returns:
            bool: True if the P2WPKH input is valid, False otherwise
        """
        # Check for witness data
        witness = vin.get("witness", [])
        if len(witness) != 2:  # P2WPKH requires exactly 2 witness items (signature and pubkey)
            return False
            
        # Get witness components
        signature = bytes.fromhex(witness[0])
        pubkey = bytes.fromhex(witness[1])
        
        # Get previous output's scriptPubKey
        prevout = vin.get("prevout", {})
        if not prevout:
            return False
            
        scriptpubkey = bytes.fromhex(prevout.get("scriptpubkey", ""))
        
        # Verify the script is proper P2WPKH format (OP_0 <20-byte-key-hash>)
        if len(scriptpubkey) != 22 or scriptpubkey[0] != 0x00 or scriptpubkey[1] != 0x14:
            return False
        
        # Create P2PKH-style script from witness data
        # P2WPKH witness program is executed as if it were P2PKH scriptPubKey
        p2pkh_script = (
            bytes([len(signature)]) +  # Push signature
            signature +
            bytes([len(pubkey)]) +     # Push pubkey
            pubkey +
            # Standard P2PKH script operations
            bytes([
                0x76,  # OP_DUP
                0xa9,  # OP_HASH160
                0x14   # Push 20 bytes
            ]) +
            scriptpubkey[2:22] +  # 20-byte pubkey hash from witness program
            bytes([
                0x88,  # OP_EQUALVERIFY
                0xac   # OP_CHECKSIG
            ])
        )
        
        # Create script object with witness-specific transaction data
        script = Script(
            p2pkh_script,
            json_transaction=self.json_transaction,
            input_index=vin_idx,
            segwit=True
        )
        
        # Execute the script
        try:
            return script.execute()
        except Exception as e:
            print(f"P2WPKH validation error: {str(e)}")
            return False
