import hashlib
import json

from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from Crypto.Hash import RIPEMD160

from src.script import Script, InvalidScriptException
from src.serialize import serialize_transaction
from src.utils import decode_hex, get_filename_without_extension, hash160
from src.verify import parse_der_signature_bytes, valid_transaction_syntax


def calculate_txid(transaction_content, segwit=False):
    # Serialize the transaction content
    serialized_transaction = serialize_transaction(transaction_content, segwit=segwit)

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
            self.fee = 0
            self.has_witness = False
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
        
        self.fee = input_sum - output_sum

        # Output sum can't be greater than the input sum.
        if input_sum < output_sum:
            return False
        
        return True

    def calculate_weight(self):
        base_size = len(serialize_transaction(self.json_transaction))
        total_size = len(serialize_transaction(self.json_transaction, segwit=self.has_witness))

        return int(base_size * 3 + total_size)

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
            self.has_witness = True
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

    def validate_p2sh(self, vin_idx, vin):
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

        # Check if the scriptpubkey is a P2SH script
        if scriptpubkey[:2] != b'\xa9\x14' or scriptpubkey[-1:] != b'\x87':
            # Not a P2SH script, fallback to P2PKH validation
            return self.validate_p2pkh(vin_idx, vin)

        # Extract the script hash from the scriptpubkey        
        script_hash = scriptpubkey[2:-1]

        # Find the redeem script in the scriptsig
        redeem_script_len = int.from_bytes(scriptsig[0:1], byteorder='little')
        redeem_script = scriptsig[1:1+redeem_script_len]

        # Create the combined script
        script = Script.combine_scripts(redeem_script, json_transaction=self.json_transaction)

        # Hash the redeem script and compare with the script hash
        # Compute the HASH160 (RIPEMD-160 of SHA-256) of the redeem script
        sha256_hash = hashlib.sha256(redeem_script).digest()
        ripemd160 = RIPEMD160.new()
        ripemd160.update(sha256_hash)
        computed_script_hash = ripemd160.digest()

        # Compare with the provided script hash
        if computed_script_hash != script_hash:            
            return False

        # Execute the redeem script
        is_valid = script.execute()

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
        # Check for witness data (P2WPKH requires exactly 2 items: signature and pubkey)
        witness = vin.get("witness", [])
        if len(witness) != 2:
            return False
        
        # Extract the signature and public key from the witness data
        try:
            signature = bytes.fromhex(witness[0])
            pubkey = bytes.fromhex(witness[1])
        except ValueError:
            # Handle invalid hex data
            return False
        
        # Check the length of the public key (33 bytes for compressed, 65 for uncompressed)
        if len(pubkey) not in {33, 65}:
            return False

        # Extract the previous output's scriptPubKey
        prevout = vin.get("prevout", {})
        if not prevout:
            return False
        
        scriptpubkey = bytes.fromhex(prevout.get("scriptpubkey", ""))

        # Verify that the scriptPubKey matches the P2WPKH format (OP_0 <20-byte-key-hash>)
        if len(scriptpubkey) != 22 or scriptpubkey[0] != 0x00 or scriptpubkey[1] != 0x14:
            return False
        
        # Create the equivalent P2PKH scriptPubKey from the witness data
        p2pkh_script = (
            bytes([len(signature)]) +  # Push the signature
            signature +
            bytes([len(pubkey)]) +     # Push the public key
            pubkey +
            bytes([
                0x76,  # OP_DUP
                0xa9,  # OP_HASH160
                0x14   # Push 20 bytes (20-byte hash follows)
            ]) +
            scriptpubkey[2:22] +  # Extract 20-byte public key hash from scriptPubKey
            bytes([
                0x88,  # OP_EQUALVERIFY
                0xac   # OP_CHECKSIG
            ])
        )
        
        # Create a script object with the generated P2PKH script and transaction context
        script = Script(
            p2pkh_script,
            json_transaction=self.json_transaction,
            input_index=vin_idx,
            segwit=True
        )
        
        # Execute the script and catch any errors during the process
        try:
            return script.execute()
        except Exception as e:
            print(f"P2WPKH validation error: {str(e)}")
            return False
