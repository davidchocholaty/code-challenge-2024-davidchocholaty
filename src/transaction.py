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
            #return self.validate_p2sh_p2wpkh(vin_idx, vin)
        elif scriptpubkey_type == "v0_p2wsh":
            pass
            #return self.validate_p2wsh(vin)
        elif scriptpubkey_type == "v1_p2tr":
            pass
            #return self.validate_p2tr(vin)
        elif scriptpubkey_type == "v0_p2wpkh":
            pass
            #return self.validate_p2wpkh(vin)
        
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
        script = Script.combine_scripts(scriptsig, scriptpubkey)
        is_valid = script.execute()
        return is_valid
"""
        #####################################################################
        # Extract signature and public key from scriptSig (Parse scriptSig) #
        #####################################################################
        # https://learnmeabitcoin.com/technical/script/p2pkh/
        # Explanation: the scriptSig contains the signature and the public key (including ASM instructions).            
        
        signature_len = scriptsig[0] # The first byte represents the length of the DER signature (including hash type)
        signature_w_hash_type = scriptsig[1:1+signature_len] # Extract the signature (includes the hash type at the end)

        # The last byte of the signature is the hash type (e.g., SIGHASH_ALL = 0x01)
        signature = signature_w_hash_type[:-1]
        hash_type = signature_w_hash_type[-1]

        public_key_idx = 1 + signature_len
        public_key_len = scriptsig[public_key_idx]
        public_key = scriptsig[public_key_idx+1:public_key_idx+1+public_key_len]

        #######################
        # Parse DER signature #
        #######################
        # https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format
        # https://learnmeabitcoin.com/technical/keys/signature/

        # Remove the hash_type from the DER signature
        der_signature = signature_w_hash_type[:-1]

        r, s, hash_type = parse_der_signature_bytes(der_signature)
        
        der_len = len(der_signature)
        signature_len = len(r + s) + 6

        if der_len != signature_len:        
            return False

        signature = r + s

        ######################
        # Parse scriptPubKey #
        ######################
        # https://learnmeabitcoin.com/technical/script/p2pkh/
        # Explanation: the scriptPubKey contains: DUP, HASH160, public key hash (including OP_PUSHBYTES_20), EQUALVERIFY and CHECKSIG.

        if scriptpubkey[0:1] != b'\x76' or scriptpubkey[1:2] != b'\xa9' or scriptpubkey[2:3] != b'\x14':
            return False  # Not a valid P2PKH scriptPubKey (missing OP_DUP, OP_HASH160, or length mismatch)

        if scriptpubkey[23:24] != b'\x88' or scriptpubkey[24:25] != b'\xac':
            return False  # Not a valid P2PKH scriptPubKey (missing OP_EQUALVERIFY or OP_CHECKSIG)

        pkh = scriptpubkey[3:23]

        # Compute the public key hash (HASH160 of the public key) and compare with scriptPubKey
        calc_pkh = hash160(public_key)
        if calc_pkh != pkh:
            return False  # Public key hash does not match

        ############################################
        # Verify the signature with the public key #
        ############################################

        data_signed = serialize_transaction(self.json_transaction, vin_idx, int(hash_type))
        data_hash = hashlib.sha256(data_signed).digest()

        print(self.json_transaction)
        print("********************************")

        # Verify the signature
        verifying_key = VerifyingKey.from_string(public_key, curve=SECP256k1)
        try:
            verifying_key.verify(signature, data_hash, hashlib.sha256)
        except BadSignatureError:
            return False
        
        return True"""

"""
        def validate_p2sh_p2wpkh(self, vin_idx, vin):
        # Extract scriptSig and witness
        scriptsig = decode_hex(vin.get("scriptsig", ""))
        witness = vin.get("witness", [])

        if not scriptsig or len(witness) < 2:                        
            return False
        
        print(vin["txid"])

        prevout = vin.get("prevout", {})

        if not prevout:
            return False

        scriptpubkey = decode_hex(prevout.get("scriptpubkey", ""))

        #############################
        # Check if it's a P2SH script #
        #############################
        if len(scriptpubkey) != 23 or scriptpubkey[0:1] != b'\xa9' or scriptpubkey[-1:] != b'\x87':
            return False  # Not a valid P2SH scriptPubKey

        # Extract the redeem script hash from the scriptPubKey
        # Extract redeem script hash from scriptPubKey
        if scriptpubkey[0] != 0xa9:  # Check for OP_HASH160
            return False
        
        length_of_hash = scriptpubkey[1]
        if length_of_hash != 0x14:  # 20 bytes
            return False

        expected_redeem_script_hash = scriptpubkey[2:2+length_of_hash]

        ###########################
        # Extract the redeem script #
        ###########################
        # The redeem script is the data in the scriptSig
        redeem_script = scriptsig

        # Hash the redeem script and compare it with the expected hash in the scriptPubKey
        redeem_script_hash = hash160(redeem_script)

        #print("rsh: ", redeem_script_hash)
        #print("ersh: ", expected_redeem_script_hash)

        if redeem_script_hash != expected_redeem_script_hash:
            return False  # Redeem script hash does not match        

        ##############################
        # Parse and execute redeem script #
        ##############################
        # The redeem script should be a P2WPKH script: OP_0 <20-byte-public-key-hash>
        if len(redeem_script) != 22 or redeem_script[0:1] != b'\x00' or redeem_script[1:2] != b'\x14':
            return False  # Not a valid P2WPKH redeem script

        # Extract the public key hash from the redeem script
        public_key_hash = redeem_script[2:]

        ######################
        # Verify the witness #
        ######################
        # The witness field contains:
        #  - witness[0] = signature
        #  - witness[1] = public key

        signature = decode_hex(witness[0])
        public_key = decode_hex(witness[1])

        # Compute the public key hash (HASH160 of the public key) and compare with the public key hash in the redeem script
        calc_pkh = hash160(public_key)
        if calc_pkh != public_key_hash:
            return False  # Public key hash does not match

        ############################################
        # Verify the signature with the public key #
        ############################################

        data_signed = serialize_transaction(self.json_transaction, vin_idx, 1)  # SIGHASH_ALL is typically 1
        data_hash = hashlib.sha256(data_signed).digest()

        # Verify the signature
        verifying_key = VerifyingKey.from_string(public_key, curve=SECP256k1)
        try:
            verifying_key.verify(signature[:-1], data_hash, hashlib.sha256)  # Remove the last byte (hash type)
        except BadSignatureError:
            return False

        return True """