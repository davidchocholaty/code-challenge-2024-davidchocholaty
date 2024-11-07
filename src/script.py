from dataclasses import dataclass
from typing import List, Any, Union
from Crypto.Hash import RIPEMD160
import hashlib
import ecdsa
from src.op_codes import OP_CODES
from src.verify import parse_der_signature_bytes
from src.serialize import serialize_transaction

class InvalidScriptException(Exception):
    """Custom exception for Script execution errors"""
    pass

class Stack:
    def __init__(self):
        self._items: List[bytes] = []
    
    def push(self, item: bytes) -> None:
        self._items.append(item)
    
    def pop(self) -> bytes:
        if not self._items:
            raise InvalidScriptException("Attempted to pop from empty stack")
        return self._items.pop()
    
    def peek(self) -> bytes:
        if not self._items:
            raise InvalidScriptException("Attempted to peek empty stack")
        return self._items[-1]
    
    def size(self) -> int:
        return len(self._items)
    
    def is_empty(self) -> bool:
        return len(self._items) == 0

class Script:
    def __init__(self, script: bytes, json_transaction: dict = None, input_index: int = 0, segwit: bool = False):
        self.script = script
        self.stack = Stack()
        self.alt_stack = Stack()
        self.if_stack: List[bool] = []
        self.transaction = json_transaction  # Store JSON transaction
        self.input_index = input_index
        self.segwit = segwit
        
    def create_signature_hash(self, hash_type: int) -> bytes:
        data_signed = serialize_transaction(self.transaction, self.input_index, int(hash_type), self.segwit)
        return hashlib.sha256(data_signed).digest()
        """
        Create the signature hash for the transaction based on the hash type.
        This is what gets signed/verified in OP_CHECKSIG.
        
        if not self.transaction:
            raise InvalidScriptException("No transaction context provided for signature verification")
            
        # Create a copy of the transaction
        tx_copy = self.transaction.copy()
        
        # Clear all input scripts
        for inp in tx_copy['vin']:
            inp['scriptsig'] = ''
            
        # Handle different hash types
        if hash_type & 0x1F == 0x01:  # SIGHASH_ALL
            # Most common, signs all inputs and outputs
            # Current input gets the subscript
            tx_copy['vin'][self.input_index]['scriptsig'] = self.script.hex()
            
        elif hash_type & 0x1F == 0x02:  # SIGHASH_NONE
            # Signs all inputs, but no outputs
            tx_copy['vout'] = []
            # Zero out sequence numbers of other inputs
            for i in range(len(tx_copy['vin'])):
                if i != self.input_index:
                    tx_copy['vin'][i]['sequence'] = 0
                    
        elif hash_type & 0x1F == 0x03:  # SIGHASH_SINGLE
            # Signs all inputs and only the output with same index
            if self.input_index >= len(tx_copy['vout']):
                raise InvalidScriptException("SIGHASH_SINGLE invalid output index")
            # Keep only the output at the same index
            output = tx_copy['vout'][self.input_index]
            tx_copy['vout'] = [{'value': -1, 'scriptpubkey': ''}] * self.input_index
            tx_copy['vout'].append(output)
            # Zero out sequence numbers of other inputs
            for i in range(len(tx_copy['vin'])):
                if i != self.input_index:
                    tx_copy['vin'][i]['sequence'] = 0
                    
        if hash_type & 0x80:  # SIGHASH_ANYONECANPAY
            # Only sign the current input
            current_input = tx_copy['vin'][self.input_index]
            tx_copy['vin'] = [current_input]
            self.input_index = 0
            
        # Serialize the modified transaction
        serialized = self.serialize_transaction(tx_copy)
        
        # Add hash type
        serialized += hash_type.to_bytes(4, 'little')
        
        # Double SHA256
        return hashlib.sha256(hashlib.sha256(serialized).digest()).digest()
        """
    def serialize_transaction(self, tx: dict) -> bytes:
        """Serialize a transaction for signing/verification"""
        result = bytearray()
        
        # Version
        result.extend(tx['version'].to_bytes(4, 'little'))
        
        # Number of inputs
        result.extend(len(tx['vin']).to_bytes(1, 'little'))
        
        # Inputs
        for inp in tx['vin']:
            # Previous transaction hash (reverse byte order)
            prev_tx = bytes.fromhex(inp['txid'])[::-1]
            result.extend(prev_tx)
            
            # Previous output index
            result.extend(inp['vout'].to_bytes(4, 'little'))
            
            # Script
            script_sig = bytes.fromhex(inp['scriptsig']) if inp['scriptsig'] else b''
            result.extend(len(script_sig).to_bytes(1, 'little'))
            result.extend(script_sig)
            
            # Sequence
            result.extend(inp['sequence'].to_bytes(4, 'little'))
            
        # Number of outputs
        result.extend(len(tx['vout']).to_bytes(1, 'little'))
        
        # Outputs
        for out in tx['vout']:
            # Amount in satoshis
            result.extend(out['value'].to_bytes(8, 'little'))
            
            # Script
            script_pubkey = bytes.fromhex(out['scriptpubkey'])
            result.extend(len(script_pubkey).to_bytes(1, 'little'))
            result.extend(script_pubkey)
            
        # Locktime
        result.extend(tx['locktime'].to_bytes(4, 'little'))
        
        return bytes(result)
        
    def execute(self) -> bool:
        """Execute the script and return True if it executed successfully"""
        try:
            i = 0
            while i < len(self.script):
                # Skip execution if we're in a false IF block
                if self.if_stack and not self.if_stack[-1]:
                    op = self.script[i:i+1]
                    if op == OP_CODES['OP_ENDIF']:
                        self.if_stack.pop()
                    elif op == OP_CODES['OP_ELSE']:
                        self.if_stack[-1] = not self.if_stack[-1]
                    i += 1
                    continue
                
                op = self.script[i:i+1]
                
                # Handle data push operations
                if op not in OP_CODES.values():
                    length = int.from_bytes(op, 'little')
                    if length > 75:  # Use OP_PUSHDATA operations for larger chunks
                        raise InvalidScriptException(f"Invalid push operation length: {length}")
                    data = self.script[i+1:i+1+length]
                    self.stack.push(data)
                    i += length + 1
                    continue
                
                # Handle opcodes
                op_name = list(OP_CODES.keys())[list(OP_CODES.values()).index(op)]
                i += self._execute_opcode(op_name)
            
            # Script executed successfully if stack is not empty and top value is true
            if self.stack.is_empty():                
                return False
            
            return self.stack.pop() != b'\x00'
            
        except Exception as e:
            raise InvalidScriptException(f"Script execution failed: {str(e)}")

    def _execute_opcode(self, op_name: str) -> int:
        """Execute a single opcode and return how many bytes to advance"""
        
        # Constants
        if op_name == 'OP_0':
            self.stack.push(b'\x00')
            return 1
        elif op_name == 'OP_1NEGATE':
            self.stack.push(b'\xff')
            return 1
        elif op_name.startswith('OP_') and op_name[3:].isdigit():
            n = int(op_name[3:])
            self.stack.push(bytes([n]))
            return 1
            
        # Flow Control
        elif op_name == 'OP_IF':
            if self.stack.is_empty():
                self.if_stack.append(False)
            else:
                value = self.stack.pop()                
                self.if_stack.append(value != b'\x00')
            return 1
        elif op_name == 'OP_NOTIF':
            if self.stack.is_empty():
                self.if_stack.append(True)
            else:
                value = self.stack.pop()
                self.if_stack.append(value == b'\x00')
            return 1
        elif op_name == 'OP_ELSE':
            if not self.if_stack:
                raise InvalidScriptException("OP_ELSE without OP_IF")
            self.if_stack[-1] = not self.if_stack[-1]
            return 1
        elif op_name == 'OP_ENDIF':
            if not self.if_stack:
                raise InvalidScriptException("OP_ENDIF without OP_IF")
            self.if_stack.pop()
            return 1
            
        # Stack Operations
        elif op_name == 'OP_DUP':
            self.op_dup()
            return 1
        elif op_name == 'OP_DROP':
            self.stack.pop()
            return 1
        elif op_name == 'OP_SWAP':
            if self.stack.size() < 2:
                raise InvalidScriptException("Stack too small for OP_SWAP")
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.push(a)
            self.stack.push(b)
            return 1
        elif op_name == 'OP_ROT':
            if self.stack.size() < 3:
                raise InvalidScriptException("Stack too small for OP_ROT")
            a = self.stack.pop()
            b = self.stack.pop()
            c = self.stack.pop()
            self.stack.push(b)
            self.stack.push(a)
            self.stack.push(c)
            return 1
            
        # Arithmetic and Logical Operations
        elif op_name == 'OP_ADD':
            if self.stack.size() < 2:
                raise InvalidScriptException("Stack too small for OP_ADD")
            a = int.from_bytes(self.stack.pop(), 'little', signed=True)
            b = int.from_bytes(self.stack.pop(), 'little', signed=True)
            result = (a + b).to_bytes(4, 'little', signed=True)
            self.stack.push(result)
            return 1
        elif op_name == 'OP_SUB':
            if self.stack.size() < 2:
                raise InvalidScriptException("Stack too small for OP_SUB")
            a = int.from_bytes(self.stack.pop(), 'little', signed=True)
            b = int.from_bytes(self.stack.pop(), 'little', signed=True)
            result = (b - a).to_bytes(4, 'little', signed=True)
            self.stack.push(result)
            return 1
            
        # Crypto Operations
        elif op_name == 'OP_HASH160':
            self.op_hash160()
            return 1
        elif op_name == 'OP_CHECKSIG':
            return self.op_checksig()
        elif op_name == 'OP_CHECKMULTISIG':
            return self.op_checkmultisig()
            
        # Comparison Operations
        elif op_name == 'OP_EQUALVERIFY':
            self.op_equalverify()
            return 1
        elif op_name == 'OP_EQUAL':
            if self.stack.size() < 2:
                raise InvalidScriptException("Stack too small for OP_EQUAL")
            a = self.stack.pop()
            b = self.stack.pop()            
            self.stack.push(b'\x01' if a == b else b'\x00')
            return 1
            
        raise InvalidScriptException(f"Unimplemented opcode: {op_name}")

    def op_dup(self) -> None:
        """Duplicate the top stack item"""
        if self.stack.is_empty():
            raise InvalidScriptException("Cannot DUP empty stack")
        self.stack.push(self.stack.peek())

    def op_hash160(self) -> None:
        """SHA256 followed by RIPEMD160"""
        if self.stack.is_empty():
            raise InvalidScriptException("Cannot HASH160 empty stack")
        value = self.stack.pop()
        sha256 = hashlib.sha256(value).digest()
        ripemd160 = RIPEMD160.new()
        ripemd160.update(sha256)
        self.stack.push(ripemd160.digest())

    def op_equalverify(self) -> None:
        """Verify top two stack items are equal"""
        if self.stack.size() < 2:
            raise InvalidScriptException("Stack too small for EQUALVERIFY")
        a = self.stack.pop()
        b = self.stack.pop()
        if a != b:
            raise InvalidScriptException("EQUALVERIFY failed")

    def op_checksig(self) -> int:
        """
        Verify a signature against a public key
        Returns number of bytes consumed
        """
        if self.stack.size() < 2:
            raise InvalidScriptException("Stack too small for CHECKSIG")
            
        pubkey = self.stack.pop()
        signature = self.stack.pop()
        
        try:
            # Extract DER signature and hash type
            if len(signature) < 1:                
                raise InvalidScriptException("Empty signature")
                
            #der_sig = signature[:-1]  # Remove hash type byte
            #hash_type = signature[-1]

            der_sig = signature[:-1]
            r, s, hash_type = parse_der_signature_bytes(der_sig)

            der_len = len(der_sig)
            signature_len = len(r + s) + 6

            if der_len != signature_len:
                self.stack.push(b'\x00')
                return 1
            
            sig = r + s

            #print(pubkey)

            # Create verifying key from public key bytes
            try:
                vk = ecdsa.VerifyingKey.from_string(
                    pubkey, 
                    curve=ecdsa.SECP256k1,
                    hashfunc=hashlib.sha256
                )
            except Exception as e:      
                raise InvalidScriptException(f"Invalid public key: {str(e)}")
                
            # Create signature hash based on hash type
            sig_hash = self.create_signature_hash(hash_type)
            
            # Verify the signature
            try:
                verified = vk.verify(sig, sig_hash)
            except Exception:
                verified = False
            
            self.stack.push(b'\x01' if verified else b'\x00')

            #print(verified)

            return 1
            
        except Exception as e:
            self.stack.push(b'\x00')
            return 1

    def op_checkmultisig(self) -> int:
        """
        Verify multiple signatures against multiple public keys
        Returns number of bytes consumed
        """
        if self.stack.size() < 1:
            raise InvalidScriptException("Stack too small for CHECKMULTISIG")
            
        # Get number of public keys
        n = int.from_bytes(self.stack.pop(), 'little')
        if n < 0 or n > 20:
            raise InvalidScriptException("Invalid number of public keys")
            
        if self.stack.size() < n + 1:
            raise InvalidScriptException("Stack too small for public keys")
            
        # Get public keys
        pubkeys = []
        for _ in range(n):
            pubkeys.append(self.stack.pop())
            
        # Get number of signatures
        m = int.from_bytes(self.stack.pop(), 'little')
        if m < 0 or m > n:
            raise InvalidScriptException("Invalid number of signatures")
            
        if self.stack.size() < m:
            raise InvalidScriptException("Stack too small for signatures")
            
        # Get signatures
        signatures = []
        for _ in range(m):
            signatures.append(self.stack.pop())
            
        # Remove the extra null byte (Bitcoin protocol quirk)
        if self.stack.size() < 1:
            raise InvalidScriptException("No extra null byte for CHECKMULTISIG")
        self.stack.pop()
        
        # TODO: Implement proper multisig verification
        # This is a simplified version that always returns true
        # In a real implementation, you would:
        # 1. Verify each signature against public keys in order
        # 2. Ensure all signatures are valid
        # 3. Handle proper error cases
        
        verified = True  # Replace with actual verification

        self.stack.push(b'\x01' if verified else b'\x00')
        return 1

    @staticmethod
    def combine_scripts(*scripts: Union[bytes, 'Script'], json_transaction: dict, segwit: bool = False) -> 'Script':
        """
        Combine multiple scripts into a single script.
        Accepts both bytes and Script objects.
        """
        combined = bytearray()
        for script in scripts:
            if isinstance(script, Script):
                combined.extend(script.script)
            elif isinstance(script, bytes):
                combined.extend(script)
            else:
                raise InvalidScriptException(f"Invalid script type: {type(script)}")
        return Script(bytes(combined), json_transaction, segwit=segwit)
    