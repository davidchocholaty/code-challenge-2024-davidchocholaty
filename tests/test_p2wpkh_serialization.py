import unittest
import os
import sys

current_script_directory = os.path.dirname(__file__)
project_root_directory = os.path.join(current_script_directory, "..")

if project_root_directory not in sys.path:
    sys.path.append(project_root_directory)

from src.serialize import serialize_transaction

class TestTransactionSerialization(unittest.TestCase):
    def setUp(self):
        """Set up sample transaction data."""
        self.tx_non_segwit = {
            "version": 1,
            "vin": [
                {
                    "txid": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                    "vout": 0,
                    "scriptsig": "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
                    "sequence": 0xfffffffe
                }
            ],
            "vout": [
                {
                    "value": 100000000,
                    "scriptpubkey": "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"
                }
            ],
            "locktime": 0
        }

        self.tx_segwit = {
            "version": 2,
            "vin": [
                {
                    "txid": "cd3412abcd3412abcd3412abcd3412abcd3412abcd3412abcd3412abcd3412abcd",  # Reversed txid
                    "vout": 1,
                    "scriptsig": "",
                    "sequence": 0xffffffff,
                    "witness": [
                        "3045022100abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef022034abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef01",
                        "02abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"
                    ],
                    "prevout": {
                        "scriptpubkey": "0014abcdefabcdefabcdefabcdefabcdefabcdefabcd"
                    }
                }
            ],
            "vout": [
                {
                    "value": 5000000000,
                    "scriptpubkey": "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"
                }
            ],
            "locktime": 0
        }

    def test_serialize_non_segwit_transaction(self):
        """Test serialization of a non-SegWit transaction."""
        serialized_tx = serialize_transaction(self.tx_non_segwit, segwit=False)
        expected_hex = (
            "01000000"  # Version
            "01"  # Number of inputs
            "3412cdab3412cdab3412cdab3412cdab3412cdab3412cdab3412cdab3412cdab"  # Txid (reversed)
            "00000000"  # Vout
            "19"  # Script length
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"  # ScriptSig
            "feffffff"  # Sequence
            "01"  # Number of outputs
            "00e1f50500000000"  # Value
            "19"  # Script length
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"  # ScriptPubKey
            "00000000"  # Locktime
        )
        self.assertEqual(serialized_tx.hex(), expected_hex)

    def test_serialize_segwit_transaction(self):
        """Test serialization of a SegWit transaction."""
        serialized_tx = serialize_transaction(self.tx_segwit, segwit=True)
        expected_hex = (
            "02000000"  # Version
            "0001"  # Marker and flag for SegWit
            "01"  # Number of inputs
            "cd3412abcd3412abcd3412abcd3412abcd3412abcd3412abcd3412abcd3412abcd"  # Txid (reversed)
            "01000000"  # Vout
            "00"  # Empty scriptsig
            "ffffffff"  # Sequence
            "01"  # Number of outputs
            "00f2052a01000000"  # Value
            "19"  # Script length
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"  # ScriptPubKey
            "02"  # Witness item count
            "48"  # Witness 1 length
            "3045022100abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef022034abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef01"  # Witness 1
            "21"  # Witness 2 length
            "02abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"  # Witness 2
            "00000000"  # Locktime
        )

        print("\n")
        print("Serialized TX:\n", serialized_tx.hex())
        print("Expected HEX:\n", expected_hex)

        self.assertEqual(serialized_tx.hex(), expected_hex)

    """
    def test_empty_witness_stack(self):
        tx = self.tx_segwit.copy()
        tx["vin"][0]["witness"] = []
        serialized_tx = serialize_transaction(tx, segwit=True)
        self.assertIn(b'\x00', serialized_tx)  # Empty witness stack explicitly encoded

    def test_invalid_input(self):
        tx_invalid = self.tx_non_segwit.copy()
        tx_invalid["vin"][0].pop("scriptsig")
        with self.assertRaises(KeyError):
            serialize_transaction(tx_invalid)
    """
