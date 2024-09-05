import argparse
import sys
import os

current_script_directory = os.path.dirname(__file__)
project_root_directory = os.path.join(current_script_directory, '..')

if project_root_directory not in sys.path:
    sys.path.append(project_root_directory)

from src.coinbase_transaction import COINBASE_TRANSACTION
from src.mempool import MemPool
from src.mining import calculate_witness_commitment, block_mining
from src.serialize import serialize_transaction
from src.transaction import calculate_txid

def parse_arguments():
    parser = argparse.ArgumentParser(description='Simulation of the mining process of a block')
    parser.add_argument('--mempool', type=str, required=True, help='Path to the directory containing the JSON files with transactions.')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()

    if args.mempool is None:
        # TODO error
        pass

    mempool = MemPool(args.mempool)

    # TODO pokracovani

    block_transactions = [COINBASE_TRANSACTION] + mempool.valid_transactions
    
    transaction_hashes = [calculate_txid(COINBASE_TRANSACTION)] + [calculate_txid(json_transaction) for json_transaction in block_transactions[1:]]
    block_hash = block_mining(transaction_hashes).hex()

    wtxids =  ["0000000000000000000000000000000000000000000000000000000000000000"] + transaction_hashes[1:]

    witness_commitment = calculate_witness_commitment(wtxids)    
    scriptpubkey_wc = '6a24aa21a9ed' + witness_commitment

    COINBASE_TRANSACTION["vout"][1]["scriptpubkey"] = scriptpubkey_wc

    coinbase_serialized = serialize_transaction(COINBASE_TRANSACTION, segwit=True)

    print(block_hash)
    print(coinbase_serialized.hex())
    for transaction in transaction_hashes:
        print(transaction)
