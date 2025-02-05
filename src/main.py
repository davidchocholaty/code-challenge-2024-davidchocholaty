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
from src.utils import double_spending

def parse_arguments():
    parser = argparse.ArgumentParser(description='Simulation of the mining process of a block')
    parser.add_argument('--mempool', type=str, required=True, help='Path to the directory containing the JSON files with transactions.')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()

    if args.mempool is None:
        print("Error: mempool is not provided")
        exit(1)

    mempool = MemPool(args.mempool)

    # Check double spending
    non_double_spend = []
    non_double_spend = [tx for i, tx in enumerate(mempool.valid_transactions) if not double_spending(non_double_spend[:i], tx)]

    mempool.valid_transactions = non_double_spend

    block_transactions = []

    total_weight = 0
    total_fees = 0
    max_block_weight = 4000000

    # Sort the transactions by the fee in descending order
    transactions_sorted_by_fee = sorted(mempool.valid_transactions, key=lambda tx: tx.fee, reverse=True)

    for tx in transactions_sorted_by_fee:
        tx_weight = tx.calculate_weight()
        if total_weight + tx_weight > max_block_weight:
            break
        block_transactions.append(tx)
        total_weight = total_weight + tx_weight
        total_fees = total_fees + tx.fee

    transaction_hashes = [calculate_txid(COINBASE_TRANSACTION, True)] + [calculate_txid(transaction.json_transaction, transaction.has_witness) for transaction in block_transactions]
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
