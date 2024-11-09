import os

from src.transaction import Transaction

class MemPool:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.transaction_files = [os.path.join(self.root_dir, file) for file in os.listdir(self.root_dir) if file.endswith('.json')]
        self.transactions = [Transaction(file) for file in self.transaction_files]
        self.valid_transactions = [transaction for transaction in self.transactions if transaction.is_valid()]
