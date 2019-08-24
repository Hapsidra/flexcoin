from hashlib import sha256
import json


class Transaction:
    def __init__(self, sender, to, value, nonce, signature):
        self.sender = sender
        self.to = to
        self.value = value
        self.nonce = nonce
        self.signature = signature

    @staticmethod
    def from_dict(d):
        value = int(d['value'])
        nonce = int(d['nonce'])
        return Transaction(d['sender'], d['to'], value, nonce, d['signature'])


class Block:
    def __init__(self, miner, previous_hash, transactions, length, nonce=0):
        self.miner = miner
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.length = length
        self.nonce = nonce

    def get_hash(self):
        return sha256(json.dumps(self.__dict__).encode()).hexdigest()

    @staticmethod
    def from_dict(data):
        print(type(data))
        miner = data['miner']
        previous_hash = data['previous_hash']
        transactions_raw = data['transactions']
        transactions = []
        for raw_transaction in transactions_raw:
            transactions.append(
                Transaction(raw_transaction['sender'], raw_transaction['to'], int(raw_transaction['value']),
                            int(raw_transaction['nonce']), raw_transaction['signature']))
        length = int(data['length'])
        nonce = int(data['nonce'])
        return Block(miner, previous_hash, transactions, length, nonce)


class State:
    def __init__(self, balance, nonce):
        self.balance = balance
        self.nonce = nonce
