from hashlib import sha256
import json


class Transaction:
    def __init__(self, sender, to, value, nonce, signature):
        self.sender = sender
        self.to = to
        self.value = value
        self.nonce = nonce
        self.signature = signature


class Block:
    def __init__(self, miner, previous_hash, transactions, length, nonce=0):
        self.miner = miner
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.length = length
        self.nonce = nonce

    def get_hash(self):
        return sha256(json.dumps(self.__dict__).encode()).hexdigest()


class State:
    def __init__(self, balance, nonce):
        self.balance = balance
        self.nonce = nonce