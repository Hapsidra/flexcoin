class Transaction:
    def __init__(self, sender, to, value, nonce, signature):
        self.sender = sender
        self.to = to
        self.value = value
        self.nonce = nonce
        self.signature = signature


class Block:
    def __init__(self, transactions, nonce=0):
        self.transactions = transactions
        self.nonce = nonce

    def mine(self):
        print(type(self.__dict__))


class State:
    def __init__(self, balance, nonce):
        self.balance = balance
        self.nonce = nonce