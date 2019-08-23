from hashlib import sha256
from cryptography.hazmat.primitives.hashes import SHA256
from flask import Flask, request as req
import requests
import json


class Transaction:
    def __init__(self, sender, to, value, nonce):
        self.sender = sender
        self.to = to
        self.value = value
        self.nonce = nonce


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


transactions_pool: [Transaction] = []
nodes: [str] = ['192.168.0.2']


def is_valid_transaction(transaction: Transaction) -> bool:
    sender_state = get_state(transaction.sender)
    if sender_state.nonce >= transaction.nonce:
        return False
    if sender_state.balance < transaction.value:
        return False
    return True


def add_transaction(transaction):
    if is_valid_transaction(transaction):
        print('new transaction:' + json.dumps(transaction.__dict__))
        transactions_pool.append(transaction)
        for node in nodes:
            requests.post('http://' + node + ':5000' + '/new_transaction', data=transaction.__dict__)


def get_all_transactions() -> [Transaction]:
    return transactions_pool


def get_state(address):
    transactions = get_all_transactions()
    nonce = 0
    if len(transactions) > 0:
        nonce = transactions[len(transactions) - 1].nonce
    balance = 0
    for transaction in transactions:
        if transaction.sender == address:
            balance -= transaction.value
        elif transaction.to == address:
            balance += transaction.value
    return State(balance, nonce)


def create_server():
    app = Flask(__name__)

    @app.route('/')
    def hello_world():
        return 'Hello, World'

    @app.route('/new_transaction', methods=['POST'])
    def new_transaction():
        print(req)
        form = req.form
        value = int(form['value'])
        nonce = int(form['nonce'])
        transaction = Transaction(form['sender'], form['to'], value, nonce)
        add_transaction(transaction)
        return 'ok'

    return app


create_server().run()