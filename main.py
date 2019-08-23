from hashlib import sha256
from cryptography.hazmat.primitives.hashes import SHA256
from flask import Flask, render_template, request as req, jsonify
import requests
import json
from wallet import get_private_key, public_key_to_pem, sign, verify
from models import *
my_host = open('host.txt', 'r').readline().strip()
# signature = sign(private_key, 'kek')
# print(signature)
# print(verify(public_key_to_pem(private_key), 'kek', signature))


transactions_pool: [Transaction] = []
nodes: [str] = ['192.168.0.1', '192.168.0.2']


def is_valid_transaction(transaction: Transaction) -> bool:
    sender_state = get_state(transaction.sender)
    if sender_state.nonce >= transaction.nonce:
        return False
    if sender_state.balance < transaction.value:
        return False
    message = transaction.sender + ' ' + transaction.to + ' ' + str(transaction.value) + ' ' + str(transaction.nonce)
    if not verify(transaction.sender, message, transaction.signature):
        return False
    return True


def add_transaction(transaction):
    if is_valid_transaction(transaction):
        print('new transaction:' + json.dumps(transaction.__dict__))
        transactions_pool.append(transaction)
        for node in nodes:
            if node != my_host:
                try:
                    requests.post('http://' + node + ':5000' + '/new_transaction', data=transaction.__dict__)
                except:
                    print('node', node, 'is unavailable')


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
        return render_template('index.html', name='keke')

    @app.route('/user_state/<address>')
    def get_user_state(address):
        state = get_state(address)
        return jsonify(state.__dict__)

    @app.route('/new_transaction', methods=['POST'])
    def new_transaction():
        print(req)
        form = req.form
        value = int(form['value'])
        nonce = int(form['nonce'])
        transaction = Transaction(form['sender'], form['to'], value, nonce, form['signature'])
        add_transaction(transaction)
        return 'ok'

    return app


create_server().run(my_host)