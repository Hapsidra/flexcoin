from flask import Flask, render_template, request as req, jsonify, after_this_request, make_response
import requests
from wallet import verify, get_private_key, public_key_to_pem, sign
from models import *
import threading
my_host = open('host.txt', 'r').readline().strip()
transactions_pool: [Transaction] = []
nodes: [str] = ['192.168.0.1', '192.168.0.2']
chain = dict()
DIFFICULTY = 5
MINER_REWARD = 25


def is_valid_transaction(transaction: Transaction) -> bool:
    sender_state = get_state(transaction.sender)
    if sender_state.nonce >= transaction.nonce:
        print('invalid nonce')
        return False
    if sender_state.balance < transaction.value:
        print('no money')
        return False
    message = transaction.sender + ' ' + transaction.to + ' ' + str(transaction.value) + ' ' + str(transaction.nonce)
    if not verify(transaction.sender, message, transaction.signature):
        print('invalid signature')
        return False
    return True


def is_valid_block(block: Block) -> bool:
    if block.get_hash() in chain:
        print('block already in chain')
        return False
    if block.get_hash()[:DIFFICULTY] != '0' * DIFFICULTY:
        print('invalid hash')
        return False
    for transaction in block.transactions:
        if not is_valid_transaction(transaction):
            print('block contains invalid transaction')
            return False
    if block.previous_hash not in chain:
        print('сиротский блок')
        return False
    if block.length != chain[block.previous_hash].length + 1:
        print('invalid length')
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


def add_block(block):
    global current_block_hash
    if is_valid_block(block):
        transactions_pool.clear()
        chain[block.get_hash()] = block
        current_block_hash = block.get_hash()
        print('new block:', jsonEncoder.encode(block))
        for node in nodes:
            if node != my_host:
                try:
                    requests.post('http://' + node + ':5000' + '/new_block', data=jsonEncoder.encode(block))
                except:
                    print('node', node, 'is unavailable')
    else:
        print('invalid block')


def get_all_transactions() -> [Transaction]:
    return transactions_pool


def get_state(address):
    transactions = get_all_transactions()
    nonce = 0
    if len(transactions) > 0:
        nonce = transactions[len(transactions) - 1].nonce
    balance = 0
    for block_hash in chain:
        block = chain[block_hash]
        if block.miner == address:
            balance += MINER_REWARD
        for transaction in block.transactions:
            if transaction.sender == address:
                balance -= transaction.value
            elif transaction.to == address:
                balance += transaction.value
    return State(balance, nonce)


def create_server():
    app = Flask(__name__)

    @app.route('/')
    def hello_world():
        return 'hello world'

    @app.route('/user_state/<address>')
    def get_user_state(address):
        @after_this_request
        def add_header(response):
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response
        state = get_state(address)
        return jsonify(state.__dict__)


    @app.route('/chain')
    def get_chain():
        return jsonEncoder.encode(chain)

    @app.route('/new_block', methods=['POST'])
    def new_block():
        print('req:', req)
        form = req.form
        print(form)
        print(req.data)
        # miner = form['miner']
        # previous_hash = form['previous_hash']
        # transactions_raw = json.loads(form['transactions'])
        # print(transactions_raw)
        # transactions = []
        # for raw_transaction in transactions_raw:
        #     transactions.append(Transaction(raw_transaction['sender'], raw_transaction['to'], int(raw_transaction['value']), int(raw_transaction['nonce']), raw_transaction['signature']))
        # length = int(form['length'])
        # nonce = int(form['nonce'])
        # block = Block(miner, previous_hash, transactions, length, nonce)
        # add_block(block)
        return 'ok'

    @app.route('/new_transaction', methods=['POST'])
    def new_transaction():
        print('req:', req)
        form = req.form
        value = int(form['value'])
        nonce = int(form['nonce'])
        transaction = Transaction(form['sender'], form['to'], value, nonce, form['signature'])
        add_transaction(transaction)
        return 'ok'

    return app


class Server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self) -> None:
        create_server().run(my_host)


class Miner(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self) -> None:
        while True:
            current_block = chain[current_block_hash]
            block = Block(my_address, current_block_hash, transactions_pool, current_block.length + 1)
            mine(block)
            add_block(block)


server = Server()
server.start()

private_key = get_private_key()
my_address = public_key_to_pem(private_key)

genesis = Block('', '', [], 1, 25814)


def mine(block: Block):
    while True:
        h = block.get_hash()
        if h[:DIFFICULTY] == '0' * DIFFICULTY:
            return
        block.nonce += 1


# mine(genesis)
chain[genesis.get_hash()] = genesis
current_block_hash = genesis.get_hash()


class JSONEncoder(json.JSONEncoder):
    def encode(self, o):
        if isinstance(o, Block):
            result = o.__dict__
            return result
        result = {}
        for e in o:
            result[e] = json.dumps(o[e].__dict__)
        return json.dumps(result)


jsonEncoder = JSONEncoder()
j = jsonEncoder.encode(chain)
print(j)
e = json.loads(j)
print(e)


def main():
    while True:
        cmd = input()
        if cmd == 'sign':
            message = input('enter message: ')
            signature = sign(private_key, message)
            print(signature)
        elif cmd == 'mine':
            Miner().start()
        else:
            print('unsupported command')


main()