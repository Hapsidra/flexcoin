# coding=utf-8
from flask import Flask, request as req
import requests
from crypto import verify, get_private_key, public_key_to_pem, sign
from models import *
import threading
import socket
from flask_cors import CORS
DIFFICULTY = 5
MINER_REWARD = 25
PORT = 5000


class Server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    @staticmethod
    def create_server():
        app = Flask(__name__)
        CORS(app)

        @app.route('/')
        def hello_world():
            return 'flexcoin'

        @app.route('/chain')
        def get_chain():
            return json.dumps(chain, default=lambda o: o.__dict__)

        @app.route('/pool')
        def get_pool():
            return json.dumps(transactions_pool, default=lambda o: o.__dict__)

        @app.route('/new_block', methods=['POST'])
        def new_block():
            print('получен новый блок:', req)
            block_json = json.loads(req.data)
            add_block(Block.from_dict(block_json))
            return 'ok'

        @app.route('/new_transaction', methods=['POST'])
        def new_transaction():
            print('получена новая транзакция:', req)
            t_json = json.loads(req.data)
            if add_transaction(Transaction.from_dict(t_json)):
                return 'ok'
            return 'fail'

        return app

    def run(self) -> None:
        Server.create_server().run(host=my_host, port=PORT)


class Miner(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    @staticmethod
    def mine(block: Block):
        while True:
            h = block.get_hash()
            if h[:DIFFICULTY] == '0' * DIFFICULTY:
                return
            block.nonce += 1

    def run(self) -> None:
        while True:
            current_block = chain[current_block_hash]
            block = Block(my_address, current_block_hash, transactions_pool, current_block.length + 1)
            Miner.mine(block)
            print('Замайнен новый блок')
            add_block(block)


my_host = socket.gethostbyname(socket.gethostname())
transactions_pool: [Transaction] = []
nodes: [str] = []
chain = dict()
private_key = get_private_key()
my_address = public_key_to_pem(private_key)
genesis = Block('', '', [], 1, 25814)
chain[genesis.get_hash()] = genesis
current_block_hash = genesis.get_hash()


def get_current_chain():
    s = []
    h = current_block_hash
    while h != '':
        b = json.loads(json.dumps(chain[h], default=lambda o: o.__dict__))
        b['hash'] = h
        s.append(b)
        h = chain[h].previous_hash
    return s


def is_valid_transaction(transaction: Transaction) -> bool:
    sender_state = get_state(transaction.sender)
    if sender_state.nonce >= transaction.nonce:
        print('invalid nonce. Sender nonce:', sender_state.nonce, 'transactions nonce:', transaction.nonce)
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
    if block.length <= chain[current_block_hash].length:
        print('не самый длинный блок')
        return False
    if block.length != chain[block.previous_hash].length + 1:
        print('invalid length')
        return False
    return True


def add_transaction(transaction):
    if is_valid_transaction(transaction):
        for t in transactions_pool:
            if t.sender == transaction.sender and t.nonce >= transaction.nonce:
                print('invalid nonce. pool nonce:', t.nonce, 'transactions nonce:', transaction.nonce)
                return
        print('new transaction:' + json.dumps(transaction, default=lambda o: o.__dict__))
        transactions_pool.append(transaction)
        for node in nodes:
            try:
                requests.post('http://' + node + ':' + str(PORT) + '/new_transaction', data=json.dumps(transaction, default=lambda o: o.__dict__))
            except:
                print('node', node, 'is unavailable')
        return True
    return False


def add_block(block):
    global current_block_hash
    global transactions_pool
    if is_valid_block(block):
        chain[block.get_hash()] = block
        current_block_hash = block.get_hash()
        block_json = json.dumps(block, default=lambda o: o.__dict__)
        print('new block:', block_json)
        transactions_pool = []
        for node in nodes:
            try:
                requests.post('http://' + node + ':' + str(PORT) + '/new_block', data=block_json)
            except:
                print('node', node, 'is unavailable')
    else:
        chain[block.get_hash()] = block


def get_state(address):
    nonce = 0
    balance = 0
    h = current_block_hash
    while chain[h].length > 1:
        block = chain[h]
        if block.miner == address:
            balance += MINER_REWARD
        for transaction in block.transactions:
            if transaction.sender == address:
                balance -= transaction.value
                nonce = max(nonce, transaction.nonce)
            if transaction.to == address:
                balance += transaction.value
        h = block.previous_hash
    return State(balance, nonce)


def next_nonce(address):
    nonce = get_state(address).nonce
    for t in transactions_pool:
        if t.sender == address and t.nonce > nonce:
            nonce = t.nonce
    return nonce + 1


def add_node(node):
    global current_block_hash
    if node != my_host and node not in nodes:
        try:
            resp_chain = requests.get('http://' + node + ':' + str(PORT) + '/chain')
            resp_pool = requests.get('http://' + node + ':' + str(PORT) + '/pool')
            if resp_chain.ok and resp_pool.ok:
                pool_json = json.loads(resp_pool.text)
                for t in pool_json:
                    transactions_pool.append(Transaction.from_dict(t))
                chain_json = resp_chain.json()
                for block_hash in chain_json:
                    block_json = chain_json[block_hash]
                    block = Block.from_dict(block_json)
                    chain[block_hash] = block
                    if block.length > chain[current_block_hash].length:
                        current_block_hash = block.get_hash()
            nodes.append(node)
            print('Получен чейн')
        except:
            print('node ' + node + ' is unavailable')


def main():
    print('your address:', my_address)
    server = Server()
    server.start()

    while True:
        cmd = input()
        if cmd == 'mine':
            print('mining...')
            Miner().start()
        elif cmd == 'balance':
            print(get_state(my_address).balance)
        elif cmd == 'chain':
            print(json.dumps(get_current_chain(), default=lambda o: o.__dict__))
        elif cmd == 'send':
            to = input('to: ')
            value = int(input('value: '))
            n = next_nonce(my_address)
            m = my_address + ' ' + to + ' ' + str(value) + ' ' + str(n)
            if add_transaction(Transaction(my_address, to, value, n, sign(private_key, m))):
                print('success')
        elif cmd == 'nodes':
            print(nodes)
        elif cmd == 'node':
            node = input('ip: ')
            add_node(node)
        elif cmd == 'pool':
            print(json.dumps(transactions_pool, default=lambda o: o.__dict__))
        else:
            print('unsupported command')


main()
