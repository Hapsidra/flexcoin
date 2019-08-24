from flask import Flask, render_template, request as req, jsonify, after_this_request, make_response
import requests
from wallet import verify, get_private_key, public_key_to_pem, sign
from models import *
import threading
DIFFICULTY = 5
MINER_REWARD = 25


class Server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    @staticmethod
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
            @after_this_request
            def add_header(response):
                response.headers['Access-Control-Allow-Origin'] = '*'
                return response

            return json.dumps(chain, default=lambda o: o.__dict__)

        @app.route('/new_block', methods=['POST'])
        def new_block():
            print('req:', req)
            block_json = json.loads(json.loads(req.data))
            add_block(Block.from_dict(block_json))
            return 'ok'

        @app.route('/new_transaction', methods=['POST'])
        def new_transaction():
            print('req:', req)
            form = req.form
            add_transaction(Transaction.from_dict(form))
            return 'ok'

        return app

    def run(self) -> None:
        Server.create_server().run(my_host)


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
            add_block(block)


my_host = open('host.txt', 'r').readline().strip()
transactions_pool: [Transaction] = []
nodes: [str] = ['192.168.0.1', '192.168.0.2']
chain = dict()
private_key = get_private_key()
my_address = public_key_to_pem(private_key)
current_block_hash = None


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
    if block.length <= chain[current_block_hash].length:
        print('не самый длинный блок')
    if block.length != chain[block.previous_hash].length + 1:
        print('invalid length')
        return False
    return True


def add_transaction(transaction):
    if is_valid_transaction(transaction):
        print('new transaction:' + json.dumps(transaction, default=lambda o: o.__dict__))
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
        block_json = json.dumps(block, default=lambda o: o.__dict__)
        print('new block:', block_json)
        for node in nodes:
            if node != my_host:
                try:
                    requests.post('http://' + node + ':5000' + '/new_block', json=block_json)
                except:
                    print('node', node, 'is unavailable')


def get_state(address):
    nonce = 0
    balance = 0
    for block_hash in chain:
        block = chain[block_hash]
        if block.miner == address:
            balance += MINER_REWARD
        for transaction in block.transactions:
            if transaction.sender == address:
                balance -= transaction.value
                nonce = max(nonce, transaction.nonce)
            if transaction.to == address:
                balance += transaction.value
    return State(balance, nonce)


def main():
    server = Server()
    server.start()
    global current_block_hash

    for node in nodes:
        if node != my_host:
            try:
                resp = requests.get('http://' + node + ':5000/chain')
                if resp.ok:
                    chain_json = resp.json()
                    for block_hash in chain_json:
                        block_json = chain_json[block_hash]
                        block = Block.from_dict(block_json)
                        chain[block_hash] = block
                        if current_block_hash is None or block.length > chain[current_block_hash].length:
                            current_block_hash = block.get_hash()
                print('Получен чейн')
            except:
                print('node ' + node + ' is unavailable')
    if len(chain) == 0:
        print('Создан генезис')
        genesis = Block('', '', [], 1, 25814)
        chain[genesis.get_hash()] = genesis
        current_block_hash = genesis.get_hash()
    print(json.dumps(chain, default=lambda o: o.__dict__))
    print('Хеш последнего:', current_block_hash)
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

# class JSONEncoder(json.JSONEncoder):
# #     def encode(self, o):
# #         if isinstance(o, Block):
# #             result = o.__dict__
# #             ts = o.transactions
# #             result['transactions'] = []
# #             for t in ts:
# #                 result['transactions'].append(jsonEncoder.encode(t))
# #             return json.dumps(result)
# #         if isinstance(o, Transaction):
# #             result = o.__dict__
# #             return json.dumps(result)
# #         if isinstance(o, dict):
# #             result = {}
# #             for e in o:
# #                 result[e] = json.dumps(o[e].__dict__)
# #             return json.dumps(result)
# #         return json.dumps(o.__dict__)
# jsonEncoder = JSONEncoder()