from flask import Flask, render_template, request as req, jsonify, after_this_request, make_response
import requests
from wallet import verify, get_private_key, public_key_to_pem, sign, encode_private
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

        @app.route('/sign', methods=['POST'])
        def d_sign():
            @after_this_request
            def add_header(resp):
                resp.headers['Access-Control-Allow-Origin'] = '*'
                return resp
            print(req.data)
            d = json.loads(req.data)
            print(d)
            print(type(d))
            k = d['key']
            print(k)
            pk = encode_private(k)
            message = d['message']
            return sign(pk, message)

        @app.route('/sorted_chain')
        def sorted_chain():
            @after_this_request
            def add_header(resp):
                resp.headers['Access-Control-Allow-Origin'] = '*'
                return resp
            s = []
            h = current_block_hash
            while h != '':
                b = json.loads(json.dumps(chain[h], default=lambda o: o.__dict__))
                b['hash'] = h
                s.append(b)
                h = chain[h].previous_hash
            return jsonify(s)

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
            print('получен новый блок:', req)
            block_json = json.loads(json.loads(req.data))
            add_block(Block.from_dict(block_json))
            return 'ok'

        @app.route('/new_transaction', methods=['POST'])
        def new_transaction():
            @after_this_request
            def add_header(response):
                response.headers['Access-Control-Allow-Origin'] = '*'
                return response
            print('получена новая транзакция:', req)
            if add_transaction(Transaction.from_dict(json.loads(req.data))):
                return 'ok'
            return 'fail'

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
            print('Замейнен новый блок')
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
            if node != my_host:
                try:
                    requests.post('http://' + node + ':5000' + '/new_transaction', data=transaction.__dict__)
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
            if node != my_host:
                try:
                    requests.post('http://' + node + ':5000' + '/new_block', json=block_json)
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


def main():
    print('your private:', private_key)
    #ps = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI1Des8sxHbnYCAggA\nMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBUPj978aRSrZugNxYunSnxBIIB\nYK0WNIeTSuj8WiLXKI3V30yMQeX36eyXZFGb9/4EvP+rqV6aE5EXsLiZf6qMaiH1\nts/dcmaSwvTePY49zcvrlOByqampDl9lEKwnKHCS5fcwbBh23bVVmA4db/MaGC4N\nkp7wi+kdZBobQMrEyjLZsTxgACnVHYjIALivTlOuBlTnqbItvrMLCfGGV9IsC4vG\ndqTtyqKeRq3oqhrIPMFUfJmAbvGE5sW/oTW8Se7+oBu8XIX0IIBfazvkdYVO1msO\n8L3r4X9aztp7e+wPHTOk1d0QXk17IFqlYiDVeOLeNUC48rG+bHsAcPPCAOUdapfP\nZXvxUkQo8baxLt8xV+OU7cF58aK2hjty5OidBOVkuClvnpH2JxVAEugQuC8whjZZ\nZeowvZG9Pu4j74W1J3WxAXQtiQwSBhTbCgV4QGZGCuwfCy1Mw7ILm1de1x/o26CH\nc3Xyi5vjPcv0eRjXFApvHUY=\n-----END ENCRYPTED PRIVATE KEY-----'
    #print(public_key_to_pem(encode_private(ps)))
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