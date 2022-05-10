import socket

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import Padding

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 5150  # The port used by the server
sqn = 0
rcvsqn = 0
key = b'1234567812345678'  # TODO: Change to b''
header_len = 16
authtag_len = 12


# MTP protocol


def _create_message(
    action, value,
):
    global sqn, key
    msg_length = 0
    _typ = b''

    if action == "login":
        # add the encrypted temp key length
        msg_length += 256
        _typ = b'\x00\x00'
        key = Random.get_random_bytes(32)

    if action == 'command':
        _typ = b'\x01\x00'

    # compute payload_length
    payload_length = len(value)

    # compute message length...
    # header: _header_len
    # payload: payload_length
    # authtag: _authtag_len
    msg_length += header_len + payload_length + authtag_len

    # header: 16 bytes
    #    version: 2 bytes
    #    type:    2 btye
    #    length:  2 btyes
    #    sqn:     2 bytes
    #    rnd:     6 bytes
    #    rsv:     2 bytes

    # create header
    ver = b'\x01\x00'                                     # protocol version 1.0
    typ = _typ                                   # message type 0
    # message length (encoded on 2 bytes)
    _len = msg_length.to_bytes(2, byteorder='big')
    # next message sequence number (encoded on 2 bytes)
    sqn_byte = (sqn + 1).to_bytes(2, byteorder='big')
    # 6-byte long random value
    rnd = Random.get_random_bytes(6)
    rsv = b'\x00\x00'                                     # reserved bytes

    header = ver + typ + _len + sqn_byte + rnd + rsv

    # encrypt the payload and compute the authentication tag over the header and the payload
    # with AES in GCM mode using nonce = sqn + rnd
    nonce = sqn_byte + rnd

    AE = AES.new(key, AES.MODE_GCM, nonce=nonce,
                 mac_len=authtag_len)
    AE.update(header)
    encrypted_payload, authtag = AE.encrypt_and_digest(bytes(value, 'utf-8'))

    msg = header + encrypted_payload + authtag

    if action == "login":
        # load the public key from the public key file
        with open('pubkey.pem', 'rb') as inf:
            server_key = inf.read()
            pubkey = RSA.import_key(server_key)

        # create an RSA cipher object
        RSAcipher = PKCS1_OAEP.new(pubkey)
        # encrypt the temporary key
        etk = RSAcipher.encrypt(key)

        msg += etk

    sqn += 1

    return msg

# convert dictionary to message string


def _create_request_from_dict(dictionary):
    request = ''
    for key, value in dictionary.items():
        request += value + '\n'

    return request

# create request data based on user command


def _get_value_by_command(command):
    dictionary = None

    if command == 'pwd':
        dictionary = {'command': 'pwd'}
    elif command == 'lst':
        dictionary = {'command': 'lst'}
    elif command == 'chd':
        print('Please enter the directory name:')
        directory = str(input())
        dictionary = {
            'command': 'chd',
            'param1': directory
        }
    elif command == 'mkd':
        print('Please enter the directory name:')
        directory = str(input())
        dictionary = {
            'command': 'mkd',
            'param1': directory
        }
    elif command == 'del':
        print('Please enter the directory name:')
        directory = str(input())
        dictionary = {
            'command': 'del',
            'param1': directory
        }
    elif command == 'upl':
        # enter local file path
        # param2 = loaded file size
        param2 = 0
        # param3 = loaded file hash
        param3 = b''
        print('Please enter the file name:')
        file_name = str(input())

        dictionary = {
            'command': 'upl',
            'param1': file_name,
            'param2': param2,
            'param3': param3
        }
    elif command == 'dnl':
        print('Please enter the filename:')
        file_name = str(input())
        dictionary = {
            'command': 'dnl',
            'param1': file_name
        }
    return dictionary


def process_response(sock, data):
    global rcvsqn, key
    msg = data
    # parse the message msg
    header = msg[0:16]                # header is 16 bytes long
    authtag = msg[-12:]               # last 12 bytes is the authtag
    # encrypted payload is between header and authtag
    encrypted_payload = msg[16:-12]
    ver = header[0:2]                 # version is encoded on 2 bytes
    typ = header[2:4]                 # type is encoded on 2 byte
    _len = header[4:6]                 # msg length is encoded on 2 bytes
    sqn = header[6:8]                 # msg sqn is encoded on 2 bytes
    rnd = header[8:14]                # random is encoded on 6 bytes
    rsv = header[14:16]               # reserved is encoded on 2 bytes

    # check the msg length
    msg_len = len(msg)
    if msg_len != int.from_bytes(_len, byteorder='big'):
        print("Warning: Message length value in header is wrong!")
        sock.close()

    # check the sequence number
    print("Expecting sequence number " +
          str(rcvsqn + 1) + " or larger...")
    sndsqn = int.from_bytes(sqn, byteorder='big')
    if (sndsqn <= rcvsqn):
        print("Error: Message sequence number is too old!")
        print("Processing completed.")
        sock.close()
    print("Sequence number verification is successful.")

    # verify and decrypt the encrypted payload
    print("Decryption and authentication tag verification is attempted...")
    nonce = sqn + rnd
    AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
    AE.update(header)
    try:
        payload = AE.decrypt_and_verify(encrypted_payload, authtag)
    except Exception as e:
        print("Error: Operation failed!")
        print("Processing completed.")
        sock.close()
    print("Operation was successful: message is intact, content is decrypted.")

    rcvsqn += 1

    # TODO: login protocol
    # TODO: action based on typ

    print(payload)


# MAIN
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect_ex((HOST, PORT))
# login protocol here

while True:
    print('Enter action:')
    command = str(input())
    if command == 'q':
        break
    val = _get_value_by_command(command)
    if val is not None:
        request = _create_request_from_dict(val)
        print('request', request)
        message = _create_message("command", request)
        sock.send(message)
        data = sock.recv(4096)

        process_response(sock, data)
    else:
        print('Invalid command')
