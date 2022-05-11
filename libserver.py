import base64
import io
import json
import os
import re
import selectors
import struct
import sys
import threading
import time

import argon2
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA
from Crypto.Util import Padding


class Message:
    def __init__(self, selector, sock, addr):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self._recv_buffer = b""
        self._send_buffer = b""
        self.header = None

        self.key = None
        self._key = None
        self._header_len = 16   # header: 16 bytes
        self._authtag_len = 12  # we'd like to use a 12-byte long authentication tag
        self._sqn = 1
        self._rcvsqn = 0
        self._type = b''

        self.request = None
        self.response = None
        self.response_created = False

        self._request_hash = None
        self.root_folder_path = os.getcwd()
        self.starting_directory = os.getcwd() + '\\workdir'
        self.current_directory = self.starting_directory
        self.file_upload_hash = None

        self.upl_file_name = ''
        self.upl_file = b''

        self.dnl_file_name = ''
        self.dnl_file_content = b''
        self.dnl_finished = True

    def _set_selector_events_mask(self, mode):
        """Set selector to listen for events: mode is 'r', 'w', or 'rw'."""
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError(f"Invalid events mask mode {mode!r}.")
        self.selector.modify(self.sock, events, data=self)

    def _read(self):
        try:
            # Should be ready to read
            data = self.sock.recv(4096)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._recv_buffer += data
            else:
                raise RuntimeError("Peer closed.")

    def _write(self):
        # print('buffer_server', self._send_buffer.hex())
        if self._send_buffer:
            try:
                # Should be ready to write
                sent = self.sock.send(self._send_buffer)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]
                # Close when the buffer is drained. The response has been sent.
                if sent and not self._send_buffer:
                    if self.dnl_finished:
                        self._set_selector_events_mask("r")

    def _create_message(
        self, payload
    ):

        if self._type == b'\x00\x00':
            typ = b'\x00\x10'
        elif self._type == b'\x01\x00':
            typ = b'\x01\x10'
        elif self._type == b'\x02\x01':
            typ = b'\x02\x10'
        elif self._type == b'\x03\x00':
            typ = b'\x03\x10'

        print(payload)
        print(self._type)
        print(self.dnl_file_content)
        print('-----------------------------------------------------')
        if self._type == b'\x03\x10' and not self.dnl_finished:
            typ = b'\x03\x10'
            self.download_protocol()

        if self._type == b'\x03\x10' and self.dnl_finished:
            typ = b'\x03\x11'
        # compute payload_length and set authtag_length
        payload_length = len(payload)
        if self._type == b'\x03\x00' and typ == b'\x03\x10':
            self._type = b'\x03\x10'

        # print(payload)
        # compute message length...
        # header: 16 bytes
        # payload: payload_length
        # authtag: authtag_length
        msg_length = self._header_len + payload_length + self._authtag_len

        # create header
        ver = b'\x01\x00'                                     # protocol version 1.0

        # message length (encoded on 2 bytes)
        _len = msg_length.to_bytes(2, byteorder='big')
        # next message sequence number (encoded on 2 bytes)
        sqn = (self._sqn).to_bytes(2, byteorder='big')
        # 6-byte long random value
        rnd = Random.get_random_bytes(6)
        rsv = b'\x00\x00'                                     # reserved bytes

        header = ver + typ + _len + sqn + rnd + rsv

        # encrypt the payload and compute the authentication tag over the header and the payload
        # with AES in GCM mode using nonce = sqn + rnd
        nonce = sqn + rnd

        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce,
                     mac_len=self._authtag_len)
        AE.update(header)

        if typ not in [b'\x03\x10', b'\x03\x11']:
            payload = bytes(payload, 'utf-8')

        encrypted_payload, authtag = AE.encrypt_and_digest(
            payload)

        msg = header + encrypted_payload + authtag

        self._sqn += 1
        self.key = self._key
        print(typ)
        return msg

    def process_events(self, mask):
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()

    def read(self):
        #print("Before reading:", len(self._recv_buffer))
        self._read()
        # print("After reading:", len(self._recv_buffer))
        self.process_request()
        #print("After process:", len(self._recv_buffer))

    def write(self):

        self.create_response()

        self._write()

    def close(self):
        print(f"Closing connection to {self.addr}")
        try:
            self.selector.unregister(self.sock)
        except Exception as e:
            print(
                f"Error: selector.unregister() exception for "
                f"{self.addr}: {e!r}"
            )

        try:
            self.sock.close()
        except OSError as e:
            print(f"Error: socket.close() exception for {self.addr}: {e!r}")
        finally:
            # Delete reference to socket object for garbage collection
            self.sock = None

    def process_request(self):
        os.chdir(self.root_folder_path)

        msg = self._recv_buffer
        # print('msg_server', msg.hex())
        # parse the message msg

        header = msg[0:16]
        ver = header[0:2]      # version is encoded on 2 bytes
        typ = header[2:4]         # type is encoded on 2 byte
        _len = header[4:6]       # msg length is encoded on 2 bytes
        sqn = header[6:8]          # msg sqn is encoded on 2 bytes
        rnd = header[8:14]         # random is encoded on 6 bytes
        rsv = header[14:16]        # reserved is encoded on 2 bytes

        # check the msg length
        msg_len = len(msg)
        # print(msg_len)
        if msg_len != int.from_bytes(_len, byteorder='big'):
            print("Error: Message length value in header is wrong!")
            self.close()
            return

        # check the sequence number
        # print("Expecting sequence number " +
        #      str(self._rcvsqn + 1) + " or larger...")
        sndsqn = int.from_bytes(sqn, byteorder='big')
        if (sndsqn <= self._rcvsqn):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            self.close()
        #print("Sequence number verification is successful.")

        self._type = typ
        if typ == b'\x00\x00':

            mtp_msg = msg[:-256]
            etk = msg[-256:]                # header is 16 bytes long
            # last 12 bytes is the authtag
            authtag = mtp_msg[-12:]
            # encrypted payload is between header and authtag
            encrypted_payload = mtp_msg[16:-12]

            # create an RSA cipher object
            with open('privkey.pem', 'rb') as f:
                keypairstr = f.read()
            with open('privkey.pem', 'wb') as f:
                f.write(keypairstr)
            try:
                keypair = RSA.import_key(keypairstr, passphrase='asdf')
            except ValueError:
                print('Error: Cannot import private key from file ')
                sys.exit(1)

            RSAcipher = PKCS1_OAEP.new(keypair)
            self.key = RSAcipher.decrypt(etk)

        else:
            authtag = msg[-12:]
            encrypted_payload = msg[16:-12]

        # verify and decrypt the encrypted payload
        # print("Decryption and authentication tag verification is attempted...")
        nonce = sqn + rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header)
        try:
            payload = AE.decrypt_and_verify(encrypted_payload, authtag)
        except Exception as e:
            print("Error: Operation failed!")
            print("Processing completed.")
            sys.exit(1)
        print("Operation was successful: message is intact, content is decrypted.")

        self._rcvsqn = sndsqn
        # print(typ)
        if typ == b'\x00\x00':
            self.login_protocol(payload)
        elif typ == b'\x01\x00':
            self.command_protocol(payload)
        elif typ == b'\x02\x00':
            self.upload_protocol_0(payload)
        elif typ == b'\x02\x01':
            self.upload_protocol(payload)
        elif typ == b'\x03\x00':
            self.start_download(payload)

        self._recv_buffer = self._recv_buffer[msg_len:]
        # print(len(self._recv_buffer))
        # Set selector to listen for write events, we're done reading.
        if self.sock != None and typ != b'\x02\x00':
            self._set_selector_events_mask("w")

    def create_response(self):
        message = self._create_message(self.response)
        self.response_created = True
        self._send_buffer += message

    def login_protocol(self, payload):
        msg_timestamp, username, password, client_random = payload.decode(
            'utf-8').split("\n")

        # checks the received timestamp validity
        timestamp = time.time_ns()
        valid_timeframe = 2000000000  # the valid timeframe in nanoseconds

        if abs(timestamp - int(msg_timestamp)) > valid_timeframe:
            print("Message timestamp is not valid!")
            self.close()

        # authenticate the user /w username and password
        pass_hash = argon2.hash_password_raw(
            password=bytes(password, 'utf-8'), salt=b'crysys salt', hash_len=32)
        dict_users = dict()

        # read the password hashes from file
        with open("users.txt", "r") as file:
            s = file.read()
            dict_users = json.loads(s)

        try:
            if str(pass_hash.hex()) != dict_users[username]:
                print("Password is incorrect!")
                self.close()
                return
            else:
                print("Correct password")
        except:
            print("Username is incorrect!")
            self.close()
            return

        h = SHA256.new()
        h.update(payload)
        self._request_hash = h.hexdigest()
        server_random = Random.get_random_bytes(16)
        self.response = str(self._request_hash) + '\n' + \
            str(server_random.hex())

        # print(len(bytes.fromhex(client_random)))
        master_sec = bytes.fromhex(client_random) + server_random
        # print(len(master_sec))
        self._key = HKDF(master_sec, key_len=32, salt=bytes.fromhex(
            self._request_hash), hashmod=SHA256, num_keys=1)

        # print(self._key.hex())

    def command_protocol(self, payload):
        os.chdir(self.current_directory)

        h = SHA256.new()
        h.update(payload)
        self._request_hash = h.hexdigest()
        parsed_payload = self._parse_payload(payload)

        if parsed_payload[0] == 'pwd':
            current_dir = os.getcwd().replace(self.starting_directory, '')
            if current_dir == '':
                current_dir = '/'
            self.response = 'pwd\n' +\
                str(self._request_hash) + '\nsuccess\n' + \
                current_dir
        elif parsed_payload[0] == 'chd':
            if os.getcwd() == self.starting_directory and parsed_payload[1] == '..':
                self.response = 'chd\n' + \
                    str(self._request_hash) + '\nfailure\n' + \
                    'Not allowed to move out of root directory!'
                return
            try:
                os.chdir(parsed_payload[1])
                self.current_directory = os.getcwd()
                self.response = 'chd\n' + \
                    str(self._request_hash) + '\nsuccess'
            except NotADirectoryError:
                self.response = 'chd\n' + \
                    str(self._request_hash) + '\nfailure\n' + \
                    'Not a directory!'
            except FileNotFoundError:
                self.response = 'chd\n' + \
                    str(self._request_hash) + '\nfailure\n' + \
                    'Directory not found!'

        elif parsed_payload[0] == 'lst':
            list_result = os.listdir()
            # print(list_result)
            list_result_base64_encoded = base64.b64encode(
                bytes(', '.join(list_result), 'utf-8')).decode('utf-8')
            self.response = 'lst\n' + \
                str(self._request_hash) + '\nsuccess\n' + \
                list_result_base64_encoded
        elif parsed_payload[0] == 'mkd':
            try:
                os.mkdir(parsed_payload[1])
            except FileExistsError:
                self.response = 'mkd\n' + \
                    str(self._request_hash) + '\nfailure\n' + \
                    'Directory already exists!'
            else:
                self.response = 'mkd\n' + \
                    str(self._request_hash) + '\nsuccess'
        elif parsed_payload[0] == 'del':
            try:
                os.rmdir(parsed_payload[1])
            except FileNotFoundError:
                self.response = 'del\n' + \
                    str(self._request_hash) + '\nfailure\n' + \
                    'File not found!'
            except OSError:
                self.response = 'del\n' + \
                    str(self._request_hash) + '\nfailure\n' + \
                    'Directory not empty!'
            else:
                self.response = 'del\n' +\
                    str(self._request_hash)
        elif parsed_payload[0] == 'upl':
            if os.path.isfile(parsed_payload[1]):
                self.response = 'upl\n' + \
                    str(self._request_hash) + '\nreject\n' + \
                    'File already exists!'
                self.file_upload_hash = parsed_payload[3]
            else:
                self.upl_file_name = parsed_payload[1]
                self.response = 'upl\n' + \
                    str(self._request_hash) + '\naccept'

        elif parsed_payload[0] == 'dnl':
            try:
                # <result_2> is an unsigned integer converted to a string, the value of which is the size of the file to be downloaded in bytes
                result_2 = os.path.getsize(parsed_payload[1])
                # <result_3> is a hexadecimal number converted to a string, the value of which is the SHA-256 hash of the content of the file to be downloaded.
                self.dnl_file_name = parsed_payload[1]
                with open(self.dnl_file_name, 'rb') as file:
                    self.dnl_file_content = file.read()
                h = SHA256.new()
                h.update(self.dnl_file_content)
                result_3 = h.hexdigest()

                self.response = 'dnl\n' + \
                    str(self._request_hash) + '\naccept\n' + \
                    str(result_2) + '\n' + \
                    str(result_3)
            except FileNotFoundError:
                self.response = 'dnl\n' + \
                    str(self._request_hash) + '\nreject\n' + \
                    'File not found!'
            except PermissionError:
                self.response = 'dnl\n' + \
                    str(self._request_hash) + '\nreject\n' + \
                    'Permission denied!'
            except OSError:
                self.response = 'dnl\n' + \
                    str(self._request_hash) + '\nreject\n' + \
                    'File not found!'

        else:
            self.response = parsed_payload[0] + '\n' +\
                str(self._request_hash) + '\nfailure\n' + \
                'Unknown command!'

    def _create_request_from_dict(self, dictionary):
        request = ''
        for key, value in dictionary.items():
            request += value + '\n'

        return request

    def _parse_payload(self, payload):
        payload_str = payload.decode('utf-8')
        payload_list = payload_str.split('\n')
        return payload_list

    def upload_protocol(self, payload):
        self.upl_file += payload

        h = SHA256.new()
        h.update(self.upl_file)
        upl_file_hash = h.hexdigest()

        with open(os.path.join(self.current_directory, self.upl_file_name), "wb") as file:
            file.write(self.upl_file)

        size = os.path.getsize(self.upl_file_name)
        self.upl_file = b''
        self.upl_file_name = ''

        self.response = upl_file_hash + '\n' + str(size)

    def upload_protocol_0(self, payload):
        self.upl_file += payload

    def download_protocol(self):
        if len(self.dnl_file_content) > 1024:
            self.dnl_file_content = self.dnl_file_content[:1024]
            self.response = self.dnl_file_content[1024:]
        else:
            self.response = self.dnl_file_content
            self.dnl_file_content = b''
            self.dnl_file_name = ''
            self.dnl_finished = True

    def start_download(self, payload):
        if payload == b'Ready':
            self.dnl_finished = False
            print('Download started!')
            self.download_protocol()
            self.write()
        else:
            self.dnl_file_name = ''
            self.dnl_file_content = b''
            self.dnl_finished = True
