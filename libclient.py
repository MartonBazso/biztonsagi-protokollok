import base64
import io
import json
import os
import selectors
import struct
import sys
import time
from cmath import log
from distutils.util import split_quoted
from hashlib import sha256
from unittest import result

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA
from Crypto.Util import Padding


class Message:
    def __init__(self, selector, sock, addr, request):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self.request = request
        self._recv_buffer = b""
        self._send_buffer = b""
        self._request_queued = False

        self.client_random = None
        self.key = None
        self._header_len = 16   # header: 16 bytes
        self._authtag_len = 12  # we'd like to use a 12-byte long authentication tag
        self._sqn = 0
        self._rcvsqn = 0
        self.header = None
        self._type = b''
        self.response = None

        self.upload_filename = ''
        self.uploadfile_content = b''
        self.upload_finished = True
        self.file_hash = b''
        self.file_size = 0

        self.download_filename = ''
        self.download_file_content = b''
        self.download_finished = True

        self._login_hash = None

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
        #print('buffer', self._send_buffer.hex())
        if self._send_buffer:
            try:
                # Should be ready to write
                sent = self.sock.send(self._send_buffer)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]

    def _create_message(
        self, *, action, value,
    ):
        msg_length = 0
        _typ = b''

        if action == "login":
            # add the encrypted temp key length
            msg_length += 256
            _typ = b'\x00\x00'
            self.key = Random.get_random_bytes(32)
            timestamp = time.time_ns()
            self.client_random = Random.get_random_bytes(16)
            payload = str(timestamp) + '\n' + value + '\n' + \
                str(self.client_random.hex())

            h = SHA256.new()
            h.update(bytes(payload, 'utf-8'))
            self._login_hash = h.hexdigest()

        if action == "command":
            _typ = b'\x01\x00'
            payload = value

        if action == "upload":
            if len(value) > 1024:
                _typ = b'\x02\x00'
                payload = value[:1024]
                self.request["content"] = dict(
                    action="upload", value=value[1024:])
                self.upload_finished = False
            else:
                _typ = b'\x02\x01'
                payload = value
                self.upload_finished = True

        if action == "download":
            _typ = b'\x03\x00'
            payload = value

        # compute payload_length
        payload_length = len(payload)

        # compute message length...
        # header: _header_len
        # payload: payload_length
        # authtag: _authtag_len
        msg_length += self._header_len + payload_length + self._authtag_len
        print(msg_length)
        # header: 16 bytes
        #    version: 2 bytes
        #    type:    2 btye
        #    length:  2 btyes
        #    sqn:     2 bytes
        #    rnd:     6 bytes
        #    rsv:     2 bytes
        ver = b'\x01\x00'                                     # protocol version 1.0
        typ = _typ                                            # message type 0
        # message length (encoded on 2 bytes)
        _len = msg_length.to_bytes(2, byteorder='big')
        # next message sequence number (encoded on 2 bytes)
        sqn = (self._sqn + 1).to_bytes(2, byteorder='big')
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

        if action == "login" or action == "command":
            payload = bytes(payload, 'utf-8')

        encrypted_payload, authtag = AE.encrypt_and_digest(
            payload)

        msg = header + encrypted_payload + authtag

        if action == "login":
            # load the public key from the public key file
            with open('pubkey.pem', 'rb') as inf:
                server_key = inf.read()
                pubkey = RSA.import_key(server_key)

            # create an RSA cipher object
            RSAcipher = PKCS1_OAEP.new(pubkey)
            # encrypt the temporary key
            etk = RSAcipher.encrypt(self.key)

            msg += etk

        self._sqn += 1

        return msg

    def process_events(self, mask):
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()

    def read(self):
        self._read()

        self.process_response()
        # Set selector to listen for write events, we're done reading.
        # self._set_selector_events_mask("w")

    def write(self):

        if not self._request_queued:
            self.queue_request()

        self._write()

        if self._request_queued:
            if not self._send_buffer:
                self._request_queued = False
                if self.upload_finished:
                    # Set selector to listen for read events, we're done writing.
                    self._set_selector_events_mask("r")

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

    def queue_request(self):
        content = self.request["content"]

        message = self._create_message(**content)
        self._send_buffer += message
        self._request_queued = True

    def process_response(self):
        msg = self._recv_buffer
        #print('msg: ', msg.hex())
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
            self.close()

        # check the sequence number
        print("Expecting sequence number " +
              str(self._rcvsqn + 1) + " or larger...")
        sndsqn = int.from_bytes(sqn, byteorder='big')
        if (sndsqn <= self._rcvsqn):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            self.close()
        print("Sequence number verification is successful.")

        # verify and decrypt the encrypted payload
        print("Decryption and authentication tag verification is attempted...")
        nonce = sqn + rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header)
        try:
            payload = AE.decrypt_and_verify(encrypted_payload, authtag)
        except Exception as e:
            print("Error: Operation failed!")
            print("Processing completed.")
            self.close()
        print("Operation was successful: message is intact, content is decrypted.")

        self._rcvsqn = sndsqn
        self._recv_buffer = self._recv_buffer[msg_len:]

        if typ == b'\x00\x10':
            self.login_protocol(payload)

        if typ == b'\x01\x10':
            self.command_protocol(payload)
            if payload.decode('utf-8').split('\n')[0] == "upl" or payload.decode('utf-8').split('\n')[0] == "dnl":
                return

        if typ == b'\x02\x10':
            self.upload_protocol(payload)
        print(typ)
        if typ == b'\x03\x10':
            self.download_protocol(payload)
            return
        if typ == b'\x03\x11':
            self.finish_download(payload)

        print('Enter action:')
        command = str(input())
        if command == 'q':
            self.close()
        val = self._get_value_by_command(command)
        if val is not None:
            value = self._create_request_from_dict(val)
            self.request["content"] = dict(action="command", value=value)
            self.write()
        else:
            print('Invalid command, closing connection...')
            self.close()

    def login_protocol(self, payload):
        request_hash, server_random = payload.decode('utf-8').split("\n")

        if request_hash != self._login_hash:
            print("Response hash failed!")
            self.close()

        master_sec = self.client_random + bytes.fromhex(server_random)
        self.key = HKDF(master_sec, 32, salt=bytes.fromhex(
            request_hash), hashmod=SHA256, num_keys=1)

        # print(self.key.hex())

    def command_protocol(self, payload):
        result = payload.decode('utf-8')
        # decode base64 when command was lst
        split_result = result.split('\n')

        if split_result[0] == 'lst':
            split_result[3] = base64.b64decode(split_result[3]).decode('utf-8')

        if split_result[0] == 'upl' and split_result[2] == 'accept':
            print("Uploading...")
            self.upload_request()
        if split_result[0] == 'dnl' and split_result[2] == 'accept':
            print("Server accepted, would you like to proceed? (y/n)")
            answer = str(input())
            if answer == 'y':
                self.download_request()
                return
            else:
                self.cancel_download()
                return

        for line in split_result:
            print(line)

    def upload_protocol(self, payload):
        file_hash, file_size = payload.decode('utf-8').split("\n")

        if self.file_hash != file_hash or self.file_size != file_size:
            self.close()

        self.upload_filename = ''
        self.uploadfile_content = b''
        self.upload_finished = True
        self.file_hash = b''
        self.file_size = 0

    def download_protocol(self, payload):
        self.download_file_content += payload
        self.download_finished = False
        print("Downloading...")
        print(payload.decode('utf-8'))

    def finish_download(self, payload):
        self.download_file_content += payload
        self.download_finished = True
        # write file to disk
        with open(self.download_filename, 'wb') as f:
            f.write(self.download_file_content)
        print("Download finished!")

    def upload_request(self):
        self.request["content"] = dict(
            action="upload", value=self.uploadfile_content)
        self.write()
        while not self.upload_finished:
            self.write()

    def download_request(self):
        self.request["content"] = dict(
            action="download", value=bytes("Ready", 'utf-8'))
        self.write()

    def cancel_download(self):
        self.request["content"] = dict(
            action="download", value=bytes("Cancel", 'utf-8'))
        self.write()

    def _create_request_from_dict(self, dictionary):
        request = ''
        for key, value in dictionary.items():
            request += value + '\n'

        return request

    def _get_value_by_command(self, command):
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

            param2, param3 = self._upl_file_meta(file_name)
            self.upload_filename = file_name
            dictionary = {
                'command': 'upl',
                'param1': file_name,
                'param2': param2,
                'param3': param3
            }
        elif command == 'dnl':
            print('Please enter the filename:')
            file_name = str(input())
            self.download_filename = file_name
            dictionary = {
                'command': 'dnl',
                'param1': file_name
            }
        return dictionary

    def _upl_file_meta(self, filename):
        size = os.path.getsize(filename)
        print(size)

        with open(filename, 'rb') as file:
            self.uploadfile_content = file.read()

        h = SHA256.new()
        h.update(self.uploadfile_content)
        file_hash = h.hexdigest()
        self.file_size = str(size)
        self.file_hash = str(file_hash)
        return str(size), file_hash
