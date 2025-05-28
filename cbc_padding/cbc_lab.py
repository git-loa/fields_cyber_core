from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Callable

import socket
import json 

###################################################################
###################################################################
###############    Padding Functions    ###########################
###################################################################
###################################################################

# 1. Implementing PKCS7 Padding:
def pad_msg(msg: bytes, block_size: int = 16) -> bytes:
    """
    PKCS#7 pads the message for AES (block size of 16)
    """
    padding_len = block_size - (len(msg) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return msg + bytes([padding_len] * padding_len)


def check_padding(padded_msg: bytes) -> bool:
    """
    Verifies that the input is PKCS#7 padded
    """
    if not padded_msg or len(padded_msg) == 0:
        return False

    padding_len = padded_msg[-1]
    if padding_len < 1 or padding_len > len(padded_msg):
        return False

    return all(b == padding_len for b in padded_msg[-padding_len:])


def unpad_msg(padded_msg: bytes) -> bytes:
    """
    Strips the padding if it is valid, raises an exception if not.
    """

    if not check_padding(padded_msg):
        raise ValueError("Invalid PKCS7 padding")

    padding_len = padded_msg[-1]
    return padded_msg[:-padding_len]


# 2. Implementing CBC Encryption
class AESCBCCipher:
    def __init__(self, block_decryptor):
        self.block_decryptor = block_decryptor

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypts `ciphertext` under CBC. The IV is assumed to be the first
        16 bytes of the ciphertext
        Returns the plaintext with PKCS#7 padding removed.
        """
        # Your Code here
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext is too short")
        iv = ciphertext[:16]  # Assume the IV is the first 16 bytes
        encrypted_data = ciphertext[16:]
        decrypted_blocks = []
        previous_block = iv

        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i : i + 16]
            decrypted_block = self.block_decryptor(block)
            db_xor_prev = bytes(i ^ j for i, j in zip(decrypted_block, previous_block))
            decrypted_blocks.append(db_xor_prev)
            previous_block = block
        decrypted_msg = b"".join(decrypted_blocks)
        return decrypted_msg


###################################################################
###################################################################
###############     Testing AESCBC Decryption    ##################
###################################################################
###################################################################

def aes_block_decrypt(key: bytes, block: bytes) -> bytes:
    """
    Decrypt exactly one 16-byte block under AES-ECB.

    Parameters
    ----------
    key : bytes
            16, 24, or 32-byte AES key
    block : bytes
            16-byte ciphertext block

    Returns
    -------
    bytes
            16-byte plaintext block
    """
    if len(block) != AES.block_size:
        raise ValueError(f"Ciphertexttext block must be {AES.block_size} bytes")
    if len(key) not in {16, 24, 32}:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)


def aes_cbc_encrypt(key: bytes, message: bytes) -> bytes:
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(message, AES.block_size))


def test_cbc():
    key = bytes(16)
    messages = [
        b"a sample message that's more than a block",
        b"a sample message",
        b"short",
    ]
    decryptor = lambda block: aes_block_decrypt(key, block)
    cbc_cipher = AESCBCCipher(decryptor)

    for m in messages:
        ctxt = aes_cbc_encrypt(key, m)
        assert unpad_msg(cbc_cipher.decrypt(ctxt)) == m

    print("All assertions passed!")

###################################################################
###################################################################
################         Vaudenay Oracle       ####################
###################################################################
###################################################################

class VaudenayOracle:
    def __init__(
        self, query_fn: Callable[[bytes], bool], get_ciphertext_fn: Callable[[], bytes]
    ):
        """
        A generic CBC padding oracle interface.

        Parameters
        ----------
        query_fn : Callable[[bytes], bool]
            A callable that takes ciphertext bytes (IV prepended or however formatted)
            and returns True if padding is valid, False otherwise.
        get_ciphertext_fn : Callable[[], bytes]
            A callable that returns the target ciphertext to attack (including prepended IV).
        """
        self._query_fn = query_fn
        self._get_ciphertext_fn = get_ciphertext_fn

    def query(self, ciphertext: bytes) -> bool:
        """
        Ask the oracle whether `ciphertext` decrypts to validly-padded plaintext.

        Parameters
        ----------
        ciphertext : bytes
            The ciphertext to test (IV prepended, or as expected by the oracle).

        Returns
        -------
        bool
            True if padding is valid; False otherwise.
        """
        return self._query_fn(ciphertext)

    def get_ciphertext(self) -> bytes:
        """
        Retrieve the ciphertext to attack.

        Returns
        -------
        bytes
            The ciphertext (including IV) that the attack should target.
        """
        return self._get_ciphertext_fn()


# 1) Create a key & some plaintext, then encrypt it under AES-CBC + PKCS#7
key = get_random_bytes(16)
plaintext = b"Attack at dawn! Here's some test data."
iv = get_random_bytes(16)
cipher_enc = AES.new(key, AES.MODE_CBC, iv=iv)
ciphertext_body = cipher_enc.encrypt(pad(plaintext, AES.block_size))
test_ciphertext = iv + ciphertext_body

# 2) Define the local oracle functions
def local_query(ct: bytes) -> bool:
    """Return True if ct decrypts to correctly-padded plaintext."""
    iv_, body = ct[:16], ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv_)
    pt_padded = cipher.decrypt(body)
    try:
        unpad(pt_padded, AES.block_size)
        return True
    except ValueError:
        return False


def local_get_ciphertext() -> bytes:
    """Return the precomputed ciphertext to attack."""
    return test_ciphertext


# 3) Instantiate and exercise the oracle
oracle = VaudenayOracle(query_fn=local_query, get_ciphertext_fn=local_get_ciphertext)


def test_oracle():
    ciphertext = oracle.get_ciphertext()
    print("Original padding valid?  ", oracle.query(ciphertext))  # → True

    # 4) Tamper with one byte and see padding fail
    tampered = bytearray(ciphertext)
    tampered[63] ^= 0xFF  # Tamper the last byte to increase chances of failure
    print("After bit-flip padding valid?", oracle.query(bytes(tampered)))  # → False


###################################################################
###################################################################
#############         Sample Vaudenay Oracle       ################
###################################################################
###################################################################
# 4. Implementing the Attack
class VaudenayAttack:
    def __init__(self, oracle: object):
        """
        Initialize the attack with a padding oracle.

        Parameters
        ----------
        oracle : object
            An object implementing:
              - get_ciphertext() -> bytes: returns the ciphertext (IV || body) to attack
              - query(ciphertext: bytes) -> bool: returns True if padding valid
        """
        self._oracle = oracle

    def get_ciphertext(self) -> bytes:
        """
        Fetch the target ciphertext from the oracle.

        Returns
        -------
        bytes
            The ciphertext, with the IV prepended, that the attack will recover.
        """
        return self._oracle.get_ciphertext()

    def query(self, ciphertext: bytes) -> bool:
        """
        Query the oracle to test padding validity.

        Parameters
        ----------
        ciphertext : bytes
            Ciphertext (IV || body) to submit to the padding oracle.

        Returns
        -------
        bool
            True if the decrypted plaintext has valid PKCS#7 padding; False otherwise.
        """
        return self._oracle.query(ciphertext)

    def decrypt_block(self, ct: bytes) -> bytes:
        """
        Recover a single plaintext block via the padding oracle.

        Parameters
        ----------
        ct : bytes
            A 16-byte ciphertext block to decrypt.

        Returns
        -------
        bytes
            The 16-byte plaintext block corresponding to `ct`.
        """
        raise NotImplementedError("Implement padding-oracle block decryption")

    def request_ciphertext(self) -> bytes:
        """
        Retrieve the full ciphertext to be attacked.

        Returns
        -------
        bytes
            The full ciphertext (IV || body) to decrypt block by block.
        """
        return self._oracle.get_ciphertext()

    def decrypt_ciphertext(self) -> bytes:
        """
        Perform a full CBC decryption using this block decrypt method.

        Returns
        -------
        bytes
            The recovered, unpadded plaintext for the oracle's ciphertext.

        """
        full_ct = self.request_ciphertext()
        cbc = AESCBCCipher(self.decrypt_block)  # assumes AESCBCCipher is in scope
        return cbc.decrypt(full_ct)





class CryptohackClient():
    def __init__(self, hostname, port):
        self.server_host = hostname
        self.server_port = port
        self.sock = None
        
    def connect(self):
       self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       self.sock.connect((self.server_host, self.server_port))
       
       print(f"Connected to server at {self.server_host}:{self.server_port}")
       
    def disconnect(self):
        if self.sock:
            self.sock.close()
            print("Disconnected from server.")
    
    def readline(self):
        packet = self.sock.recv(1)
        data = bytearray(packet)

        while packet and data[-1] != ord('\n'):
            packet = self.sock.recv(1)
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

    def json_recv(self):
        line = self.readline()
        return json.loads(line.decode())

    def json_send(self, data):
        request = json.dumps(data).encode()+b"\n"
        self.sock.sendall(request)

class CryptohackOracle():
    def __init__(self):
        hostname = "socket.cryptohack.org"
        port = 13421
        self.client = CryptohackClient(hostname, port)
        self.client.connect()
        self.client.readline()
		
    def query(self, ciphertext: bytes):
        ciphertext = bytes(ciphertext)
        ct = bytes.hex(ciphertext)
        request =  {"option": "unpad", "ct": ct}
        self.client.json_send(request)
        response = self.client.json_recv()['result']
        return response
    
    def get_ciphertext(self):
        request = {"option": "encrypt"}
        self.client.json_send(request)
        response = self.client.json_recv()['ct']
        return bytes.fromhex(response)
        

    def check_plaintext(self, pt: bytes):
        request = {"option": "check", "message": pt.decode()}
        self.client.json_send(request)
        response = self.client.json_recv()
        return response




#print(pt)
if __name__ == "__main__":
    print(f"{pad_msg(b'YellowFox')}")
    print("\n------------------")
    test_cbc()
    print("\n---------------")
    test_oracle()


    