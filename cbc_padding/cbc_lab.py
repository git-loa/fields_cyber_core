from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#1. Implementing PKCS7 Padding:
def pad_msg(msg: bytes, block_size: int=16) -> bytes:
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
        #Your Code here
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext is too short")
        iv = ciphertext[:16] # Assume the IV is the first 16 bytes
        encrypted_data = ciphertext[16:]
        decrypted_blocks = []
        previous_block = iv

        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i+16]
            decrypted_block = self.block_decryptor(block)
            db_xor_prev = bytes(i^j for i, j in zip(decrypted_block, previous_block))
            decrypted_blocks.append(db_xor_prev)
            previous_block = block
        decrypted_msg = b''.join(decrypted_blocks)
        return unpad_msg(decrypted_msg)


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
    messages = [b"a sample message that's more than a block", b"a sample message", b"short"]
    decryptor = (lambda block: aes_block_decrypt(key, block)) 
    cbc_cipher = AESCBCCipher(decryptor)

    for m in messages: 
        ctxt = aes_cbc_encrypt(key, m)
        assert cbc_cipher.decrypt(ctxt) == m

        
    print("All assertions passed!")

if __name__ == "__main__":
    test_cbc()