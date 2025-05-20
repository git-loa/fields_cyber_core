#!usr/bin/python3

# Import packages and libraries
import hashlib
import base64
import subprocess
from pathlib import Path


### 1. Encoding Binary Data for URLs


def url_format(data: bytes) -> str:
    """
    Convert a bytes sequence to its URL-encoded representation by percent
    encoding each byte.
    Each byte in the input is formatted as a two-digit hexadecimal number,
    prefixed with '%', as commonly used in URL encoding.
    Args:
    data (bytes): The input data to encode.
    Returns:
    str: A string where each byte of `data` is represented as '%XX',
    with XX being the lowercase hexadecimal value of the byte.
    Example:
    >>> url_format(b'Hello!')
    '%48%65%6c%6c%6f%21'
    """

    return "".join(f"%{b:02x}" for b in data)


def decode_url_format(url_format: str) -> bytes:
    """
    Convert url format to bytes object.

    Parameter:
        url_format (str): A url-encoded hex representation

    Returns
        bytes: A decode of url_format

    Example:
        >>> decode_url_format('%48%65%6c%6c%6f%21')
        b'Hello!'

    """
    return bytes.fromhex(url_format.replace("%", ""))


##  2. Using Hash Functions in Python


def compute_hash(message: bytes, algorithm: str = "md5", output_format: str = "bytes"):
    """
    Computes the hash of a given message using the specified algorithm.

    Parameters:
    ----------
    message : bytes
        Encoded message to be hashed.
    algorithm : str, default 'md5'
        Must be one of the following: 'md5', 'sha256', 'sha512'. Otherwise, raises a ValueError.
    output_format : str, default 'bytes'
        Must be one of the following: 'bytes', 'hex', 'base64'. Otherwise, raises a ValueError.

    Returns:
    -------
    The hash digest of the message using the given algorithm, in the given format.
    - 'bytes' returns a bytes object.
    - 'hex' returns a hexadecimal string.
    - 'base64' returns a Base64-encoded string.
    """

    # Dictionary mapping algorithms to their respective functions
    hash_funcs = {
        "md5": hashlib.md5,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }

    # Validate algorithm
    if algorithm not in hash_funcs:
        raise ValueError("Invalid algorithm. Choose from 'md5', 'sha256', or 'sha512'.")

    # Validate output format
    if output_format not in {"bytes", "hex", "base64"}:
        raise ValueError(
            "Invalid output format. Choose from 'bytes', 'hex', or 'base64'."
        )

    # Create hash object dynamically
    hash_obj = hash_funcs[algorithm]()
    hash_obj.update(message)
    digest = hash_obj.digest()
    #print(f"Type of digest = {type(digest)}")
    # Convert output format
    if output_format == "hex":
        return digest.hex()
    if output_format == "base64":
        return base64.b64encode(digest).decode("utf-8")

    return digest


## 3. Implementing Correct Padding


def compute_padding(algorithm='md5',message=None,  output_format='bytes'):
    """
    Computes padding for a given hash algorithm.

    Parameters:
    - algorithm: 'md5', 'sha256', or 'sha512'
    - output_format: 'bytes', 'hex', or 'base64'
    - message: bytes (Required)

    Returns:
    - Padding in the requested format and its length.
    """
    if message is None:
        raise ValueError("Message is required.")

    block_size = {'md5': 64, 'sha256': 64, 'sha512': 128}[algorithm]
    bit_length = len(message) * 8

    # Append the mandatory 0x80 byte
    padding = b'\x80'

    # Compute the number of zero bytes needed
    zero_padding_length = (block_size - ((len(message) + 1 + (16 if algorithm == 'sha512' else 8)) % block_size)) % block_size
    padding += b'\x00' * zero_padding_length

    # Append the length of the original message in bits
    length_bytes = bit_length.to_bytes(16 if algorithm == 'sha512' else 8, 'big')
    padding += length_bytes

    
    print(f"Padding Length: {len(padding)}")

    formatted_padding = {
        'bytes': padding,
        'hex': padding.hex(),
        'base64': base64.b64encode(padding).decode()
    }[output_format]

    return formatted_padding




# 5. Integrating Our Binary into Python
def length_extend_sha256(digest_hex: str, len_padded: int, extension_hex: str, binary: str | Path = "./length_ext",) -> str:
    """
    Run the `length_ext` C program and return the forged digest.

    Parameters---------
        digest_hex : str 
            64‑character hex SHA‑256 of `M || pad(M)`.
        len_padded : int 
            Length in **bytes** of `M || pad(M)` (must be a multiple of 64).
        extension_hex : str 
            Even‑length hex string for the data to append.
        binary : str or Path, optional
            Path to the compiled `length_ext` executable (default:./length_ext).
    Returns------
        str 64‑character hex digest of `M || pad(M) || extension`.
    """

    # Command to pass to subprocess.run()
    command = [binary, digest_hex, str(len_padded), extension_hex]
    print(f"The command is: {command}")

    try:
        output = subprocess.run(command, capture_output=True, text=True, check=True)
        
        return output.stdout.strip()
    except subprocess.CalledProcessError as cpe:
        #print(output)
        print("Error executing the length extension binary:", cpe)
        return None



#  6. Running a Length Extension Attack

def test_attack(message: bytes, extension: bytes) -> None:
    """
    Test a SHA‑256 length‑extension attack by comparing:
    1. The hash of (message || padding(message) || extension)
    2. The hash obtained via a length‑extension routine.

    Args:
    message (bytes):      The original message.
    extension (bytes):    The data to append via the length‑extension 
    attack.

    Raises:
    AssertionError: If the two hashes don’t match.
    """
    # 1) Compute the hash of (message + padding + extension)
    padding = compute_padding('sha256', message, 'bytes')
    extension_hash = compute_hash(message + padding + extension, 'sha256', 'hex')
    print(f"Conventionally computed extension hash: {extension_hash}")

    # 2) Run the length‑extension attack
    path = Path("./length_ext").resolve()
    orig_hash = compute_hash(message, 'sha256', 'hex')
    attack_hash = length_extend_sha256(
        orig_hash, 
        len(message + padding),               # original message length in bytes
        extension.hex(),                      # hex‑encoded extension          
        path       # path to your extension binary/script
    )
    print(f"Hash computed with Length Extension: {attack_hash}")

    # 3) Verify they agree
    assert extension_hash == attack_hash, "Length‑extension attack failed: hashes differ"


if __name__ == "__main__":
    #Example usage
    message = b"hello"
    padding_result = compute_padding("sha256",message, "hex")
    print(f"Padding Data: {padding_result}")

    test_attack(b"Hello", b"4578747261206d7367")
    

