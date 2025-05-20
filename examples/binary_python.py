
############################################################
################# 1. Bytes and Bytearray ###################
############################################################

byte_obj = bytes([65, 66, 67])  # b'ABC'
byte_array = bytearray([120, 121, 122])  # bytearray(b'xyz')

print("1. Bytes object:", byte_obj)
print("   Bytearray object:", byte_array)


############################################################
####### 2. Converting Between Bytes and Bytearray ##########
############################################################

converted_to_bytes = bytes(byte_array)
converted_to_bytearray = bytearray(byte_obj)

print("\n2. Converted to bytes:", converted_to_bytes)
print("   Converted to bytearray:", converted_to_bytearray)


############################################################
################ 3. Bitwise XOR on Integers ################
############################################################

a = 42  # 0b101010
b = 15  # 0b001111
xor_result = a ^ b  # 0b100101 => 37

print("\n3. XOR of {} and {} is: {}".format(a, b, xor_result))


############################################################
############# 4. Bitwise XOR on Bytes Objects ##############
############################################################

bytes_a = bytes([1, 2, 3])
bytes_b = bytes([3, 1, 6])
xor_bytes = bytes(i ^ j for i, j in zip(bytes_a, bytes_b))  # [2, 3, 5]

print("\n4. XOR of bytes:", xor_bytes)


############################################################
################ 6. Bit Length of an Integer ###############
############################################################

m = 1025
print("\n5. Bit length of", m, "is:", m.bit_length())

############################################################
############ 6. Integer to Bytes with to_bytes() ###########
############################################################

n = 1025
byte_len = (n.bit_length() + 7) // 8
bytes_from_int = n.to_bytes(byte_len, "big")

print("\n6. Integer to bytes:", bytes_from_int)

n1 = 1025
byte_len = (n1.bit_length() + 7) // 8
bytes_from_int = n1.to_bytes(byte_len, "little")

print("\n6.1. Integer to bytes:", bytes_from_int)


############################################################
################## 7. Bytes to Integer #####################
############################################################

recovered_int = int.from_bytes(bytes_from_int, "little")

print("\n7. Bytes back to integer:", recovered_int)


############################################################
############## 8. String <-> Bytes Conversion ##############
############################################################

original_str = "hello world"
encoded_bytes = original_str.encode("utf-8")
decoded_str = encoded_bytes.decode("utf-8")

print("\n8. String to bytes:", encoded_bytes)
print("   Bytes back to string:", decoded_str)

############################################################
################## 9. Hex String <-> Bytes #################
############################################################

hex_str = "48656c6c6f21"  # "Hello!" in hex
bytes_from_hex = bytes.fromhex(hex_str)
hex_from_bytes = bytes_from_hex.hex()

print("\n9. Hex to bytes:", bytes_from_hex)
print("   Bytes to hex:", hex_from_bytes)


############################################################
################### 10. Base64 <-> Bytes ###################
############################################################

import base64

data = b"binary data here"
b64_encoded = base64.b64encode(data)
b64_decoded = base64.b64decode(b64_encoded)

print("\n10. Base64 encoded:", b64_encoded)
print("    Base64 decoded:", b64_decoded)

############################################################
################# 11. One-Time Pad Example #################
############################################################

import os

# Message as bytes
message = b"SecretMsg"

# Generate a truly random pad of the same length
pad = os.urandom(len(message))



# Encrypt: ciphertext = message XOR pad
ciphertext = bytes(m ^ p for m, p in zip(message, pad))

# Decrypt: message = ciphertext XOR pad
decrypted = bytes(c ^ p for c, p in zip(ciphertext, pad))

print(f"\n11. One-Time Pad Example\nOriginal message: {message}\nPad (hex): {pad.hex()}\nCiphertext (hex): {ciphertext.hex()}\nDecrypted message: {decrypted}")
