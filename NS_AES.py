from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(plaintext: str, key: bytes) -> bytes:
   
    cipher = AES.new(key, AES.MODE_ECB) 
    
    padded_text = pad(plaintext.encode(), AES.block_size)
    return cipher.encrypt(padded_text)

def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
   
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size).decode()

def to_binary(data: bytes) -> str:

    return ''.join(format(byte, '08b') for byte in data)


if __name__ == "__main__":
    password = input("Enter password: ").strip()  
    key = hashlib.sha256(password.encode()).digest()[:16]  #
    plaintext = input("Enter text to encrypt: ").strip()

   
    ciphertext = aes_encrypt(plaintext, key)

   
    print(f"Encrypted (hex): {ciphertext.hex()}")
    print(f"Encrypted (binary): {to_binary(ciphertext)}")

   
    decrypted_text = aes_decrypt(ciphertext, key)
    print(f"Decrypted text: {decrypted_text}")
