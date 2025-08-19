import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def decrypt_aes(ciphertext_hex, iv_hex, master_key):
    key_hash = SHA256.new(master_key.encode()).digest()
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    cipher = AES.new(key_hash, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    
    # Quitar padding PKCS7
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode('utf-8')

def deobfuscate_key(obfuscated_key):
    try:
        # Recortar los caracteres extra según tu JS
        trimmed = obfuscated_key[4:-16]
        # Invertir la cadena
        reversed_key = trimmed[::-1]
        # Decodificar Base64
        decoded_bytes = base64.b64decode(reversed_key)
        decoded_text = decoded_bytes.decode('utf-8')
        # Separar IV y ciphertext
        iv_hex, ciphertext = decoded_text.split(':')
        master_key = "EnRjmF8X6VZlfS4PifbJD8oWK4PaHnlZ"
        decrypted = decrypt_aes(ciphertext, iv_hex, master_key)
        return decrypted
    except Exception as e:
        print("Error:", e)
        return None

# Ejemplo de uso
obfuscated_key = "======gNjJjMjNTM0IWYlJzM0UWMihzM2kDMwcTZhFGZzQDMlFTYmljM5EzY2YzMhJWY1EWY1ETNzMmZxkzNhJTY4AzNhNGO1IzM0QTN3MGN1ImYklDZklTYjZGMjdTNwkTYlZzMiNGOyUWMlRWYzIzM3QTNlFWYiR2MzkzMjFDMmZGZxUjM4IDMhVDOxU2NxkTNhVjYkJDZ4UzN4IWO2ADMxIGN6cTN2EWNkZWZkFmNxEDN0E2N5Y2Y4UWOjVWZiVGOkJGMa1b2c3d4e5f67890"

final_key = deobfuscate_key(obfuscated_key)
print("Key desencriptada:", final_key)
