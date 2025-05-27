from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# AES-256 için anahtar oluşturma (32 byte'lık anahtar)
def get_key():
    return hashlib.sha256(b'key_for_aes_encryption').digest()  # AES-256 için 32 byte anahtar

# Parolayı AES-256 ile şifreleme
def encrypt_password(password):
    key = get_key()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    # IV (Initialization Vector) + Şifreli veri + Tag'ı birleştirip base64 formatında döndürüyoruz
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# Şifreyi AES-256 ile çözme
def decrypt_password(encrypted_password):
    key = get_key()
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:16]  # IV kısmı ilk 16 byte
    tag = encrypted_data[16:32]  # Tag kısmı sonraki 16 byte
    ciphertext = encrypted_data[32:]  # Şifreli veri
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_password.decode('utf-8')
