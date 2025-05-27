# password_utils.py
import random
import string
import re

# Parola Üretici (Güvenli Parola Oluşturma)
def generate_password(length=12):
    # Kullanılacak karakterler (büyük harf, küçük harf, rakamlar, özel karakterler)
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Parola Gücü Değerlendirici
def evaluate_password_strength(password):
    # Parola uzunluğu kontrolü
    length_check = len(password) >= 8
    # Büyük harf kontrolü
    upper_check = bool(re.search(r'[A-Z]', password))
    # Küçük harf kontrolü
    lower_check = bool(re.search(r'[a-z]', password))
    # Rakam kontrolü
    digit_check = bool(re.search(r'\d', password))
    # Özel karakter kontrolü
    special_check = bool(re.search(r'[@$!%*?&]', password))

    # Şifrenin güçlü olup olmadığını kontrol et
    if all([length_check, upper_check, lower_check, digit_check, special_check]):
        return "Güçlü"
    elif all([length_check, upper_check, lower_check]):
        return "Orta"
    else:
        return "Zayıf"
