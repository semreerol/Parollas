import psycopg2
from config import DB_CONFIG
from encryption import encrypt_password, decrypt_password  # AES şifreleme işlevleri
from password_utils import generate_password, evaluate_password_strength  # Parola üretici ve değerlendirici
import re
def get_db_connection():
    connection = psycopg2.connect(
        dbname=DB_CONFIG['dbname'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        host=DB_CONFIG['host'],
        port=DB_CONFIG['port'],  # Port'u unutma!
        options='-c client_encoding=UTF8'  # UTF-8 zorlaması
    )
    return connection

def register_user(email, password):
    encrypted_password = encrypt_password(password)

    # 🛡️ Güvenlik sorusu seçenekleri
    SECURITY_QUESTIONS = [
        "İlk evcil hayvanınızın adı nedir?",
        "İlkokul öğretmeninizin soyadı nedir?",
        "En sevdiğiniz yemek nedir?",
        "Doğduğunuz şehir neresidir?",
        "Annenizin kızlık soyadı nedir?",
        "En sevdiğiniz film nedir?",
        "İlk telefonunuzun markası nedir?",
    ]

    print("\n🛡️ Güvenlik Sorusu Seçin:")
    for i, question in enumerate(SECURITY_QUESTIONS, start=1):
        print(f"{i}. {question}")

    # ❓ Kullanıcıdan seçim alın
    while True:
        try:
            selected = int(input("Bir güvenlik sorusu seçin (1-7): "))
            if 1 <= selected <= len(SECURITY_QUESTIONS):
                question = SECURITY_QUESTIONS[selected - 1]
                break
            else:
                print("⚠️ Lütfen 1 ile 7 arasında bir sayı girin.")
        except ValueError:
            print("⚠️ Lütfen geçerli bir sayı girin.")

    # 🔐 Cevap al
    answer = input("Cevabınız: ").strip().lower()

    # 💾 Veritabanına kayıt
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (email, password_hash, security_question, security_answer) VALUES (%s, %s, %s, %s)",
        (email, encrypted_password, question, answer)
    )
    conn.commit()
    cur.close()
    conn.close()

    print("✅ Kullanıcı başarıyla kaydedildi!\n")

def login_user(email, password):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT password_hash, security_question, security_answer FROM users WHERE email = %s", (email,))
    result = cur.fetchone()

    if not result:
        print("❌ Bu e-posta adresi sistemde kayıtlı değil. Lütfen önce kayıt olun.\n")
        cur.close()
        conn.close()
        return

    stored_hash = result[0]
    security_question = result[1]
    correct_answer = result[2]
    attempt_count = 0

    while attempt_count < 3:
        decrypted_password = decrypt_password(stored_hash)
        if password == decrypted_password:
            print("✅ Giriş başarılı!\n")
            break
        else:
            attempt_count += 1
            if attempt_count == 2:
                print("⚠️ 2 kez yanlış şifre girdiniz.")
                print(f"🔐 Güvenlik Sorusu: {security_question}")
                user_answer = input("Cevabınız: ").strip().lower()
                if user_answer != correct_answer:
                    print("❌ Güvenlik cevabı hatalı. Giriş engellendi.\n")
                    break
                else:
                    print("✅ Güvenlik cevabı doğru! Son bir şifre deneme hakkınız var.")
                    password = input("Şifreyi tekrar girin: ")
            elif attempt_count < 3:
                password = input("Tekrar şifre girin: ")
            else:
                print("❌ Çok fazla deneme. Giriş başarısız.\n")
                break

    cur.close()
    conn.close()

def generate_and_evaluate_password():
    generated_password = generate_password(16)
    print("🔐 Oluşturulan Parola:", generated_password)
    password_strength = evaluate_password_strength(generated_password)
    print("🔎 Parola Gücü:", password_strength, "\n")

def get_password_choice():
    while True:
        print("\nŞifre seçimi:")
        print("1. Şifremi kendim gireceğim")
        print("2. Sistem benim için güçlü bir şifre oluştursun")
        choice = input("Seçiminiz (1/2): ").strip()

        if choice == "1":
            while True:
                print("Şifrenizi giriniz:")
                password = ""
                while True:
                    char = input("➤ Karakter ekle (Enter = bitir): ")
                    if char == "":
                        break
                    password += char
                    strength = evaluate_password_strength(password)
                    print(f"🔎 Şu anki şifre: {password}")
                    print(f"🔒 Güç: {strength}\n")

                # Kullanıcı Enter ile şifreyi bitirdikten sonra son güce göre kontrol:
                if len(password) < 4:
                    print("⚠️ Çok kısa şifre. Lütfen tekrar deneyin.\n")
                elif evaluate_password_strength(password) == "Zayıf":
                    onay = input("Şifreniz zayıf. Yine de kullanmak istiyor musunuz? (e/h): ").strip().lower()
                    if onay == "e":
                        return password
                    else:
                        print("Yeni bir şifre girin.\n")
                else:
                    return password

        elif choice == "2":
            password = generate_password(16)
            print("🔐 Oluşturulan Parola:", password)
            strength = evaluate_password_strength(password)
            print("🔎 Parola Gücü:", strength)
            return password

        else:
            print("⚠️ Geçersiz seçim, lütfen 1 ya da 2 girin.")

def main():
    while True:
        print("===== MENÜ =====")
        print("1. Kayıt Ol")
        print("2. Giriş Yap")
        print("3. Çıkış")
        choice = input("Bir seçenek girin (1-3): ").strip()

        if choice == "1":
            while True:
                email = input("E-posta adresinizi girin: ").strip()

                # ✅ 1. E-posta formatını kontrol et
                email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
                if not re.match(email_regex, email):
                    print("⚠️ Geçersiz e-posta formatı. Lütfen tekrar deneyin.\n")
                    continue

                # ✅ 2. Veritabanında kayıtlı mı?
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                existing_user = cur.fetchone()
                cur.close()
                conn.close()

                if existing_user:
                    print("❗ Bu e-posta adresine ait bir kullanıcı zaten mevcut. Lütfen başka bir e-posta girin.\n")
                else:
                    break  # her şey yolunda

            password = get_password_choice()
            register_user(email, password)
        elif choice == "2":
            while True:
                email = input("E-posta adresinizi girin: ").strip()

                # E-posta format kontrolü (opsiyonel ama önerilir)
                email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
                if not re.match(email_regex, email):
                    print("⚠️ Geçersiz e-posta formatı. Lütfen tekrar deneyin.\n")
                    continue

                # E-posta sistemde kayıtlı mı?
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                existing_user = cur.fetchone()
                cur.close()
                conn.close()

                if not existing_user:
                    print("❌ Bu e-posta adresi sistemde kayıtlı değil. Kayıt sayfasına yönlendiriliyorsunuz...\n")

                    # 👇 Kayıt işlemine otomatik geçiş
                    while True:
                        # tekrar aynı e-posta kullanılmasın diye email'i burada kullanabiliriz
                        print("📥 Kayıt İşlemi:")
                        new_email = email  # kullanıcıdan yeniden istemek istersen burada tekrar sorabilirsin
                        password = get_password_choice()
                        register_user(new_email, password)
                        break  # kayıt olduktan sonra çık
                    break  # giriş işleminden çık
                else:
                    break  # giriş işlemine devam edebiliriz

            # e-posta kayıtlıysa şifre sor
            password = input("Şifrenizi girin: ")
            login_user(email, password)

        elif choice == "3":
            print("👋 Programdan çıkılıyor...")
            break

        else:
            print("⚠️ Geçersiz seçenek! Lütfen 1-3 arasında bir seçim yapın.\n")

if __name__ == "__main__":
    main()





