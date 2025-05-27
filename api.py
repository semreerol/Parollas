from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from config import DB_CONFIG
from encryption import encrypt_password, decrypt_password
from password_utils import generate_password, evaluate_password_strength
import psycopg2
import re
from datetime import timedelta

app = Flask(__name__)
CORS(app) 

# JWT ayarları
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Güvenli bir secret key kullanın
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_ERROR_MESSAGE_KEY'] = 'error'
jwt = JWTManager(app)

@jwt.invalid_token_loader
def invalid_token_callback(error_string):
    return jsonify({
        'error': 'Invalid token',
        'message': error_string
    }), 401

@jwt.unauthorized_loader
def unauthorized_callback(error_string):
    return jsonify({
        'error': 'No token provided',
        'message': error_string
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_data):
    return jsonify({
        'error': 'Token has expired',
        'message': 'Please log in again'
    }), 401

@jwt.user_identity_loader
def user_identity_lookup(user):
    return str(user)

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return identity

def get_db_connection():
    connection = psycopg2.connect(
        dbname=DB_CONFIG['dbname'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        host=DB_CONFIG['host'],
        port=DB_CONFIG['port'],
        options='-c client_encoding=UTF8'
    )
    return connection

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    security_question = data.get('securityQuestion')
    security_answer = data.get('securityAnswer')

    if not all([email, password, security_question, security_answer]):
        return jsonify({'error': 'Tüm alanları doldurun'}), 400

    # E-posta formatı kontrolü
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return jsonify({'error': 'Geçersiz e-posta formatı'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # E-posta kontrolü
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({'error': 'Bu e-posta adresi zaten kayıtlı'}), 400

        encrypted_password = encrypt_password(password)
        
        cur.execute(
            "INSERT INTO users (email, password_hash, security_question, security_answer) VALUES (%s, %s, %s, %s)",
            (email, encrypted_password, security_question, security_answer)
        )
        conn.commit()
        
        return jsonify({'message': 'Kayıt başarılı'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'error': 'E-posta ve şifre gerekli'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            return jsonify({'error': 'Kullanıcı bulunamadı'}), 404

        user_id, stored_hash = user
        decrypted_password = decrypt_password(stored_hash)

        if password == decrypted_password:
            # Debug prints
            print(f"User ID type: {type(user_id)}, value: {user_id}")
            
            # Ensure user_id is string and create token
            user_id_str = str(user_id)
            print(f"Converted user ID type: {type(user_id_str)}, value: {user_id_str}")
            
            access_token = create_access_token(identity=user_id_str)
            print(f"Created token for user: {user_id_str}")
            
            return jsonify({
                'message': 'Giriş başarılı',
                'access_token': access_token,
                'user_id': user_id_str
            }), 200
        else:
            return jsonify({'error': 'Geçersiz şifre'}), 401

    except Exception as e:
        print(f"Login error: {str(e)}")  # Debug print
        return jsonify({'error': str(e)}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.route('/api/generate-password', methods=['GET'])
def generate_password_endpoint():
    try:
        password = generate_password(16)  # 16 karakterlik güçlü şifre oluştur
        return jsonify({'password': password})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/evaluate-password', methods=['POST'])
def evaluate_password_endpoint():
    data = request.get_json()
    password = data.get('password')
    
    if not password:
        return jsonify({'error': 'Şifre gerekli'}), 400
        
    strength = evaluate_password_strength(password)
    return jsonify({'strength': strength})

@app.route('/api/passwords', methods=['GET'])
@jwt_required()
def get_passwords():
    user_id = get_jwt_identity()
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, title, username, password, url, notes FROM passwords WHERE user_id = %s",
            (user_id,)
        )
        passwords = cur.fetchall()
        return jsonify([{
            'id': p[0],
            'title': p[1],
            'username': p[2],
            'password': decrypt_password(p[3]),
            'url': p[4],
            'notes': p[5]
        } for p in passwords])
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/passwords', methods=['POST'])
@jwt_required()
def add_password():
    try:
        # Get user ID from JWT token
        user_id = get_jwt_identity()
        print(f"User ID from token: {user_id}")  # Debug print
        
        # Get and validate request data
        data = request.get_json()
        print(f"Received data: {data}")  # Debug print
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        required_fields = ['title', 'username', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            encrypted_password = encrypt_password(data['password'])
            
            cur.execute(
                """
                INSERT INTO passwords (user_id, title, username, password, url, notes)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    user_id,
                    data['title'],
                    data['username'],
                    encrypted_password,
                    data.get('url', ''),
                    data.get('notes', '')
                )
            )
            
            new_id = cur.fetchone()[0]
            conn.commit()
            
            return jsonify({
                'message': 'Şifre başarıyla eklendi',
                'id': new_id
            }), 201

        except Exception as e:
            print(f"Database error: {str(e)}")  # Debug print
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        finally:
            if 'cur' in locals():
                cur.close()
            if 'conn' in locals():
                conn.close()

    except Exception as e:
        print(f"General error: {str(e)}")  # Debug print
        return jsonify({'error': str(e)}), 500

@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
@jwt_required()
def delete_password(password_id):
    user_id = get_jwt_identity()
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Önce şifrenin kullanıcıya ait olduğunu kontrol et
        cur.execute(
            "SELECT id FROM passwords WHERE id = %s AND user_id = %s",
            (password_id, user_id)
        )
        if not cur.fetchone():
            return jsonify({'error': 'Şifre bulunamadı veya erişim izniniz yok'}), 404
        
        cur.execute("DELETE FROM passwords WHERE id = %s", (password_id,))
        conn.commit()
        
        return jsonify({'message': 'Şifre başarıyla silindi'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/passwords/<int:password_id>', methods=['PUT'])
@jwt_required()
def update_password(password_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Önce şifrenin kullanıcıya ait olduğunu kontrol et
        cur.execute(
            "SELECT id FROM passwords WHERE id = %s AND user_id = %s",
            (password_id, user_id)
        )
        if not cur.fetchone():
            return jsonify({'error': 'Şifre bulunamadı veya erişim izniniz yok'}), 404
        
        # Şifre değiştirilmişse şifrele
        if 'password' in data:
            data['password'] = encrypt_password(data['password'])
        
        # Güncelleme sorgusu
        update_fields = []
        values = []
        for key, value in data.items():
            if key in ['title', 'username', 'password', 'url', 'notes']:
                update_fields.append(f"{key} = %s")
                values.append(value)
        
        if not update_fields:
            return jsonify({'error': 'Güncellenecek alan yok'}), 400
        
        values.append(password_id)
        query = f"""
            UPDATE passwords 
            SET {', '.join(update_fields)}
            WHERE id = %s AND user_id = %s
        """
        values.append(user_id)
        
        cur.execute(query, values)
        conn.commit()
        
        return jsonify({'message': 'Şifre başarıyla güncellendi'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/forgot-password/email', methods=['POST'])
def forgot_password_email():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'E-posta adresi gerekli'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # E-posta ve güvenlik sorusunu kontrol et
        cur.execute(
            "SELECT security_question FROM users WHERE email = %s",
            (email,)
        )
        result = cur.fetchone()
        
        if not result:
            return jsonify({'error': 'Bu e-posta adresi sistemde kayıtlı değil'}), 404
            
        return jsonify({
            'message': 'Güvenlik sorusu bulundu',
            'security_question': result[0]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/forgot-password/verify', methods=['POST'])
def verify_security_answer():
    data = request.get_json()
    email = data.get('email')
    security_answer = data.get('security_answer')
    
    if not all([email, security_answer]):
        return jsonify({'error': 'Tüm alanları doldurun'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Güvenlik sorusu cevabını kontrol et
        cur.execute(
            "SELECT id FROM users WHERE email = %s AND security_answer = %s",
            (email, security_answer)
        )
        if not cur.fetchone():
            return jsonify({'error': 'Güvenlik sorusu cevabı yanlış'}), 401
            
        return jsonify({'message': 'Güvenlik sorusu doğrulandı'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/forgot-password/reset', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    security_answer = data.get('security_answer')
    new_password = data.get('new_password')
    
    if not all([email, security_answer, new_password]):
        return jsonify({'error': 'Tüm alanları doldurun'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Güvenlik sorusu cevabını tekrar kontrol et
        cur.execute(
            "SELECT id FROM users WHERE email = %s AND security_answer = %s",
            (email, security_answer)
        )
        if not cur.fetchone():
            return jsonify({'error': 'Güvenlik sorusu cevabı yanlış'}), 401
        
        # Yeni şifreyi şifrele ve güncelle
        encrypted_password = encrypt_password(new_password)
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s",
            (encrypted_password, email)
        )
        conn.commit()
        
        return jsonify({'message': 'Şifre başarıyla güncellendi'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True) 