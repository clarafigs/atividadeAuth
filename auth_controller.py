from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_connection

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.json
    nome = data.get('nome')
    email = data.get('email')
    senha = generate_password_hash(data.get('senha'))

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (nome, email, senha) VALUES (?, ?, ?)", (nome, email, senha))
        conn.commit()
        return jsonify({"message": "Usuário criado com sucesso!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        conn.close()


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    senha = data.get('senha')

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user['senha'], senha):
        return jsonify({"message": "Login bem-sucedido!"})
    return jsonify({"error": "Credenciais inválidas"}), 401


@auth_bp.route('/recuperar-senha', methods=['POST'])
def recuperar_senha():
    data = request.json
    email = data.get('email')
    nova_senha = generate_password_hash(data.get('nova_senha'))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET senha = ? WHERE email = ?", (nova_senha, email))
    conn.commit()
    conn.close()

    return jsonify({"message": "Senha atualizada com sucesso!"})


@auth_bp.route('/logout', methods=['POST'])
def logout():
    return jsonify({"message": "Logout efetuado com sucesso!"})


@auth_bp.route('/me', methods=['GET'])
def me():
    
    return jsonify({
        "id": 1,
        "nome": "Usuário Exemplo",
        "email": "usuario@teste.com"
    })
