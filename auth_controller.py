from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_connection
import psycopg2.extras
import time

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')



tentativas_login = {}


BLOQUEIO_TEMPO = 600
LIMITE_TENTATIVAS = 3



@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.json
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    if not nome or not email or not senha:
        return jsonify({"error": "Preencha todos os campos."}), 400

    senha_hash = generate_password_hash(senha)

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (nome, email, senha) VALUES (%s, %s, %s)",
            (nome, email, senha_hash)
        )
        conn.commit()
        return jsonify({"message": "Usuário criado com sucesso!"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": f"Erro ao criar usuário: {str(e)}"}), 400
    finally:
        cursor.close()
        conn.close()



@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({"error": "Email e senha são obrigatórios."}), 400

    agora = time.time()
    usuario_tentativa = tentativas_login.get(email)

    
    if usuario_tentativa and 'bloqueado_ate' in usuario_tentativa:
        if agora < usuario_tentativa['bloqueado_ate']:
            tempo_restante = int(usuario_tentativa['bloqueado_ate'] - agora)
            return jsonify({
                "error": f"Usuário bloqueado. Tente novamente em {tempo_restante} segundos."
            }), 403
        else:
            
            tentativas_login[email] = {"tentativas": 0}

    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user['senha'], senha):
        
        tentativas_login[email] = {"tentativas": 0}
        return jsonify({
            "message": "Login bem-sucedido!",
            "usuario": {
                "id": user['id'],
                "nome": user['nome'],
                "email": user['email']
            }
        }), 200
    else:
        
        if not usuario_tentativa:
            tentativas_login[email] = {"tentativas": 1}
        else:
            tentativas_login[email]['tentativas'] += 1

        tentativas = tentativas_login[email]['tentativas']

        if tentativas >= LIMITE_TENTATIVAS:
            tentativas_login[email]['bloqueado_ate'] = agora + BLOQUEIO_TEMPO
            return jsonify({
                "error": "Muitas tentativas falhas. Conta bloqueada por 10 minutos."
            }), 403

        return jsonify({
            "error": f"Credenciais inválidas. Tentativa {tentativas}/{LIMITE_TENTATIVAS}."
        }), 401



@auth_bp.route('/recuperar-senha', methods=['POST'])
def recuperar_senha():
    data = request.json
    email = data.get('email')
    nova_senha = data.get('nova_senha')

    if not email or not nova_senha:
        return jsonify({"error": "Informe o email e a nova senha."}), 400

    nova_senha_hash = generate_password_hash(nova_senha)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET senha = %s WHERE email = %s", (nova_senha_hash, email))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Senha atualizada com sucesso!"}), 200



@auth_bp.route('/logout', methods=['POST'])
def logout():
    return jsonify({"message": "Logout efetuado com sucesso!"}), 200



@auth_bp.route('/me', methods=['GET'])
def me():
    return jsonify({
        "id": 1,
        "nome": "Usuário Exemplo",
        "email": "usuario@teste.com"
    }), 200
