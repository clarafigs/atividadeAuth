import psycopg2

DB_HOST = "localhost"
DB_NAME = "auth"
DB_USER = "postgres"
DB_PASS = "clarapost"


def get_connection():
    """Cria a conexão com o banco PostgreSQL"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        return conn
    except Exception as e:
        print("❌ Erro ao conectar no banco:", e)
        raise


def init_db():
    """Cria tabela de usuários se não existir"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                nome VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                senha TEXT NOT NULL
            );
        """)
        conn.commit()
        print("✅ Banco inicializado com sucesso.")
    except Exception as e:
        conn.rollback()
        print("❌ Erro ao inicializar o banco:", e)
    finally:
        cursor.close()
        conn.close()
