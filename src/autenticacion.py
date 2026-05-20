"""
Módulo 4: Autenticación de Usuarios
Sistema de Notas Universitarias — Sprint 2
"""

import hashlib
import secrets
import sqlite3
import os


# ==============================
# VARIABLES DE ENTORNO
# ==============================
# export ADMIN_PASSWORD="admin1234"
# export DB_SECRET_KEY="clave_secreta"

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

DB_SECRET_KEY = os.environ.get("DB_SECRET_KEY")

if not ADMIN_PASSWORD:
    raise ValueError("ADMIN_PASSWORD no configurada")

if not DB_SECRET_KEY:
    raise ValueError("DB_SECRET_KEY no configurada")

# ==============================
# HASH SEGURO SHA-256 + SALT
# ==============================
def _hash_password(password: str) -> str:
    """
    Genera hash seguro SHA-256 + salt.
    """

    salt = secrets.token_hex(16)

    hashed = hashlib.sha256(
        (salt + password).encode()
    ).hexdigest()

    return f"{salt}${hashed}"


def _verify_password(password: str, stored_password: str) -> bool:
    """
    Verifica password usando salt almacenado.
    """

    try:
        salt, saved_hash = stored_password.split("$")

        hashed = hashlib.sha256(
            (salt + password).encode()
        ).hexdigest()

        return hashed == saved_hash

    except ValueError:
        return False


# ==============================
# BASE DE DATOS
# ==============================
def inicializar_db(db_path: str) -> None:
    """
    Crea la tabla de usuarios si no existe.
    """
    conn = sqlite3.connect(db_path)

    try:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                rol TEXT DEFAULT 'estudiante'
            )
        """)

        conn.commit()

    finally:
        conn.close()


# ==============================
# REGISTRO DE USUARIOS
# ==============================
def registrar_usuario(
    username: str,
    password: str,
    db_path: str,
    rol: str = "estudiante"
) -> bool:

    hashed = _hash_password(password)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # CONSULTA SEGURA
        cursor.execute(
            """
            INSERT INTO usuarios (username, password, rol)
            VALUES (?, ?, ?)
            """,
            (username, hashed, rol)
        )

        conn.commit()
        return True

    except sqlite3.Error as e:
        print(f"Error al registrar usuario: {e}")
        return False

    finally:
        conn.close()


# ==============================
# LOGIN
# ==============================
def login(username: str, password: str, db_path: str) -> dict:
    """
    Autentica usuario usando consultas seguras.
    """

    user = None

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        query = """
            SELECT id, username, password, rol
            FROM usuarios
            WHERE username = ?
        """

        cursor.execute(query, (username,))

        row = cursor.fetchone()

        conn.close()

        if row:
            user_id, user_name, stored_password, rol = row

            if _verify_password(password, stored_password):

                user = {
                    "id": user_id,
                    "username": user_name,
                    "rol": rol
                }

    except sqlite3.Error as e:
        print(f"Error de autenticación: {e}")

    return {
        "autenticado": user is not None,
        "usuario": user
    }


# ==============================
# TOKEN DE SESIÓN SEGURO
# ==============================
def generar_token_sesion(username: str) -> str:
    """
    Genera token seguro.
    """

    token = secrets.token_hex(32)

    return f"{username}:{token}"


# ==============================
# CAMBIO DE PASSWORD
# ==============================
def cambiar_password(
    username: str,
    nueva_password: str,
    db_path: str
) -> bool:

    hashed = _hash_password(nueva_password)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # CONSULTA SEGURA
        query = """
            UPDATE usuarios
            SET password = ?
            WHERE username = ?
        """

        cursor.execute(query, (hashed, username))

        conn.commit()

        return True

    except sqlite3.Error as e:
        print(f"Error al cambiar contraseña: {e}")
        return False

    finally:
        conn.close()


# ==============================
# VALIDAR ADMINISTRADOR
# ==============================
def es_administrador(username: str, db_path: str) -> bool:
    """
    Verifica si el usuario es administrador.
    """

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # CONSULTA SEGURA
        query = """
            SELECT rol
            FROM usuarios
            WHERE username = ?
        """

        cursor.execute(query, (username,))

        row = cursor.fetchone()

        if row and row[0] == "admin":
            return True

    except sqlite3.Error as e:
        print(f"Error al validar administrador: {e}")

    finally:
        conn.close()

    return False
