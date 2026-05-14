"""
Pruebas unitarias — Módulo autenticacion
Sistema de Notas Universitarias — Sprint 2
"""

import os
import pytest
from src.autenticacion import (
    _hash_password,
    inicializar_db,
    registrar_usuario,
    login,
    generar_token_sesion,
    cambiar_password,
    es_administrador,
    ADMIN_PASSWORD,
    DB_SECRET_KEY,
)


# ─────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path):
    """Base de datos SQLite temporal, inicializada y limpia para cada test."""
    path = str(tmp_path / "test_usuarios.db")
    inicializar_db(path)
    return path


@pytest.fixture
def db_con_usuario(db_path):
    """Base de datos con un estudiante y un admin pre-registrados."""
    registrar_usuario("estudiante1", "password123", db_path, "estudiante")
    registrar_usuario("admin", ADMIN_PASSWORD, db_path, "admin")
    return db_path


# ─────────────────────────────────────────────
#  Tests: _hash_password
# ─────────────────────────────────────────────

class TestHashPassword:

    def test_retorna_string(self):
        assert isinstance(_hash_password("test"), str)

    def test_hash_contiene_salt_y_hash(self):
        resultado = _hash_password("cualquier_password")
        assert isinstance(resultado, str)
        assert "$" in resultado

    def test_mismo_input_genera_hashes_distintos_por_salt(self):
        assert _hash_password("abc") != _hash_password("abc")

    def test_diferente_input_diferente_output(self):
        assert _hash_password("abc") != _hash_password("xyz")

    def test_string_vacio(self):
        resultado = _hash_password("")
        assert isinstance(resultado, str)
        assert "$" in resultado


# ─────────────────────────────────────────────
#  Tests: inicializar_db
# ─────────────────────────────────────────────

class TestInicializarDB:

    def test_crea_archivo_de_base_de_datos(self, tmp_path):
        path = str(tmp_path / "nueva.db")
        inicializar_db(path)
        assert os.path.exists(path)

    def test_llamada_doble_no_lanza_excepcion(self, tmp_path):
        path = str(tmp_path / "doble.db")
        inicializar_db(path)
        inicializar_db(path)


# ─────────────────────────────────────────────
#  Tests: registrar_usuario
# ─────────────────────────────────────────────

class TestRegistrarUsuario:

    def test_registro_exitoso_retorna_true(self, db_path):
        assert registrar_usuario("nuevo", "pass123", db_path) is True

    def test_usuario_duplicado_retorna_false(self, db_path):
        registrar_usuario("usuario1", "pass", db_path)
        assert registrar_usuario("usuario1", "otro_pass", db_path) is False

    def test_registro_con_rol_admin(self, db_path):
        resultado = registrar_usuario("root", "admin1234", db_path, "admin")
        assert resultado is True


# ─────────────────────────────────────────────
#  Tests: login
# ─────────────────────────────────────────────

class TestLogin:

    def test_credenciales_correctas_retorna_autenticado(self, db_con_usuario):
        resultado = login("estudiante1", "password123", db_con_usuario)
        assert resultado["autenticado"] is True

    def test_resultado_contiene_username(self, db_con_usuario):
        resultado = login("estudiante1", "password123", db_con_usuario)
        assert resultado["usuario"]["username"] == "estudiante1"

    def test_resultado_contiene_rol(self, db_con_usuario):
        resultado = login("estudiante1", "password123", db_con_usuario)
        assert resultado["usuario"]["rol"] == "estudiante"

    def test_password_incorrecta_no_autentica(self, db_con_usuario):
        resultado = login("estudiante1", "password_mal", db_con_usuario)
        assert resultado["autenticado"] is False
        assert resultado["usuario"] is None

    def test_usuario_inexistente_no_autentica(self, db_con_usuario):
        resultado = login("noexiste", "pass", db_con_usuario)
        assert resultado["autenticado"] is False

    def test_admin_se_autentica_correctamente(self, db_con_usuario):
        resultado = login("admin", ADMIN_PASSWORD, db_con_usuario)
        assert resultado["autenticado"] is True
        assert resultado["usuario"]["rol"] == "admin"


# ─────────────────────────────────────────────
#  Tests: generar_token_sesion
# ─────────────────────────────────────────────

class TestGenerarTokenSesion:

    def test_token_empieza_con_username(self):
        token = generar_token_sesion("ana")
        assert token.startswith("ana:")

    def test_token_tiene_64_chars_hex_despues_del_prefijo(self):
        username = "usuario"
        token = generar_token_sesion(username)
        parte_token = token[len(username) + 1:]
        assert len(parte_token) == 64

    def test_tokens_consecutivos_son_distintos(self):
        tokens = {generar_token_sesion("ana") for _ in range(20)}
        assert len(tokens) > 1

    def test_token_es_string(self):
        assert isinstance(generar_token_sesion("juan"), str)


# ─────────────────────────────────────────────
#  Tests: cambiar_password
# ─────────────────────────────────────────────

class TestCambiarPassword:

    def test_cambio_exitoso_retorna_true(self, db_con_usuario):
        assert cambiar_password("estudiante1", "nueva_pass", db_con_usuario) is True

    def test_login_con_password_nueva_funciona(self, db_con_usuario):
        cambiar_password("estudiante1", "nueva_pass", db_con_usuario)
        resultado = login("estudiante1", "nueva_pass", db_con_usuario)
        assert resultado["autenticado"] is True

    def test_login_con_password_vieja_falla_tras_cambio(self, db_con_usuario):
        cambiar_password("estudiante1", "nueva_pass", db_con_usuario)
        resultado = login("estudiante1", "password123", db_con_usuario)
        assert resultado["autenticado"] is False


# ─────────────────────────────────────────────
#  Tests: es_administrador
# ─────────────────────────────────────────────

class TestEsAdministrador:

    def test_admin_es_reconocido(self, db_con_usuario):
        assert es_administrador("admin", db_con_usuario) is True

    def test_estudiante_no_es_admin(self, db_con_usuario):
        assert es_administrador("estudiante1", db_con_usuario) is False

    def test_usuario_inexistente_no_es_admin(self, db_con_usuario):
        assert es_administrador("fantasma", db_con_usuario) is False


# ─────────────────────────────────────────────
#  Tests: constantes hardcodeadas (S6437)
# ─────────────────────────────────────────────

class TestConstantesHardcodeadas:

    def test_admin_password_es_string_no_vacio(self):
        assert isinstance(ADMIN_PASSWORD, str) and len(ADMIN_PASSWORD) > 0

    def test_db_secret_key_es_string_no_vacio(self):
        assert isinstance(DB_SECRET_KEY, str) and len(DB_SECRET_KEY) > 0
