import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from django.core.cache import cache


"""Cria um usuário ativo no banco de dados"""
@pytest.fixture
def usuario_ativo(db):
    return User.objects.create_user(username="testuser", password="correctpassword", is_active=True)


"""Cria um usuário inativo no banco de dados"""
@pytest.fixture
def usuario_inativo(db):
    return User.objects.create_user(username="inactiveuser", password="correctpassword", is_active=False)


"""Testa login com usuário correto e senha errada"""
@pytest.mark.django_db
def test_login_usuario_correto_senha_errada(client, usuario_ativo):
    url = reverse("login")
    response = client.post(url, {"username": "testuser", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "Senha incorreta" in response.content.decode()
    assert "sessionid" not in response.cookies  # Não deve criar sessão


"""Testa login com usuário incorreto e senha correta"""
@pytest.mark.django_db
def test_login_usuario_errado_senha_correta(client):
    url = reverse("login")
    response = client.post(url, {"username": "wronguser", "password": "correctpassword"})
    assert response.status_code == 401
    assert "Usuário não encontrado" in response.content.decode()


"""Testa login com usuário errado e senha errada"""
@pytest.mark.django_db
def test_login_usuario_errado_senha_errada(client):
    url = reverse("login")
    response = client.post(url, {"username": "wronguser", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "Usuário ou senha inválidos" in response.content.decode()


"""Testa login bem-sucedido"""
@pytest.mark.django_db
def test_login_usuario_correto_senha_correta(client, usuario_ativo):
    url = reverse("login")
    response = client.post(url, {"username": "testuser", "password": "correctpassword"})
    assert response.status_code == 200
    assert "Login realizado com sucesso" in response.content.decode()
    assert "sessionid" in response.cookies  # Sessão deve ser criada


"""Testa login de um usuário inativo"""
@pytest.mark.django_db
def test_login_usuario_inativo(client, usuario_inativo):
    url = reverse("login")
    response = client.post(url, {"username": "inactiveuser", "password": "correctpassword"})
    assert response.status_code == 403  # Bloqueado
    assert "Usuário inativo" in response.content.decode()


"""Testa diferentes entradas inválidas"""
@pytest.mark.django_db
@pytest.mark.parametrize("username, password, expected_status, expected_message", [
    ("", "", 400, "Campos obrigatórios"),  # Ambos vazios
    ("testuser", "", 400, "Senha é obrigatória"),  # Senha vazia
    ("", "correctpassword", 400, "Usuário é obrigatório"),  # Usuário vazio
    ("testuser", "wrongpassword" * 100, 400, "Senha muito longa"),  # Senha excessiva
    ("<script>alert('hack')</script>", "password", 400, "Caracteres inválidos no usuário")  # Ataque XSS
])
def test_login_inputs_invalidos(client, username, password, expected_status, expected_message):
    url = reverse("login")
    response = client.post(url, {"username": username, "password": password})
    assert response.status_code == expected_status
    assert expected_message in response.content.decode()


"""Testa múltiplas tentativas de login para verificar bloqueio"""
@pytest.mark.django_db
def test_login_multiplo_falha(client, usuario_ativo):
    url = reverse("login")

    for _ in range(5):  # Simula 5 tentativas de login com senha errada
        response = client.post(url, {"username": "testuser", "password": "wrongpassword"})
        assert response.status_code == 401

    response = client.post(url, {"username": "testuser", "password": "wrongpassword"})
    assert response.status_code == 429  # Bloqueado por muitas tentativas
    assert "Muitas tentativas, tente mais tarde" in response.content.decode()


"""Verifica se a API responde dentro de um tempo aceitável"""
@pytest.mark.django_db
def test_tempo_de_resposta_login(client, usuario_ativo):
    url = reverse("login")
    import time
    start_time = time.time()
    response = client.post(url, {"username": "testuser", "password": "correctpassword"})
    end_time = time.time()

    assert response.status_code == 200
    assert end_time - start_time < 1.0  # O login deve ser processado em menos de 1 segundo
