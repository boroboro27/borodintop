import base64
from email import message
import json
from typing import Optional
import hmac
import hashlib
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import HTMLResponse, Response

app = FastAPI()

# openssl rand -hex 32 - генерирует хэш
SECRET_KEY = 'aeca6bfb96e2a24d06b1e4b1552f5a3b4adf967b91f15a7f68aecba55838c03d'
PASSWORD_SALT = 'da61b99fa963164d96c6f1075896eebe71e78c1eb4c04ac7fb8ac09aac0bf3c5'


def sign_data(data: str) -> str:
    """Возвращает подписанные данные

    Args:
        data (str): данные для подписи

    Returns:
        str: подписанные данные
    """
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_singed_string(username_signed: str) -> Optional[str]:
    """Возвращает имя пользователя из зашифрованной строки

    Args:
        username_signed (str): зашифрованная строка

    Returns:
        Optional[str]: имя пользователя
    """
    try:
        username_base64, sign = username_signed.split('.')
    except ValueError:
        return None
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    """Проверяет, что пароль верный

    Args:
        username (str): имя пользователя
        pasword_hash (str): пароль для проверки

    Returns:
        bool: да/нет
    """

    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()) \
                    .hexdigest().lower()
    password_hash_stored = users[username]['password'].lower()
    return  password_hash == password_hash_stored


users = {
    "ruslan@mail.ru": {
        "name": "Руслан",
        "password": "772cd64df7d34ceadda0ebafdc42c97d6d9208a01d735ad620c450fe1bc29a5f",
        "balance": 100_000
    },
    "olga@mail.ru": {
        "name": "Ольга",
        "password": "a75295f27a47d9dd600e9d819f6dac3837d26db4652b6dcb6988ce07bcbeddf8",
        "balance": 200_555
    }
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_singed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key='username')
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key='username')
        return response
    return Response(f"Привет, {user['name']}!<br />Ваш баланс: {user['balance']}.", 
                    media_type="text/html"
    )


@app.post("/login")
#def process_login_page(username: str = Form(str), password: str = Form(str)):
def process_login_page(data: dict = Body(...)):    
    username = data['username']
    password = data['password']
    user = users.get(username)

    if not user or not verify_password(username=username, password=password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю!"
            }), 
            media_type="application/json"
        )

    response = Response(
        json.dumps({
                "success": True,
                "message": f"Привет, {user['name']}!<br />Ваш баланс: {user['balance']}."
            }), 
            media_type="application/json"
    )
    username_signed = base64.b64encode(username.encode()).decode() + "." + \
                      sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
