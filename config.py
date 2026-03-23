# ============================================================
#  config.py — настройки VK-VPN
# ============================================================
#
#  Как получить токены:
#  1. GROUP_TOKEN: Управление сообществом → Работа с API → Ключи доступа
#     Права: messages (обязательно)
#  2. USER_TOKEN:  https://vkhost.github.io/
#     Выбери «Kate Mobile» → Разреши → скопируй access_token из URL
#     Права: messages
#  3. GROUP_ID: ID твоей группы (без минуса), например 123456789
#  4. YOUR_USER_ID: твой VK user_id (узнать: vk.com/id_number в URL)
# ============================================================

import os
from dotenv import load_dotenv

load_dotenv()

# --- БОТ (bot.py, запускается на сервере) ---
GROUP_TOKEN   = os.getenv("GROUP_TOKEN")           # токен группы ВК
ALLOWED_USER  = int(os.getenv("ALLOWED_USER", 0))  # только этот user_id может слать запросы

# --- КЛИЕНТ (client.py, запускается локально) ---
USER_TOKEN    = os.getenv("USER_TOKEN")            # токен пользователя с правом messages
GROUP_ID      = int(os.getenv("GROUP_ID", 0))      # ID сообщества-бота (без минуса)

# --- ПРОКСИ ---
PROXY_HOST    = os.getenv("PROXY_HOST", "127.0.0.1")
PROXY_PORT    = int(os.getenv("PROXY_PORT", 8080))

# --- ПРОТОКОЛ ---
CHUNK_SIZE      = int(os.getenv("CHUNK_SIZE", 3500))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 45))
FETCH_TIMEOUT   = int(os.getenv("FETCH_TIMEOUT", 10))
MAX_BODY_SIZE   = int(os.getenv("MAX_BODY_SIZE", 2 * 1024 * 1024))  # 2 MB
