#!/usr/bin/env python3
# ============================================================
#  bot.py — серверная часть VK-VPN
#  Запускать на машине с нормальным интернетом
#
#  Установка:  pip install vk_api requests
#  Запуск:     python bot.py
# ============================================================

import base64
import json
import time
import logging

import requests
import vk_api
from vk_api.longpoll import VkLongPoll, VkEventType

from config import (
    GROUP_TOKEN, ALLOWED_USER,
    CHUNK_SIZE, FETCH_TIMEOUT, MAX_BODY_SIZE
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("VK-VPN-BOT")

# ──────────────────────────────────────────────
# Инициализация VK API
# ──────────────────────────────────────────────
vk_session = vk_api.VkApi(token=GROUP_TOKEN)
longpoll   = VkLongPoll(vk_session)
vk         = vk_session.get_api()


def vk_send(user_id: int, text: str) -> None:
    """Отправить сообщение пользователю, соблюдая rate-limit."""
    try:
        vk.messages.send(
            user_id=user_id,
            message=text,
            random_id=int(time.time() * 1000),
        )
    except vk_api.exceptions.ApiError as e:
        log.error("Ошибка отправки: %s", e)
        time.sleep(1)


def encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def split_chunks(text: str) -> list[str]:
    """Разбить длинную строку на куски по CHUNK_SIZE символов."""
    return [text[i : i + CHUNK_SIZE] for i in range(0, len(text), CHUNK_SIZE)]


# ──────────────────────────────────────────────
# Обработка входящего запроса
# ──────────────────────────────────────────────
def handle_vpn_request(user_id: int, raw: str) -> None:
    """
    Формат входящего сообщения:
        VPN_REQ|<req_id>|<METHOD>|<url>|<headers_b64>|<body_b64_or_NONE>
    """
    try:
        prefix, req_id, method, url, headers_b64, body_b64 = raw.split("|", 5)
    except ValueError:
        log.warning("Неверный формат запроса от %d", user_id)
        return

    log.info("→ %s %s  (req=%s)", method, url, req_id)

    # Декодируем заголовки и тело
    try:
        headers: dict = json.loads(base64.b64decode(headers_b64).decode())
        body: bytes | None = base64.b64decode(body_b64) if body_b64 != "NONE" else None
    except Exception as e:
        vk_send(user_id, f"VPN_ERR|{req_id}|Decode error: {e}")
        return

    # Убираем hop-by-hop заголовки, которые испортят запрос
    for hop in ("host", "transfer-encoding", "connection",
                "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailers", "upgrade"):
        headers.pop(hop, None)
        headers.pop(hop.title(), None)

    # Делаем запрос к целевому сайту
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            timeout=FETCH_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )
        # Читаем тело с ограничением размера
        content = resp.raw.read(MAX_BODY_SIZE, decode_content=True)

    except requests.exceptions.Timeout:
        vk_send(user_id, f"VPN_ERR|{req_id}|Timeout fetching {url}")
        return
    except Exception as e:
        vk_send(user_id, f"VPN_ERR|{req_id}|{e}")
        return

    # Формируем ответ
    status_code     = resp.status_code
    resp_headers    = dict(resp.headers)
    resp_headers_b64 = encode_b64(json.dumps(resp_headers).encode())
    body_b64_full   = encode_b64(content)

    chunks = split_chunks(body_b64_full)
    total  = len(chunks)

    log.info("← HTTP %d  body=%d bytes  chunks=%d  (req=%s)",
             status_code, len(content), total, req_id)

    # Отправляем куски:
    # Первый кусок содержит статус + заголовки ответа.
    # Остальные — только данные (hdrs_field = CONT).
    for idx, chunk in enumerate(chunks):
        hdrs_field = resp_headers_b64 if idx == 0 else "CONT"
        msg = f"VPN_RES|{req_id}|{status_code}|{total}|{idx}|{hdrs_field}|{chunk}"
        vk_send(user_id, msg)

        # ВК не любит флуд: 1 сообщение ~каждые 350 мс
        if total > 1:
            time.sleep(0.35)

    log.info("✓ Ответ отправлен (req=%s)", req_id)


# ──────────────────────────────────────────────
# Главный цикл Long Poll
# ──────────────────────────────────────────────
def main() -> None:
    log.info("VK-VPN Bot запущен. Ожидаю запросы от user_id=%d …", ALLOWED_USER)

    for event in longpoll.listen():
        if event.type != VkEventType.MESSAGE_NEW:
            continue
        if not event.to_me:
            continue

        # Фильтр: только авторизованный пользователь
        if event.user_id != ALLOWED_USER:
            log.warning("Попытка от неизвестного user_id=%d — игнорирую", event.user_id)
            continue

        text = event.text.strip()
        if text.startswith("VPN_REQ|"):
            handle_vpn_request(event.user_id, text)
        else:
            # Любое другое сообщение — подсказка
            vk_send(event.user_id,
                    "VK-VPN Bot активен.\n"
                    "Используй клиент (client.py) и настрой браузер на прокси 127.0.0.1:8080")


if __name__ == "__main__":
    main()
