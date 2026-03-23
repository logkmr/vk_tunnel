#!/usr/bin/env python3
# ============================================================
#  client.py — локальный HTTP-прокси для VK-VPN
#  Запускать на своём устройстве
#
#  Установка:  pip install vk_api
#  Запуск:     python client.py
#  Настройка браузера: HTTP-прокси 127.0.0.1:8080
# ============================================================

import base64
import json
import logging
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

import vk_api
from vk_api.longpoll import VkLongPoll, VkEventType

from config import (
    USER_TOKEN, GROUP_ID,
    PROXY_HOST, PROXY_PORT,
    CHUNK_SIZE, REQUEST_TIMEOUT,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("VK-VPN-CLIENT")

# peer_id для группы ВК — это минус group_id
PEER_ID = -GROUP_ID


# ══════════════════════════════════════════════════════════════
# Транспортный слой: отправка запросов и приём ответов через ВК
# ══════════════════════════════════════════════════════════════

class ResponseBuffer:
    """Накапливает чанки ответа от бота и сигнализирует о готовности."""

    def __init__(self):
        self.chunks:  dict[int, str] = {}
        self.total:   Optional[int]  = None
        self.status:  Optional[int]  = None
        self.headers: dict           = {}
        self.error:   Optional[str]  = None
        self.ready    = threading.Event()

    def add_chunk(self, status: int, total: int, idx: int,
                  hdrs_b64: str, data: str) -> None:
        if self.status is None:
            self.status = status
        if self.total is None:
            self.total = total
        if hdrs_b64 != "CONT":
            try:
                self.headers = json.loads(base64.b64decode(hdrs_b64).decode())
            except Exception:
                pass
        self.chunks[idx] = data
        if len(self.chunks) == self.total:
            self.ready.set()

    def set_error(self, msg: str) -> None:
        self.error = msg
        self.ready.set()

    def assemble_body(self) -> bytes:
        full_b64 = "".join(self.chunks[i] for i in range(self.total))
        return base64.b64decode(full_b64)


class VKTransport:
    """
    Singleton. Держит одно VK-соединение и фоновый Long Poll поток,
    который раздаёт ответы бота всем ожидающим прокси-потокам.
    """

    def __init__(self):
        self.vk_session = vk_api.VkApi(token=USER_TOKEN)
        self.vk         = self.vk_session.get_api()
        # req_id → ResponseBuffer
        self._pending: dict[str, ResponseBuffer] = {}
        self._lock    = threading.Lock()

        # Запускаем фоновый Long Poll
        t = threading.Thread(target=self._longpoll_loop, daemon=True)
        t.start()
        log.info("Long Poll listener запущен (peer_id=%d)", PEER_ID)

    # ── Отправка ──────────────────────────────────────────────

    def send_http_request(
        self,
        method:  str,
        url:     str,
        headers: dict,
        body:    bytes,
    ) -> tuple[int, dict, bytes]:
        """
        Кодирует HTTP-запрос, отправляет боту через ВК и ждёт ответа.
        Возвращает (status_code, headers_dict, body_bytes).
        """
        req_id      = uuid.uuid4().hex[:8]
        headers_b64 = base64.b64encode(json.dumps(headers).encode()).decode()
        body_b64    = base64.b64encode(body).decode() if body else "NONE"

        msg = f"VPN_REQ|{req_id}|{method}|{url}|{headers_b64}|{body_b64}"

        buf = ResponseBuffer()
        with self._lock:
            self._pending[req_id] = buf

        log.info("→ %s %s  (req=%s)", method, url, req_id)

        try:
            self.vk.messages.send(
                peer_id=PEER_ID,
                message=msg,
                random_id=int(time.time() * 1000),
            )
        except Exception as e:
            with self._lock:
                self._pending.pop(req_id, None)
            raise RuntimeError(f"Не удалось отправить запрос в ВК: {e}") from e

        # Ждём, пока бот ответит (или таймаут)
        ready = buf.ready.wait(timeout=REQUEST_TIMEOUT)

        with self._lock:
            self._pending.pop(req_id, None)

        if not ready:
            raise TimeoutError(f"Бот не ответил за {REQUEST_TIMEOUT}с (req={req_id})")
        if buf.error:
            raise RuntimeError(f"Ошибка бота: {buf.error}")

        body_bytes = buf.assemble_body()
        log.info("← HTTP %d  body=%d bytes  (req=%s)",
                 buf.status, len(body_bytes), req_id)
        return buf.status, buf.headers, body_bytes

    # ── Long Poll ─────────────────────────────────────────────

    def _longpoll_loop(self) -> None:
        lp = VkLongPoll(self.vk_session)
        while True:
            try:
                for event in lp.listen():
                    if event.type != VkEventType.MESSAGE_NEW:
                        continue
                    # Сообщения ОТ группы (не наши исходящие)
                    if event.to_me and event.peer_id == PEER_ID:
                        self._dispatch(event.text.strip())
            except Exception as e:
                log.error("Long Poll упал, перезапускаю: %s", e)
                time.sleep(2)

    def _dispatch(self, text: str) -> None:
        """Разбирает входящее сообщение и передаёт данные нужному буферу."""
        if not (text.startswith("VPN_RES|") or text.startswith("VPN_ERR|")):
            return

        parts  = text.split("|", 6)
        prefix = parts[0]
        req_id = parts[1] if len(parts) > 1 else None

        with self._lock:
            buf = self._pending.get(req_id)

        if buf is None:
            return  # ответ для уже завершённого/устаревшего запроса

        if prefix == "VPN_ERR":
            buf.set_error(parts[2] if len(parts) > 2 else "unknown error")
            return

        # VPN_RES|req_id|status|total|idx|hdrs_b64|chunk_data
        if len(parts) < 7:
            return

        try:
            _, _, sc, total, idx, hdrs_b64, chunk_data = parts
            buf.add_chunk(
                status=int(sc),
                total=int(total),
                idx=int(idx),
                hdrs_b64=hdrs_b64,
                data=chunk_data,
            )
        except (ValueError, IndexError) as e:
            log.warning("Не удалось разобрать чанк (req=%s): %s", req_id, e)


# Глобальный транспорт — один на весь процесс
transport = VKTransport()


# ══════════════════════════════════════════════════════════════
# HTTP-прокси сервер
# ══════════════════════════════════════════════════════════════

# Заголовки, которые нельзя пробрасывать «как есть»
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
    "proxy-connection",
})


class VKProxyHandler(BaseHTTPRequestHandler):
    """Обрабатывает входящие запросы браузера и пересылает их через ВК."""

    server_version = "VK-VPN/0.1"

    # ── Методы без тела ───────────────────────────────────────

    def do_GET(self):
        self._proxy(body=b"")

    def do_HEAD(self):
        self._proxy(body=b"")

    def do_DELETE(self):
        self._proxy(body=b"")

    def do_OPTIONS(self):
        self._proxy(body=b"")

    # ── Методы с телом ────────────────────────────────────────

    def do_POST(self):
        self._proxy(body=self._read_body())

    def do_PUT(self):
        self._proxy(body=self._read_body())

    def do_PATCH(self):
        self._proxy(body=self._read_body())

    # ── CONNECT (HTTPS-туннель) — пока не поддерживается ──────

    def do_CONNECT(self):
        self.send_error(
            501,
            "HTTPS (CONNECT) не поддерживается в этом прокси.\n"
            "Используй HTTP или отключи HSTS в браузере для тестов.",
        )

    # ── Внутренние методы ─────────────────────────────────────

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _clean_headers(self) -> dict:
        return {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in HOP_BY_HOP
        }

    def _proxy(self, body: bytes) -> None:
        url = self.path

        # Если браузер шлёт только путь (без схемы), восстанавливаем URL
        if not url.startswith("http"):
            host = self.headers.get("Host", "")
            url  = f"http://{host}{self.path}"

        headers = self._clean_headers()

        try:
            status, resp_headers, resp_body = transport.send_http_request(
                method=self.command,
                url=url,
                headers=headers,
                body=body,
            )
        except TimeoutError as e:
            self.send_error(504, str(e))
            return
        except Exception as e:
            self.send_error(502, str(e))
            return

        # Отправляем ответ браузеру
        self.send_response(status)
        for key, val in resp_headers.items():
            if key.lower() not in HOP_BY_HOP:
                try:
                    self.send_header(key, val)
                except Exception:
                    pass  # некоторые заголовки ломают BaseHTTP — пропускаем
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        log.debug("PROXY %s — %s", self.address_string(), fmt % args)


# ══════════════════════════════════════════════════════════════
# Точка входа
# ══════════════════════════════════════════════════════════════

def main() -> None:
    server = HTTPServer((PROXY_HOST, PROXY_PORT), VKProxyHandler)
    log.info(
        "VK-VPN Proxy запущен: http://%s:%d\n"
        "Настрой браузер: HTTP-прокси  %s:%d",
        PROXY_HOST, PROXY_PORT, PROXY_HOST, PROXY_PORT,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Остановлено.")
        server.server_close()


if __name__ == "__main__":
    main()
