<div align="center">
  
  # Telegram WS Proxy CLI
<br>
  <img src="https://img.shields.io/badge/Rust-1.90+-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust Version">
<br>
</div>

**TG WS Proxy CLI** — это локальный **MTProto-прокси** для Telegram. Программа помогает частично решать проблемы и в ряде сценариев ускоряет работу мессенджера, перенаправляя трафик через защищённые Cloudflare WebSocket-соединения или напрямую к датацентрам Telegram.

---

## Возможности

- Локальный MTProto-прокси для Telegram.
- Передача трафика через Cloudflare WebSocket или напрямую к Telegram DC.

---

## Как это работает

```text
Telegram → TG WS Proxy CLI → WSS (через CloudFlare или напрямую) → Telegram DC
```

1. Программа поднимает локальный MTProto-прокси средствами нативного движка на языке **Rust**.
2. Перехватывает подключения Telegram через локальный порт и сгенерированный секретный ключ.
3. Извлекает `DC ID` из исходного пакета и устанавливает защищённое WebSocket (`TLS`) соединение с нужным датацентром, при необходимости проксируя трафик через CloudFlare.
4. Использует пул соединений, keepalive-механику и fallback-сценарии для более устойчивой работы в реальных сетевых условиях.

## Быстрый старт

1. Скачайте бинарный файл со страницы Releases.
2. Запустите его.

```bash
chmod +x tg-ws-proxy-cli
./tg-ws-proxy-cli
```

После запуска программа выведет параметры локального MTProto-прокси:

```text
  Адрес: 127.0.0.1
  Порт: 1443
  Secret: xxxxxxxxxxxxxxxxxxxxx
```

Добавьте эти параметры в Telegram.

## Использование

```text
Usage:
    tg-ws-proxy-cli [OPTIONS]

Options:
    -h, --help                 Show this help message
    -V, --version              Show version information

    --host <HOST>              Local listen address
    --port <PORT>              Local listen port
    --secret <SECRET>          MTProto secret
    --dc <ID:IP>               Override Telegram DC address
    --user-domains <DOMAIN>    Custom Cloudflare domain(s)
    --pool-size <SIZE>         WebSocket connection pool size
    --cache-dir <PATH>         Cache directory
    --verbose                  Enable verbose logging
    --enable-cf                Route all connections through Cloudflare
    --no-console               Disable console output
```

> [!NOTE]
> При возникновении проблем приложите лог программы и информацию о системе к вашему Issue.
> Мелкие ошибки в логах при нормально работающем прокси можно игнорировать.

---

## Благодарности

- Flowseal — оригинальная реализация TG WS Proxy (MIT)
- amurcanov — Android-версия проекта

## Лицензия

Исходный проект **TG WS Proxy** распространяется под лицензией **MIT**.

Данный форк содержит изменения, распространяемые под лицензией  **GPLv3**.