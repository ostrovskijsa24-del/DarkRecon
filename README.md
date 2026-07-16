# DarkRecon

Консольный набор утилит для CTF / пентеста / расследований. Объединяет пять направлений:

| # | Модуль      | Назначение                                                       |
|---|-------------|------------------------------------------------------------------|
| 1 | 🌐 Web      | Сканер структуры, ответы/Cookie/JWT, CORS, поддомены, DNS, Wayback |
| 2 | 🔎 OSINT    | Поиск никнеймов и репозиториев, WHOIS & GeoIP                    |
| 3 | 🖼️ Stego    | Битовые плоскости, XOR, статистика, палитра, PNG, аудио (WAV)     |
| 4 | 🔐 Crypto   | Авто-декодер: Base64/Hex/Цезарь/ROT/Affine/XOR                   |
| 5 | 🧪 Forensics| Сигнатуры, энтропия, строки, хеши, карвинг                       |

## Запуск

```bash
pip install -r requirements.txt
python main.py
```

## Архитектура

Проект разбит на **два слоя**:

- **`modules/`** — чистая бизнес-логика. Каждый модуль принимает входные данные и
  возвращает результат (dict / list / ndarray). Никакого вывода в консоль,
  интерактивных меню или захардкоженных путей сохранения.
- **`tui/`** — вся презентация. `runners_*.py` запрашивают ввод у пользователя
  (через `rich` Prompt/Confirm), вызывают бизнес-логику и передают результат в
  `reports_*.py`, где он выводится цветным форматированием через `rich Console`.

## Структура проекта

```
main.py                       # точка входа: главное меню + диспетчер
tui/                          # консольный интерфейс (presentation layer)
  menus.py                    #   отрисовка меню
  handlers.py                 #   циклы подменю (dispatch → runners)
  reports_web.py               #   вывод отчётов Web
  reports_osint.py             #   вывод отчётов OSINT
  reports_crypto.py           #   вывод отчётов Crypto
  reports_forensics.py         #   вывод отчётов Forensics
  reports_stego.py             #   вывод отчётов Stego
  runners_web.py              #   запуск Web-модулей
  runners_osint.py             #   запуск OSINT-модулей
  runners_crypto.py           #   запуск Crypto-модуля
  runners_forensics.py         #   запуск Forensics-модуля
  runners_stego.py             #   запуск Stego-модулей
modules/                       # бизнес-логика (business logic layer)
  web/                         #   CORS, Cookie, DNS, JWT, структура, поддомены, Wayback
  osint/                       #   username_recon, repo_search, whois_geoip
  stego/                       #   bitplanes, combine, xor, statistics, palette, png_structure, audio
  crypto/                      #   analyzer, decoders, detector, ciphers, scoring, xor, flags
  forensics/                   #   analyzer, carving, entropy, hashes, metadata, signatures, strings
tests/                         # интерактивные сценарии запуска
  images/                      #   тестовые изображения
  audio/                       #   тестовые аудиофайлы
```

## Зависимости

Минимальный набор — в `requirements.txt`. Для web/osint-модулей нужен `aiohttp`,
`PyJWT`, `python-whois`, `dnspython`; для stego — `numpy`, `Pillow`, `opencv-python`;
для crypto и forensics — только стандартная библиотека.

## Заметки

- Для системного диалога выбора файла (Stego) нужен tkinter; если графическое
  окружение недоступно — вводите путь вручную.
- Stego-анализаторы сохраняют результаты в каталог, который пользователь выбирает
  при запуске (дефолт: `./results/<анализатор>/<файл>/`).
