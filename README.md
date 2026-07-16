# DarkRecon

Консольный набор утиит для CTF / пентеста / расследований. Объединяет пять направлений:

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

## Структура проекта

```
main.py              # точка входа: главное меню + диспетчер
tui/                 # консольный интерфейс
  menus.py           #   отрисовка меню
  reports_web.py     #   вывод отчётов Web
  reports_osint.py   #   вывод отчётов OSINT
  runners_web.py     #   запуск Web-модулей
  runners_osint.py   #   запуск OSINT-модулей
  runners_stego.py   #   запуск Stego-модулей
  runners_crypto.py  #   запуск Crypto-модулей
  runners_forensics.py  # запуск Forensics-модулей
  handlers.py        #   циклы подменю
modules/             # сами модули (не меняются)
  web/ osint/ stego/ crypto/ forensics/
tests/               # тесты stego-модулей
```

## Заметки

- `main_osint_web.py.bak` — прежний монолитный файл точки входа (680 строк), оставлен как бэкап.
- Модули Web/OSINT используют `rich` для цветного вывода; Stego/Crypto/Forensics
  выводят через обычный `print` — это сделано намеренно, чтобы не трогать `modules/`.
- Для системного диалога выбора файла (Stego/Forensics) нужен tkinter; если графическое
  окружение недоступно — вводите путь вручную.
