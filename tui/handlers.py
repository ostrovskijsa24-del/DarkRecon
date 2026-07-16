"""
Обработчики подменю — циклы выбора пункта и запуска соответствующих раннеров.

Web/OSINT раннеры асинхронные, поэтому оборачиваются в asyncio.run.
Stego/Crypto/Forensics — синхронные.
"""
import asyncio

from . import console
from .menus import (
    web_menu, osint_menu, stego_menu, crypto_menu, forensics_menu,
)
from .runners_web import (
    run_structure, run_response, run_cookie, run_jwt, run_cors,
    run_subdomain_enum, run_dns_recon, run_wayback,
)
from .runners_osint import run_username_recon, run_repo_search, run_whois_geoip
from .runners_stego import (
    run_bitplanes, run_combine, run_xor, run_statistics,
    run_palette, run_png_structure, run_audio,
)
from .runners_crypto import run_crypto
from .runners_forensics import run_forensics


# Таблицы соответствия «номер пункта -> раннер».
# Web/OSINT: значения — кортеж (раннер, is_async).
_WEB_ACTIONS = {
    1: (run_structure, True), 2: (run_response, True), 3: (run_cookie, False),
    4: (run_jwt, False), 5: (run_cors, True), 6: (run_subdomain_enum, True),
    7: (run_dns_recon, True), 8: (run_wayback, True),
}
_OSINT_ACTIONS = {
    1: (run_username_recon, True), 2: (run_repo_search, True), 3: (run_whois_geoip, True),
}
_STEGO_ACTIONS = {
    1: run_bitplanes, 2: run_combine, 3: run_xor, 4: run_statistics,
    5: run_palette, 6: run_png_structure, 7: run_audio,
}
_CRYPTO_ACTIONS = {1: run_crypto}
_FORENSICS_ACTIONS = {1: run_forensics}


def handle_web():
    while True:
        choice = web_menu()
        if choice == 0:
            return
        runner, is_async = _WEB_ACTIONS[choice]
        if is_async:
            asyncio.run(runner())
        else:
            runner()


def handle_osint():
    while True:
        choice = osint_menu()
        if choice == 0:
            return
        runner, is_async = _OSINT_ACTIONS[choice]
        if is_async:
            asyncio.run(runner())
        else:
            runner()


def _run_sync(menu_fn, actions: dict):
    """Универсальный цикл для синхронных подменю (stego/crypto/forensics)."""
    while True:
        choice = menu_fn()
        if choice == 0:
            return
        actions[choice]()


def handle_stego():
    _run_sync(stego_menu, _STEGO_ACTIONS)


def handle_crypto():
    _run_sync(crypto_menu, _CRYPTO_ACTIONS)


def handle_forensics():
    _run_sync(forensics_menu, _FORENSICS_ACTIONS)
