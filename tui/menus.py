"""
Отрисовка меню DarkRecon.

Каждая функция меню печатает свои пункты и возвращает выбранный номер (int),
проверенный через rich IntPrompt.ask(choices=[...]).
"""
from rich.prompt import IntPrompt

from . import console


# ═══════════════ Главное меню ═══════════════

def main_menu():
    console.print("\n[bold magenta]╔═══ DARKRECON ═══╗[/]")
    console.print("[yellow]1[/] 🌐 Web-безопасность")
    console.print("[yellow]2[/] 🔎 OSINT")
    console.print("[yellow]3[/] 🖼️ Stego")
    console.print("[yellow]4[/] 🔐 Crypto")
    console.print("[yellow]5[/] 🧪 Forensics")
    console.print("[yellow]0[/] ❌ Выход")
    return IntPrompt.ask(">>>", choices=["0", "1", "2", "3", "4", "5"])


def web_menu():
    console.print("\n[bold cyan]═══ WEB-БЕЗОПАСНОСТЬ ═══[/]")
    console.print("[green]1[/] Сканер структуры       [dim](robots.txt, sitemap.xml, фаззинг)[/]")
    console.print("[green]2[/] Анализатор ответов     [dim](HTTP-заголовки, HTML, скрытые поля)[/]")
    console.print("[green]3[/] Анализатор Cookie      [dim](декод Base64/Hex/JWT, поиск флагов)[/]")
    console.print("[green]4[/] JWT-инструмент         [dim](декод, alg:none, брутфорс секрета)[/]")
    console.print("[green]5[/] CORS-сканер            [dim](8 векторов misconfiguration)[/]")
    console.print("[green]6[/] Поддомены              [dim](crt.sh + HackerTarget + AlienVault)[/]")
    console.print("[green]7[/] Анализ DNS             [dim](все типы записей + флаги в TXT)[/]")
    console.print("[green]8[/] История сайта          [dim](история сайта через archive.org)[/]")
    console.print("[yellow]0[/] Назад")
    return IntPrompt.ask(">>>", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])


def osint_menu():
    console.print("\n[bold cyan]═══ OSINT ═══[/]")
    console.print("[green]1[/] Проверка идентификаторов  [dim](GitHub, GitLab, Docker Hub, HTB, THM)[/]")
    console.print("[green]2[/] Поиск репозиториев        [dim](анализ GitHub на утечки и флаги)[/]")
    console.print("[green]3[/] WHOIS & GeoIP             [dim](регистрационные данные и геолокация)[/]")
    console.print("[yellow]0[/] Назад")
    return IntPrompt.ask(">>>", choices=["0", "1", "2", "3"])


def stego_menu():
    console.print("\n[bold cyan]═══ STEGO ═══[/]")
    console.print("[green]1[/] Битовые плоскости      [dim](визуализация LSB-скрытия в каналах)[/]")
    console.print("[green]2[/] Объединение плоскостей  [dim](сборка изображения из битовых плоскостей)[/]")
    console.print("[green]3[/] XOR плоскости          [dim](выявление скрытых данных через XOR)[/]")
    console.print("[green]4[/] Статистика изображения  [dim](гистограммы, аномалии распределения)[/]")
    console.print("[green]5[/] Анализ палитры          [dim](скрытые цвета/аномалии в палитре PNG)[/]")
    console.print("[green]6[/] Структура PNG           [dim](чанки, скрытые данные после IEND)[/]")
    console.print("[green]7[/] Анализ аудио (WAV)      [dim](LSB в сэмплах, спектрограмма)[/]")
    console.print("[yellow]0[/] Назад")
    return IntPrompt.ask(">>>", choices=["0", "1", "2", "3", "4", "5", "6", "7"])


def crypto_menu():
    console.print("\n[bold cyan]═══ CRYPTO ═══[/]")
    console.print("[green]1[/] Анализ строки          [dim](авто-декодер: Base64/Hex/Цезарь/ROT/Affine/XOR)[/]")
    console.print("[yellow]0[/] Назад")
    return IntPrompt.ask(">>>", choices=["0", "1"])


def forensics_menu():
    console.print("\n[bold cyan]═══ FORENSICS ═══[/]")
    console.print("[green]1[/] Анализ файла           [dim](сигнатуры, энтропия, strings, хеши, карвинг)[/]")
    console.print("[yellow]0[/] Назад")
    return IntPrompt.ask(">>>", choices=["0", "1"])
