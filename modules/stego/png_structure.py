"""
png_structure.py

Анализ структуры PNG.

Чистая бизнес-логика: analyze() возвращает dict с чанками, неизвестными
чанками и признаком оверлея после IEND. Вывод в консоль — задача слоя tui.
"""
from __future__ import annotations

import struct
from pathlib import Path


class PNGStructureAnalyzer:
    """
    Анализатор структуры PNG-файла.
    """

    PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)

        if self.image_path.suffix.lower() != ".png":
            raise ValueError("Данный модуль работает только с PNG.")

        self.chunks: list[dict] = []

    def check_signature(self) -> bool:
        """Проверяет сигнатуру PNG."""
        with open(self.image_path, "rb") as file:
            signature = file.read(8)
        return signature == self.PNG_SIGNATURE

    def read_chunks(self) -> list[dict]:
        """Читает все чанки PNG."""
        self.chunks.clear()

        with open(self.image_path, "rb") as file:
            file.read(8)  # пропускаем сигнатуру

            while True:
                length_data = file.read(4)
                if len(length_data) < 4:
                    break

                length = struct.unpack(">I", length_data)[0]
                chunk_type = file.read(4).decode(errors="replace")

                file.seek(length, 1)   # пропускаем данные чанка
                file.read(4)           # пропускаем CRC

                self.chunks.append({"type": chunk_type, "length": length})

                if chunk_type == "IEND":
                    break

        return self.chunks

    @staticmethod
    def known_chunks() -> set[str]:
        """Возвращает множество стандартных PNG-чанков."""
        return {
            "IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "gAMA",
            "pHYs", "sRGB", "cHRM", "bKGD", "hIST", "sBIT", "tIME", "tRNS",
        }

    def unknown_chunks(self) -> list[dict]:
        """Возвращает список нестандартных PNG-чанков."""
        if not self.chunks:
            self.read_chunks()
        known = self.known_chunks()
        return [chunk for chunk in self.chunks if chunk["type"] not in known]

    def has_overlay(self) -> bool:
        """Проверяет наличие данных после IEND."""
        with open(self.image_path, "rb") as file:
            data = file.read()

        index = data.find(b"IEND")
        if index == -1:
            return False
        return len(data) > index + 8

    def analyze(self) -> dict:
        """Выполняет анализ структуры PNG."""
        if not self.check_signature():
            raise ValueError("Файл не является PNG.")

        self.read_chunks()
        return {
            "file": self.image_path.name,
            "chunks": self.chunks,
            "unknown": self.unknown_chunks(),
            "overlay": self.has_overlay(),
        }
