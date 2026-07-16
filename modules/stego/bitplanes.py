"""
bitplanes.py

Извлечение битовых плоскостей изображения.

Чистая бизнес-логика:
- analyze() возвращает битовые плоскости как данные;
- save(output_dir) сохраняет их на диск и возвращает список путей.
Вывод в консоль — задача слоя tui.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np

from .utils import ImageUtils


class BitPlaneAnalyzer:
    """
    Анализатор битовых плоскостей изображения.
    """

    CHANNEL_NAMES = ["B", "G", "R", "A"]

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.image = ImageUtils.load_image(image_path)
        self.channels = ImageUtils.get_channels(self.image)
        self.image_name = self.image_path.stem

    def extract_planes(self, channel: np.ndarray) -> list[np.ndarray]:
        """Извлекает 8 битовых плоскостей одного канала."""
        return [(channel >> bit) & 1 for bit in range(8)]

    def analyze(self) -> dict:
        """
        Извлекает битовые плоскости всех каналов.

        Возвращает dict с плоскостями (без сохранения на диск и без вывода):
            {image, channels: [{name, planes: [plane, ...]}, ...]}
        """
        channels = []
        for channel_name, channel in zip(self.CHANNEL_NAMES, self.channels):
            channels.append({
                "name": channel_name,
                "planes": self.extract_planes(channel),
            })
        return {"image": self.image_name, "channels": channels}

    def save(self, output_dir: str | Path) -> list[Path]:
        """
        Сохраняет битовые плоскости каждого канала в ``output_dir``.

        Структура: ``output_dir/bitplanes/<channel>/bit<N>.png``.
        Возвращает список сохранённых путей.
        """
        results = self.analyze()
        saved: list[Path] = []
        for channel in results["channels"]:
            folder = ImageUtils.ensure_output_dir(output_dir, "bitplanes", channel["name"])
            for bit, plane in enumerate(channel["planes"]):
                filename = folder / f"bit{bit}.png"
                ImageUtils.save_image(filename, ImageUtils.normalize_binary(plane))
                saved.append(filename)
        return saved
