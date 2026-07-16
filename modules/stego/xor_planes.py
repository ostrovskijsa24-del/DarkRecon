"""
xor_planes.py

XOR-анализ битовых плоскостей изображения.

Чистая бизнес-логика:
- analyze() возвращает XOR-комбинации плоскостей как данные;
- save(output_dir) сохраняет их на диск и возвращает список путей.
Вывод в консоль — задача слоя tui.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np

from .utils import ImageUtils


class XorPlaneAnalyzer:
    """
    Анализатор XOR битовых плоскостей.
    """

    CHANNEL_NAMES = ["B", "G", "R", "A"]

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.image = ImageUtils.load_image(self.image_path)
        self.channels = ImageUtils.get_channels(self.image)
        self.image_name = self.image_path.stem

    def extract_planes(self, channel: np.ndarray) -> list[np.ndarray]:
        return [(channel >> bit) & 1 for bit in range(8)]

    def analyze(self) -> dict:
        """
        Строит все попарные XOR-комбинации битовых плоскостей всех каналов.

        Возвращает dict: {image, pairs: [{name, plane}, ...], count}.
        """
        all_planes: list[tuple[str, np.ndarray]] = []
        for channel_name, channel in zip(self.CHANNEL_NAMES, self.channels):
            for bit, plane in enumerate(self.extract_planes(channel)):
                all_planes.append((f"{channel_name}{bit}", plane))

        pairs = []
        for i in range(len(all_planes)):
            name1, plane1 = all_planes[i]
            for j in range(i + 1, len(all_planes)):
                name2, plane2 = all_planes[j]
                pairs.append({
                    "name": f"{name1}_XOR_{name2}",
                    "plane": np.bitwise_xor(plane1, plane2),
                })

        return {
            "image": self.image_name,
            "pairs": pairs,
            "count": len(pairs),
        }

    def save(self, output_dir: str | Path) -> list[Path]:
        """
        Сохраняет все XOR-изображения в ``output_dir``.

        Структура: ``output_dir/xor/<image>/<name>.png``.
        Возвращает список сохранённых путей.
        """
        results = self.analyze()
        folder = ImageUtils.ensure_output_dir(output_dir, "xor", results["image"])
        saved: list[Path] = []
        for pair in results["pairs"]:
            filename = folder / f"{pair['name']}.png"
            ImageUtils.save_image(filename, ImageUtils.normalize_binary(pair["plane"]))
            saved.append(filename)
        return saved
