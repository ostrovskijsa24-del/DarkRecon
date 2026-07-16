"""
statistics.py

Статистический анализ изображения.

Чистая бизнес-логика: analyze() возвращает dict со статистикой каналов.
Вывод в консоль — задача слоя tui.
"""
from __future__ import annotations

from math import log2
from pathlib import Path

import numpy as np

from .utils import ImageUtils


class StatisticsAnalyzer:
    """
    Выполняет статистический анализ изображения.
    """

    CHANNEL_NAMES = ["Blue", "Green", "Red", "Alpha"]

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.image = ImageUtils.load_image(self.image_path)
        self.channels = ImageUtils.get_channels(self.image)
        self.image_name = self.image_path.name

    @staticmethod
    def entropy(channel: np.ndarray) -> float:
        """Вычисляет энтропию Шеннона."""
        histogram = np.bincount(channel.flatten(), minlength=256)
        probabilities = histogram / histogram.sum()
        return -sum(p * log2(p) for p in probabilities if p > 0)

    @staticmethod
    def mean(channel: np.ndarray) -> float:
        return float(np.mean(channel))

    @staticmethod
    def std(channel: np.ndarray) -> float:
        return float(np.std(channel))

    @staticmethod
    def lsb_distribution(channel: np.ndarray) -> float:
        """Вычисляет процент единиц в младшем значащем бите."""
        lsb = channel & 1
        return (np.count_nonzero(lsb) / lsb.size) * 100

    def analyze(self) -> dict:
        """Выполняет полный статистический анализ изображения."""
        results = []
        for index, channel in enumerate(self.channels):
            lsb = self.lsb_distribution(channel)
            results.append({
                "channel": self.CHANNEL_NAMES[index],
                "entropy": self.entropy(channel),
                "mean": self.mean(channel),
                "std": self.std(channel),
                "lsb": lsb,
                # 49..51% единиц в LSB — нетипично, подозрительно на стегано.
                "status": "Suspicious" if 49 <= lsb <= 51 else "Normal",
            })

        return {
            "image": self.image_name,
            "width": self.image.shape[1],
            "height": self.image.shape[0],
            "channels": len(self.channels),
            "results": results,
        }
