"""
statistics.py

Статистический анализ изображения.

DarkRecon
"""

from pathlib import Path
from math import log2

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
        """
        Вычисляет энтропию Шеннона.
        """

        histogram = np.bincount(
            channel.flatten(),
            minlength=256
        )

        probabilities = histogram / histogram.sum()

        entropy = 0.0

        for probability in probabilities:

            if probability > 0:

                entropy -= probability * log2(probability)

        return entropy

    @staticmethod
    def mean(channel: np.ndarray) -> float:
        """
        Среднее значение.
        """

        return float(np.mean(channel))

    @staticmethod
    def std(channel: np.ndarray) -> float:
        """
        Стандартное отклонение.
        """

        return float(np.std(channel))

    @staticmethod
    def lsb_distribution(channel: np.ndarray) -> float:
        """
        Вычисляет процент единиц в младшем значащем бите.
        """

        lsb = channel & 1

        ones = np.count_nonzero(lsb)

        total = lsb.size

        return (ones / total) * 100

    def analyze(self) -> dict:
        """
        Выполняет полный статистический анализ изображения.
        """

        report = {
            "image": self.image_name,
            "width": self.image.shape[1],
            "height": self.image.shape[0],
            "channels": len(self.channels),
            "results": []
        }

        for index, channel in enumerate(self.channels):

            report["results"].append({

                "channel": self.CHANNEL_NAMES[index],

                "entropy": self.entropy(channel),

                "mean": self.mean(channel),

                "std": self.std(channel),

                "lsb": self.lsb_distribution(channel)

            })

        return report

    @staticmethod
    def print_report(report: dict):
        """
        Красивый вывод результатов анализа.
        """

        print("\n========================================")
        print("        IMAGE STATISTICS")
        print("========================================")

        print(f"Image      : {report['image']}")
        print(f"Resolution : {report['width']} x {report['height']}")
        print(f"Channels   : {report['channels']}")

        print("\n----------------------------------------")

        for item in report["results"]:

            print(f"\n[{item['channel']}]")

            print(f"Entropy : {item['entropy']:.4f}")

            print(f"Mean    : {item['mean']:.2f}")

            print(f"Std Dev : {item['std']:.2f}")

            print(f"LSB 1's : {item['lsb']:.2f}%")

            if 49 <= item["lsb"] <= 51:

                print("Status  : Suspicious")

            else:

                print("Status  : Normal")

        print("\n========================================")

    def run(self):
        """
        Запуск анализа.
        """

        report = self.analyze()

        self.print_report(report)