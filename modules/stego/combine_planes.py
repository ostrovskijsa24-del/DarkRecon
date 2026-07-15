"""
combine_planes.py

Объединение нескольких битовых плоскостей изображения.
"""

from pathlib import Path

import numpy as np

from .utils import ImageUtils


class PlaneCombiner:

    def __init__(self, image_path: str):

        self.image_path = Path(image_path)

        self.image = ImageUtils.load_image(image_path)

        self.channels = ImageUtils.get_channels(self.image)

    @staticmethod
    def combine(channel: np.ndarray, bits: list[int]) -> np.ndarray:
        """
        Объединяет несколько битовых плоскостей одного канала.
        """

        result = np.zeros_like(channel)

        for bit in bits:
            result |= ((channel >> bit) & 1) << bit

        return result

    def save(self,
             image: np.ndarray,
             channel_name: str,
             bits: list[int]):

        output = (
            Path(__file__).parent /
            "output" /
            "combine"
        )

        output.mkdir(parents=True, exist_ok=True)

        filename = (
            output /
            f"{channel_name}_{'_'.join(map(str, bits))}.png"
        )

        ImageUtils.save_image(filename, image)

        print(f"Сохранено: {filename}")