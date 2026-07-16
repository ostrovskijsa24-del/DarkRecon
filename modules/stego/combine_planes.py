"""
combine_planes.py

Объединение битовых плоскостей изображения.

Чистая бизнес-логика:
- combine() объединяет плоскости одного канала;
- combine_selected/combine_all принимают output_dir, сохраняют результаты
  и возвращают список путей.
Меню и вывод в консоль — задача слоя tui.
"""
from __future__ import annotations

from itertools import combinations
from pathlib import Path

import numpy as np

from .utils import ImageUtils


class PlaneCombiner:
    """
    Анализатор объединения битовых плоскостей.
    """

    CHANNEL_NAMES = ["B", "G", "R", "A"]

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.image = ImageUtils.load_image(self.image_path)
        self.channels = ImageUtils.get_channels(self.image)
        self.image_name = self.image_path.stem

    @staticmethod
    def combine(channel: np.ndarray, bits: list[int]) -> np.ndarray:
        """Объединяет указанные битовые плоскости канала."""
        result = np.zeros_like(channel)
        for bit in bits:
            plane = ((channel >> bit) & 1) << bit
            result |= plane
        return result

    def combine_selected(
        self,
        channel_index: int,
        bits: list[int],
        output_dir: str | Path,
    ) -> list[Path]:
        """
        Объединяет выбранные битовые плоскости одного канала и сохраняет результат.

        Возвращает список сохранённых путей.
        """
        if channel_index < 0 or channel_index >= len(self.channels):
            raise ValueError("Неверный номер канала.")
        if len(bits) == 0:
            raise ValueError("Не выбраны битовые плоскости.")
        for bit in bits:
            if bit < 0 or bit > 7:
                raise ValueError(f"Бит {bit} вне диапазона 0-7.")

        channel = self.channels[channel_index]
        channel_name = self.CHANNEL_NAMES[channel_index]
        result = self.combine(channel, bits)

        folder = ImageUtils.ensure_output_dir(output_dir, "combine", self.image_name, channel_name)
        filename = folder / f"{channel_name}_{'_'.join(map(str, bits))}.png"
        ImageUtils.save_image(filename, result)
        return [filename]

    def combine_all(
        self,
        output_dir: str | Path,
        min_bits: int = 2,
        max_bits: int = 8,
    ) -> list[Path]:
        """
        Создаёт все возможные комбинации битовых плоскостей всех каналов.

        Возвращает список сохранённых путей.
        """
        saved: list[Path] = []
        for channel_index, channel in enumerate(self.channels):
            channel_name = self.CHANNEL_NAMES[channel_index]
            for size in range(min_bits, max_bits + 1):
                for bits in combinations(range(8), size):
                    saved.extend(
                        self.combine_selected(channel_index, list(bits), output_dir)
                    )
        return saved
