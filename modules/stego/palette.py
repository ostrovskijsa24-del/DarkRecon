"""
palette.py

Анализ палитры PNG (PLTE).

Чистая бизнес-логика: analyze() возвращает dict, save(output_dir) сохраняет
изображение палитры. Вывод в консоль — задача слоя tui.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image

from .utils import ImageUtils


class PaletteAnalyzer:
    """
    Анализатор палитры PNG.
    """

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)

        if self.image_path.suffix.lower() != ".png":
            raise ValueError("Данный модуль работает только с PNG.")

        self.image = Image.open(self.image_path)

    def has_palette(self) -> bool:
        return self.image.mode == "P"

    def get_palette(self):
        """Возвращает список RGB-троек палитры или None."""
        if not self.has_palette():
            return None

        palette = self.image.getpalette()
        return [
            (palette[i], palette[i + 1], palette[i + 2])
            for i in range(0, len(palette), 3)
        ]

    def palette_size(self) -> int:
        palette = self.get_palette()
        return 0 if palette is None else len(palette)

    def unique_colors(self) -> int:
        palette = self.get_palette()
        return 0 if palette is None else len(set(palette))

    def duplicated_colors(self) -> int:
        palette = self.get_palette()
        return 0 if palette is None else len(palette) - len(set(palette))

    def analyze(self) -> dict:
        """Выполняет анализ палитры изображения."""
        report = {
            "image": self.image_path.name,
            "has_palette": self.has_palette(),
            "palette_size": 0,
            "unique_colors": 0,
            "duplicated_colors": 0,
            "status": "Normal",
        }

        if not report["has_palette"]:
            return report

        report["palette_size"] = self.palette_size()
        report["unique_colors"] = self.unique_colors()
        report["duplicated_colors"] = self.duplicated_colors()

        if report["duplicated_colors"] > 0:
            report["status"] = "Suspicious"

        return report

    def save(self, output_dir: str | Path) -> Path:
        """
        Сохраняет визуализацию палитры в ``output_dir``.

        Возвращает путь к сохранённому файлу. Если палитры нет — бросает ValueError.
        """
        palette = self.get_palette()
        if palette is None:
            raise ValueError("Изображение не содержит палитру.")

        width = 16
        height = (len(palette) + 15) // 16
        palette_image = Image.new("RGB", (width, height))
        pixels = palette_image.load()

        index = 0
        for y in range(height):
            for x in range(width):
                if index >= len(palette):
                    break
                pixels[x, y] = palette[index]
                index += 1

        palette_image = palette_image.resize((width * 25, height * 25), Image.NEAREST)

        folder = ImageUtils.ensure_output_dir(output_dir, "palette")
        filename = folder / f"{self.image_path.stem}_palette.png"
        palette_image.save(filename)
        return filename
