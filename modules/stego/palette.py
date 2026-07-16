"""
palette.py

Анализ палитры PNG (PLTE).

DarkRecon
"""

from pathlib import Path

from PIL import Image


class PaletteAnalyzer:
    """
    Анализ палитры PNG.
    """

    def __init__(self, image_path: str):

        self.image_path = Path(image_path)

        if self.image_path.suffix.lower() != ".png":
            raise ValueError(
                "Данный модуль работает только с PNG."
            )

        self.image = Image.open(self.image_path)

    def has_palette(self) -> bool:
        """
        Проверяет наличие палитры.
        """

        return self.image.mode == "P"

    def get_palette(self):
        """
        Возвращает список цветов палитры.
        """

        if not self.has_palette():
            return None

        palette = self.image.getpalette()

        colors = []

        for i in range(0, len(palette), 3):

            colors.append((
                palette[i],
                palette[i + 1],
                palette[i + 2]
            ))

        return colors
    def palette_size(self) -> int:
        """
        Возвращает количество цветов в палитре.
        """

        palette = self.get_palette()

        if palette is None:
            return 0

        return len(palette)

    def unique_colors(self) -> int:
        """
        Возвращает количество уникальных цветов.
        """

        palette = self.get_palette()

        if palette is None:
            return 0

        return len(set(palette))

    def duplicated_colors(self) -> int:
        """
        Возвращает количество повторяющихся цветов.
        """

        palette = self.get_palette()

        if palette is None:
            return 0

        return len(palette) - len(set(palette))

    def save_palette(self):
        """
        Сохраняет изображение палитры.
        """

        if not self.has_palette():

            print("Изображение не содержит палитру.")

            return

        palette = self.get_palette()

        width = 16
        height = (len(palette) + 15) // 16

        palette_image = Image.new(
            "RGB",
            (width, height)
        )

        pixels = palette_image.load()

        index = 0

        for y in range(height):

            for x in range(width):

                if index >= len(palette):
                    break

                pixels[x, y] = palette[index]

                index += 1

        output = (
            Path(__file__).parent
            / "output"
            / "palette"
        )

        output.mkdir(
            parents=True,
            exist_ok=True
        )

        filename = output / (
            f"{self.image_path.stem}_palette.png"
        )

        palette_image = palette_image.resize(
            (width * 25, height * 25),
            Image.NEAREST
        )

        palette_image.save(filename)

        print(f"[+] Палитра сохранена:\n{filename}")

    def analyze(self) -> dict:
        """
        Выполняет анализ палитры изображения.
        """

        report = {
            "image": self.image_path.name,
            "has_palette": self.has_palette(),
            "palette_size": 0,
            "unique_colors": 0,
            "duplicated_colors": 0,
            "status": "Normal"
        }

        if not report["has_palette"]:
            return report

        report["palette_size"] = self.palette_size()

        report["unique_colors"] = self.unique_colors()

        report["duplicated_colors"] = self.duplicated_colors()

        if report["duplicated_colors"] > 0:
            report["status"] = "Suspicious"

        return report

    @staticmethod
    def print_report(report: dict):

        """
        Выводит результаты анализа.
        """

        print("\n========================================")
        print("         PNG PALETTE ANALYSIS")
        print("========================================")

        print(f"Image             : {report['image']}")

        if not report["has_palette"]:

            print("\nПалитра отсутствует.")
            print("Изображение использует RGB/RGBA.")
            print("========================================")
            return

        print(f"Palette           : Yes")
        print(f"Colors            : {report['palette_size']}")
        print(f"Unique colors     : {report['unique_colors']}")
        print(f"Duplicate colors  : {report['duplicated_colors']}")
        print(f"Status            : {report['status']}")

        print("========================================")

    def run(self):
        """
        Запуск анализа палитры.
        """

        report = self.analyze()

        self.print_report(report)

        if report["has_palette"]:

            answer = input(
                "\nСохранить изображение палитры? (y/n): "
            ).lower()

            if answer == "y":

                self.save_palette()