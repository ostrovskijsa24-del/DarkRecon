"""
analyzer.py

Главное меню модуля Stego.

DarkRecon
"""

from .bitplanes import BitPlaneAnalyzer
from .combine_planes import PlaneCombiner
from .xor_planes import XorPlaneAnalyzer
from .statistics import StatisticsAnalyzer
from .palette import PaletteAnalyzer
from .png_structure import PNGStructureAnalyzer
from .audio import AudioAnalyzer


class StegoAnalyzer:
    """
    Главное меню анализа стеганографии.
    """

    def __init__(self):

        pass

    @staticmethod
    def get_path(message: str):

        return input(f"{message}: ").strip()

    def bitplanes(self):

        image = self.get_path(
            "Введите путь к изображению"
        )

        BitPlaneAnalyzer(image).extract_all()

    def combine(self):

        image = self.get_path(
            "Введите путь к изображению"
        )

        PlaneCombiner(image).run()

    def xor(self):

        image = self.get_path(
            "Введите путь к изображению"
        )

        XorPlaneAnalyzer(image).analyze()

    def statistics(self):

        image = self.get_path(
            "Введите путь к изображению"
        )

        StatisticsAnalyzer(image).run()

    def palette(self):

        image = self.get_path(
            "Введите путь к PNG"
        )

        PaletteAnalyzer(image).run()

    def png_structure(self):

        image = self.get_path(
            "Введите путь к PNG"
        )

        PNGStructureAnalyzer(image).run()

    def audio(self):

        audio = self.get_path(
            "Введите путь к WAV"
        )

        AudioAnalyzer(audio).run()

    def run(self):
        """
        Главное меню модуля Stego.
        """

        while True:

            print("\n========================================")
            print("            DARKRECON STEGO")
            print("========================================")
            print("1. Bit Plane Analysis")
            print("2. Combine Bit Planes")
            print("3. XOR Bit Planes")
            print("4. Image Statistics")
            print("5. Palette Analysis")
            print("6. PNG Structure")
            print("7. Audio Analysis")
            print("0. Exit")
            print("========================================")

            choice = input("Выберите пункт: ").strip()

            try:

                if choice == "1":
                    self.bitplanes()

                elif choice == "2":
                    self.combine()

                elif choice == "3":
                    self.xor()

                elif choice == "4":
                    self.statistics()

                elif choice == "5":
                    self.palette()

                elif choice == "6":
                    self.png_structure()

                elif choice == "7":
                    self.audio()

                elif choice == "0":

                    print("\nДо свидания!")

                    break

                else:

                    print("\nНеверный пункт меню.")

            except Exception as error:

                print(f"\nОшибка: {error}")