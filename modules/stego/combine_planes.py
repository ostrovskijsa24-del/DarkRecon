"""
combine_planes.py

Модуль объединения битовых плоскостей изображения.

DarkRecon
"""

from pathlib import Path
from itertools import combinations

import numpy as np

from .utils import ImageUtils


class PlaneCombiner:
    """
    Анализатор объединения битовых плоскостей.

    Возможности:
    - объединение выбранных битов;
    - генерация всех комбинаций;
    - сохранение результатов.
    """

    CHANNEL_NAMES = ["B", "G", "R", "A"]

    def __init__(self, image_path: str):
        """
        Загружает изображение и подготавливает рабочие каталоги.
        """

        self.image_path = Path(image_path)

        self.image = ImageUtils.load_image(self.image_path)

        self.channels = ImageUtils.get_channels(self.image)

        self.image_name = self.image_path.stem

        self.output_dir = (
            Path(__file__).parent
            / "output"
            / "combine"
            / self.image_name
        )

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

    @staticmethod
    def combine(channel: np.ndarray,
                bits: list[int]) -> np.ndarray:
        """
        Объединяет указанные битовые плоскости.

        Parameters
        ----------
        channel : np.ndarray
            Канал изображения.

        bits : list[int]
            Список битов.

        Returns
        -------
        np.ndarray
            Новое изображение.
        """

        result = np.zeros_like(channel)

        for bit in bits:

            plane = ((channel >> bit) & 1) << bit

            result |= plane

        return result

    def save_result(self,
                    image: np.ndarray,
                    channel_name: str,
                    bits: list[int]):
        """
        Сохраняет изображение.
        """

        folder = self.output_dir / channel_name

        folder.mkdir(
            parents=True,
            exist_ok=True
        )

        filename = folder / (
            f"{channel_name}_{'_'.join(map(str, bits))}.png"
        )

        ImageUtils.save_image(
            filename,
            image
        )

        print(f"[+] {filename}")
    def combine_selected(self,
                         channel_index: int,
                         bits: list[int]):
        """
        Объединяет выбранные битовые плоскости одного канала.

        Parameters
        ----------
        channel_index : int
            Индекс канала:
                0 - Blue
                1 - Green
                2 - Red
                3 - Alpha

        bits : list[int]
            Список объединяемых битов.
        """

        if channel_index < 0 or channel_index >= len(self.channels):
            raise ValueError("Неверный номер канала.")

        if len(bits) == 0:
            raise ValueError("Не выбраны битовые плоскости.")

        for bit in bits:
            if bit < 0 or bit > 7:
                raise ValueError(f"Бит {bit} вне диапазона 0-7.")

        channel = self.channels[channel_index]

        result = self.combine(channel, bits)

        self.save_result(
            result,
            self.CHANNEL_NAMES[channel_index],
            bits
        )

        print("\nГотово.")

    def combine_all(self,
                    min_bits: int = 2,
                    max_bits: int = 8):
        """
        Создает все возможные комбинации битовых плоскостей.

        Parameters
        ----------
        min_bits : int
            Минимальный размер комбинации.

        max_bits : int
            Максимальный размер комбинации.
        """

        print("\n========== COMBINE ANALYSIS ==========\n")

        total = 0

        for channel_index, channel in enumerate(self.channels):

            channel_name = self.CHANNEL_NAMES[channel_index]

            print(f"\nКанал {channel_name}")

            available_bits = list(range(8))

            for size in range(min_bits, max_bits + 1):

                print(f"  Комбинации по {size} бит(а)...")

                for bits in combinations(available_bits, size):

                    result = self.combine(
                        channel,
                        list(bits)
                    )

                    self.save_result(
                        result,
                        channel_name,
                        list(bits)
                    )

                    total += 1

        print("\n===================================")
        print(f"Создано изображений: {total}")
        print("===================================\n")
    def run(self):
        """
        Консольное меню модуля объединения битовых плоскостей.
        """

        while True:

            print("\n========================================")
            print("        COMBINE BIT PLANES")
            print("========================================")
            print("1. Создать все комбинации")
            print("2. Создать выбранную комбинацию")
            print("0. Назад")
            print("========================================")

            choice = input("Выберите пункт: ").strip()

            if choice == "0":
                break

            elif choice == "1":

                print("\nВыберите режим генерации:\n")
                print("1. Комбинации по 2 бита")
                print("2. Комбинации по 3 бита")
                print("3. Комбинации по 4 бита")
                print("4. Все комбинации (2-8)")
                print("5. Свой диапазон")

                mode = input("\n> ").strip()

                if mode == "1":

                    self.combine_all(2, 2)

                elif mode == "2":

                    self.combine_all(3, 3)

                elif mode == "3":

                    self.combine_all(4, 4)

                elif mode == "4":

                    self.combine_all(2, 8)

                elif mode == "5":

                    try:

                        minimum = int(input("Минимум бит: "))
                        maximum = int(input("Максимум бит: "))

                        self.combine_all(
                            minimum,
                            maximum
                        )

                    except ValueError:

                        print("\nОшибка ввода.")

                else:

                    print("\nНеверный пункт.")

            elif choice == "2":

                print("\nКаналы изображения:\n")

                for index in range(len(self.channels)):

                    print(
                        f"{index + 1}. "
                        f"{self.CHANNEL_NAMES[index]}"
                    )

                try:

                    channel = int(
                        input("\nВыберите канал: ")
                    ) - 1

                except ValueError:

                    print("\nОшибка.")

                    continue

                bits = input(
                    "\nВведите номера битов через пробел\n"
                    "Например:\n"
                    "0 1 2\n\n> "
                )

                try:

                    bits = [
                        int(bit)
                        for bit in bits.split()
                    ]

                except ValueError:

                    print("\nОшибка.")

                    continue

                self.combine_selected(
                    channel,
                    bits
                )

            else:

                print("\nНеверный выбор.")