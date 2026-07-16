"""
png_structure.py

Анализ структуры PNG.

DarkRecon
"""

from pathlib import Path
import struct


class PNGStructureAnalyzer:
    """
    Анализ структуры PNG-файла.
    """

    PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

    def __init__(self, image_path: str):

        self.image_path = Path(image_path)

        self.chunks = []

    def check_signature(self):
        """
        Проверяет сигнатуру PNG.
        """

        with open(self.image_path, "rb") as file:

            signature = file.read(8)

        return signature == self.PNG_SIGNATURE

    def read_chunks(self):
        """
        Читает все чанки PNG.
        """

        self.chunks.clear()

        with open(self.image_path, "rb") as file:

            file.read(8)

            while True:

                length_data = file.read(4)

                if len(length_data) < 4:
                    break

                length = struct.unpack(">I", length_data)[0]

                chunk_type = file.read(4).decode()

                file.seek(length, 1)

                file.read(4)

                self.chunks.append({
                    "type": chunk_type,
                    "length": length
                })

                if chunk_type == "IEND":
                    break

        return self.chunks

    @staticmethod
    def known_chunks():
        """
        Возвращает список стандартных PNG-чанков.
        """

        return {
            "IHDR",
            "PLTE",
            "IDAT",
            "IEND",
            "tEXt",
            "zTXt",
            "iTXt",
            "gAMA",
            "pHYs",
            "sRGB",
            "cHRM",
            "bKGD",
            "hIST",
            "sBIT",
            "tIME",
            "tRNS"
        }

    def print_chunks(self):
        """
        Выводит структуру PNG.
        """

        if not self.chunks:
            self.read_chunks()

        print("\n========================================")
        print("           PNG STRUCTURE")
        print("========================================")

        print(f"File : {self.image_path.name}")

        print("\nChunks:\n")

        for index, chunk in enumerate(self.chunks, start=1):

            status = "Standard"

            if chunk["type"] not in self.known_chunks():
                status = "Unknown"

            print(
                f"{index:2}. "
                f"{chunk['type']:<5} "
                f"{chunk['length']:>8} bytes   "
                f"{status}"
            )

        print("\n========================================")

    def unknown_chunks(self):
        """
        Возвращает список нестандартных PNG-чанков.
        """

        if not self.chunks:
            self.read_chunks()

        return [
            chunk
            for chunk in self.chunks
            if chunk["type"] not in self.known_chunks()
        ]

    def has_overlay(self) -> bool:
            """
            Проверяет наличие данных после IEND.
            """

            with open(self.image_path, "rb") as file:
                data = file.read()

            index = data.find(b"IEND")

            if index == -1:
                return False

            end = index + 8

            return len(data) > end

    def analyze(self) -> dict:
            """
            Выполняет анализ структуры PNG.
            """

            if not self.check_signature():
                raise ValueError("Файл не является PNG.")

            self.read_chunks()

            return {
                "file": self.image_path.name,
                "chunks": self.chunks,
                "unknown": self.unknown_chunks(),
                "overlay": self.has_overlay()
            }

    @staticmethod
    def print_report(report: dict):
            """
            Вывод результатов анализа.
            """

            print("\n========================================")
            print("         PNG STRUCTURE REPORT")
            print("========================================")

            print(f"File: {report['file']}")

            print(f"Chunks: {len(report['chunks'])}")

            if report["unknown"]:

                print("\nUnknown chunks:")

                for chunk in report["unknown"]:
                    print(
                        f" - {chunk['type']} "
                        f"({chunk['length']} bytes)"
                    )

            else:

                print("\nUnknown chunks: none")

            print(
                f"\nOverlay after IEND: "
                f"{'YES' if report['overlay'] else 'NO'}"
            )

            print("========================================")

    def run(self):
                """
                Запуск анализа структуры PNG.
                """

                report = self.analyze()

                self.print_chunks()

                self.print_report(report)


