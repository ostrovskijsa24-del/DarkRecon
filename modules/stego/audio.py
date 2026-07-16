"""
audio.py

Анализ WAV-файлов.

DarkRecon
"""

from pathlib import Path
import wave
import numpy as np


class AudioAnalyzer:
    """
    Анализатор WAV-файлов.
    """

    def __init__(self, audio_path: str):

        self.audio_path = Path(audio_path)

        if not self.audio_path.exists():
            raise FileNotFoundError(
                f"Файл не найден:\n{self.audio_path}"
            )

        self.wave_file = wave.open(
            str(self.audio_path),
            "rb"
        )

        self.params = self.wave_file.getparams()

        self.frames = self.wave_file.readframes(
            self.params.nframes
        )

        self.samples = np.frombuffer(
            self.frames,
            dtype=np.int16
        )

        self.output_dir = (
            Path(__file__).parent /
            "output" /
            "audio" /
            self.audio_path.stem
        )

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )
    def info(self):
        """
        Возвращает информацию о WAV-файле.
        """

        return {
            "filename": self.audio_path.name,
            "channels": self.params.nchannels,
            "sample_width": self.params.sampwidth,
            "frame_rate": self.params.framerate,
            "frames": self.params.nframes,
            "compression": self.params.compname
        }

    def print_info(self):
        """
        Вывод информации о WAV-файле.
        """

        info = self.info()

        print("\n========================================")
        print("           AUDIO ANALYSIS")
        print("========================================")

        print(f"File          : {info['filename']}")
        print(f"Channels      : {info['channels']}")
        print(f"Sample Width  : {info['sample_width']} bytes")
        print(f"Sample Rate   : {info['frame_rate']} Hz")
        print(f"Frames        : {info['frames']}")
        print(f"Compression   : {info['compression']}")

        print("========================================")

    def extract_lsb(self):
        """
        Извлекает младший бит каждого семпла.
        """

        lsb = self.samples & 1

        return lsb.astype(np.uint8)

    def save_lsb(self):
        """
        Сохраняет LSB-поток в бинарный файл.
        """

        lsb = self.extract_lsb()

        output_file = (
            self.output_dir /
            "lsb_stream.bin"
        )

        with open(output_file, "wb") as file:

            file.write(lsb.tobytes())

        print(f"\n[+] LSB поток сохранён:")
        print(output_file)

        return output_file
    def run(self):
        """
        Запуск анализа WAV-файла.
        """

        while True:

            print("\n========================================")
            print("           AUDIO ANALYZER")
            print("========================================")
            print("1. Информация о WAV")
            print("2. Извлечь LSB поток")
            print("0. Назад")
            print("========================================")

            choice = input("Выберите пункт: ").strip()

            if choice == "0":
                break

            elif choice == "1":

                self.print_info()

            elif choice == "2":

                self.save_lsb()

            else:

                print("Неверный выбор.")