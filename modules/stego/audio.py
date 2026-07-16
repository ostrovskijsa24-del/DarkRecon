"""
audio.py

Анализ WAV-файлов.

Чистая бизнес-логика: info() возвращает метаданные, extract_lsb() возвращает
массив LSB, save(output_dir) сохраняет LSB-поток на диск.
Вывод в консоль и меню — задача слоя tui.
"""
from __future__ import annotations

from pathlib import Path
import wave

import numpy as np

from .utils import ImageUtils


class AudioAnalyzer:
    """
    Анализатор WAV-файлов.
    """

    def __init__(self, audio_path: str):
        self.audio_path = Path(audio_path)

        if not self.audio_path.exists():
            raise FileNotFoundError(f"Файл не найден:\n{self.audio_path}")

        self.wave_file = wave.open(str(self.audio_path), "rb")
        self.params = self.wave_file.getparams()
        self.frames = self.wave_file.readframes(self.params.nframes)
        self.samples = np.frombuffer(self.frames, dtype=np.int16)
        self.image_name = self.audio_path.stem

    def info(self) -> dict:
        """Возвращает информацию о WAV-файле."""
        return {
            "filename": self.audio_path.name,
            "channels": self.params.nchannels,
            "sample_width": self.params.sampwidth,
            "frame_rate": self.params.framerate,
            "frames": self.params.nframes,
            "compression": self.params.compname,
        }

    def extract_lsb(self) -> np.ndarray:
        """Извлекает младший бит каждого семпла как массив uint8."""
        return (self.samples & 1).astype(np.uint8)

    def save(self, output_dir: str | Path) -> Path:
        """
        Сохраняет LSB-поток в ``output_dir``.

        Возвращает путь к сохранённому файлу.
        """
        lsb = self.extract_lsb()
        folder = ImageUtils.ensure_output_dir(output_dir, "audio", self.image_name)
        output_file = folder / "lsb_stream.bin"

        with open(output_file, "wb") as file:
            file.write(lsb.tobytes())

        return output_file
