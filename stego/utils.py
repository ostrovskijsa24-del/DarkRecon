"""
utils.py

Вспомогательные функции для работы с изображениями.
Используются всеми модулями Stego.
"""

from pathlib import Path

import cv2
import numpy as np


# Корень проекта DarkRecon
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ImageUtils:
    """Утилиты для работы с изображениями."""

    @staticmethod
    def load_image(path: str | Path) -> np.ndarray:
        """
        Загружает изображение.

        Parameters
        ----------
        path : str | Path
            Относительный или абсолютный путь.

        Returns
        -------
        numpy.ndarray
        """

        path = Path(path)

        if not path.is_absolute():
            path = PROJECT_ROOT / path

        if not path.exists():
            raise FileNotFoundError(f"Файл не найден:\n{path}")

        image = cv2.imread(str(path), cv2.IMREAD_UNCHANGED)

        if image is None:
            raise ValueError(f"OpenCV не смог открыть:\n{path}")

        return image

    @staticmethod
    def save_image(path: str | Path, image: np.ndarray):

        path = Path(path)

        if not path.is_absolute():
            path = PROJECT_ROOT / path

        path.parent.mkdir(parents=True, exist_ok=True)

        cv2.imwrite(str(path), image)

    @staticmethod
    def get_channels(image: np.ndarray):
        return cv2.split(image)

    @staticmethod
    def normalize_binary(binary: np.ndarray):
        return (binary * 255).astype(np.uint8)

    @staticmethod
    def image_info(image: np.ndarray):

        return {
            "width": image.shape[1],
            "height": image.shape[0],
            "channels": 1 if image.ndim == 2 else image.shape[2],
            "dtype": str(image.dtype)
        }