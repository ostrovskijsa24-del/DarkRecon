"""
utils.py

Вспомогательные функции для работы с изображениями.
"""

from pathlib import Path

import cv2
import numpy as np


class ImageUtils:

    @staticmethod
    def load_image(file_path: str | Path) -> np.ndarray:

        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(
                f"Файл не найден:\n{file_path}"
            )

        image = cv2.imread(str(file_path), cv2.IMREAD_UNCHANGED)

        if image is None:
            raise ValueError(
                f"OpenCV не смог открыть:\n{file_path}"
            )

        return image

    @staticmethod
    def save_image(file_path: str | Path, image: np.ndarray):

        file_path = Path(file_path)

        file_path.parent.mkdir(parents=True, exist_ok=True)

        cv2.imwrite(str(file_path), image)

    @staticmethod
    def get_channels(image):

        return cv2.split(image)

    @staticmethod
    def normalize_binary(binary):

        return (binary * 255).astype(np.uint8)

    @staticmethod
    def image_info(image):

        return {
            "width": image.shape[1],
            "height": image.shape[0],
            "channels": 1 if image.ndim == 2 else image.shape[2],
            "dtype": str(image.dtype)
        }