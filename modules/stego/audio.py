import os
import cv2
import numpy as np


class ImageUtils:
    """
    Общие функции для работы с изображениями.
    Используются всеми анализаторами Stego.
    """

    @staticmethod
    def load_image(path: str) -> np.ndarray:
        """
        Загружает изображение.

        Args:
            path: путь к изображению

        Returns:
            numpy.ndarray

        Raises:
            FileNotFoundError
        """

        if not os.path.exists(path):
            raise FileNotFoundError(f"Файл не найден: {path}")

        image = cv2.imread(path, cv2.IMREAD_UNCHANGED)

        if image is None:
            raise ValueError("OpenCV не смог открыть изображение.")

        return image

    @staticmethod
    def split_channels(image: np.ndarray):
        """
        Возвращает каналы изображения.

        Returns:
            tuple(B,G,R) или (B,G,R,A)
        """

        channels = cv2.split(image)

        return channels

    @staticmethod
    def ensure_output(directory: str):
        """
        Создает папку для результатов.
        """

        os.makedirs(directory, exist_ok=True)

    @staticmethod
    def save_image(path: str, image: np.ndarray):
        """
        Сохраняет изображение.
        """

        cv2.imwrite(path, image)

    @staticmethod
    def normalize_binary(image: np.ndarray):
        """
        Преобразует 0/1 в 0/255.
        """

        return (image * 255).astype(np.uint8)