"""
xor_planes.py

XOR-анализ битовых плоскостей изображения.
"""

from pathlib import Path

import numpy as np

from .utils import ImageUtils


class XorPlaneAnalyzer:

    CHANNEL_NAMES = ["B", "G", "R", "A"]

    def __init__(self, image_path: str):

        self.image_path = Path(image_path)

        self.image = ImageUtils.load_image(self.image_path)

        self.channels = ImageUtils.get_channels(self.image)

    def extract_planes(self, channel):

        planes = []

        for bit in range(8):
            planes.append((channel >> bit) & 1)

        return planes

    def analyze(self):

        image_name = self.image_path.stem

        output_dir = (
            Path(__file__).parent /
            "output" /
            "xor" /
            image_name
        )

        output_dir.mkdir(parents=True, exist_ok=True)

        all_planes = []

        for channel_name, channel in zip(self.CHANNEL_NAMES, self.channels):

            planes = self.extract_planes(channel)

            for bit, plane in enumerate(planes):

                all_planes.append(
                    (
                        f"{channel_name}{bit}",
                        plane
                    )
                )

        total = 0

        for i in range(len(all_planes)):

            name1, plane1 = all_planes[i]

            for j in range(i + 1, len(all_planes)):

                name2, plane2 = all_planes[j]

                xor = np.bitwise_xor(
                    plane1,
                    plane2
                )

                filename = output_dir / f"{name1}_XOR_{name2}.png"

                ImageUtils.save_image(
                    filename,
                    ImageUtils.normalize_binary(xor)
                )

                total += 1

        print(f"\nСоздано XOR изображений: {total}")