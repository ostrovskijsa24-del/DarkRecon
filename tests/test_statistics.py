from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from modules.stego.statistics import StatisticsAnalyzer


def main():

    image = input("Введите путь к изображению: ").strip()

    analyzer = StatisticsAnalyzer(image)

    analyzer.run()


if __name__ == "__main__":
    main()