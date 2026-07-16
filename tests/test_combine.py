from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from modules.stego.combine_planes import PlaneCombiner


def main():

    image = input("Введите путь к изображению: ").strip()

    combiner = PlaneCombiner(image)

    combiner.run()


if __name__ == "__main__":
    main()