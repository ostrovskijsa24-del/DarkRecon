from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from modules.stego.analyzer import StegoAnalyzer


def main():

    analyzer = StegoAnalyzer()

    analyzer.run()


if __name__ == "__main__":
    main()