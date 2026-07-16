from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from modules.stego.audio import AudioAnalyzer


def main():

    audio = input("Введите путь к WAV: ").strip()

    analyzer = AudioAnalyzer(audio)

    analyzer.run()


if __name__ == "__main__":
    main()