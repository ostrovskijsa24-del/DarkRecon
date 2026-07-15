from modules.stego.xor_planes import XorPlaneAnalyzer


def main():

    path = input("Введите путь к изображению: ").strip()

    analyzer = XorPlaneAnalyzer(path)

    analyzer.analyze()


if __name__ == "__main__":
    main()