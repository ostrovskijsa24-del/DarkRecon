from modules.stego.bitplanes import BitPlaneAnalyzer

def main():

    path = input("Введите путь к изображению: ")

    analyzer = BitPlaneAnalyzer(path)

    analyzer.extract_all()


if __name__ == "__main__":
    main()