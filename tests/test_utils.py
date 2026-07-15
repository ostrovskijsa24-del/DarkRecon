from stego.utils import ImageUtils


def main():
    image = ImageUtils.load_image("tests/images/thumb.png")

    info = ImageUtils.image_info(image)

    print("Изображение успешно открыто.\n")
    print(info)


if __name__ == "__main__":
    main()