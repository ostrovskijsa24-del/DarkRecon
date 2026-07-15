from modules.stego.combine_planes import PlaneCombiner


def main():

    path = input("Введите путь: ").strip()

    combiner = PlaneCombiner(path)

    red = combiner.channels[2]

    image = combiner.combine(red, [0, 1])

    combiner.save(image, "R", [0, 1])


if __name__ == "__main__":
    main()