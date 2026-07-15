from tkinter import Tk, filedialog


class FileDialog:
    """
    Диалог выбора файла.
    """

    @staticmethod
    def select_file():

        root = Tk()

        root.withdraw()

        filename = filedialog.askopenfilename(

            title="Выберите изображение",

            filetypes=[

                ("Изображения",
                 "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"),

                ("Аудио",
                 "*.wav"),

                ("Все файлы",
                 "*.*")
            ]
        )

        root.destroy()

        return filename