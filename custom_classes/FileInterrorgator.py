from pathlib import PurePath
from custom_modules.FileValidator import exists


class FileInterrogator:
    def __init__(this):
        this.file_path = None

    def set_path(this, path):
        if not exists(path):
            print("\n\tPath {} does not exist\n".format(path))
            return {"status": False, "cause": "Path {} does not exist".format(path)}
        else:
            this.file_path = PurePath(path)
            return {"status": True}

    def extension(this):
        return this.file_path.suffix

    def name(this):
        return this.file_path.stem

    def full_name(this):
        return this.file_path.name

    def absolute_path(this):
        return this.file_path._flavour.pathmod.abspath(this.file_path)

    def __str__(this):
        return "{}'s File Interroragtor".format(this.name)


file_interrogator = FileInterrogator()
