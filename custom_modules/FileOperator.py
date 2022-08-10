import os
from custom_modules.FileValidator import fileExists, isFile
from custom_modules.TypeTester import arg_is_a_list


def delete_file(file_path):
    if fileExists(file_path) and isFile(file_path):
        os.remove(file_path)
        return not fileExists(file_path)


def append_file(file_path, list_data):
    if arg_is_a_list(list_data):
        if fileExists(file_path) and isFile(file_path):
            deleted = delete_file(file_path)

            if deleted:
                with open(file_path, "a") as f:
                    for d in list_data:
                        f.write(d)

                return fileExists(file_path)
        else:
            with open(file_path, "a") as f:
                for d in list_data:
                    f.write(d)

            return fileExists(file_path)
    return None
