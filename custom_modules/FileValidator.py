import os


def fileExists(filePath):
    return os.path.exists(filePath)


def isFile(path):
    return os.path.isfile(path)


def isDir(path):
    return os.path.isdir(path)


def isSymLink(path):
    return os.path.islink(path)
