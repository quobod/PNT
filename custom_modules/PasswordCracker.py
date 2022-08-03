import zipfile

z_file = zipfile.ZipFile("test.zip")
pass_file = open("dictionary.txt")


for line in pass_file.readlines():
    try:
        password = line.strip("\n")
        z_file.extractall(pwd=password)
        print("Password found: {}".format(password))
    except Exception as exc:
        print("Password not found")
