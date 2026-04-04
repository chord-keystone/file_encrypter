import zipfile, pathlib, subprocess
from functional import seq

def main():

    out = subprocess.run(["py", "-m", "pip", "freeze", "-l"], capture_output=True)
    out = out.stdout.decode()
    with open(".\\etc\\dependencies.conf", 'wb') as dep:
        dep.write(seq(out.splitlines()).filter(lambda x: x.find("numpy")==-1).make_string("\n").encode())
       
    thisfile = pathlib.Path(__file__)
    fldr_list = [pathlib.Path(thisfile.parent) / ele for ele in ("context", "etc", "file_encrypter_utils", "resources")]
    with zipfile.ZipFile(pathlib.Path(thisfile.parent) / "package.zip", 'w') as pkg:
        for item in fldr_list:
            pkg.write(item.relative_to(thisfile.parent))
            for subitem in item.rglob("*"):
                if subitem.is_file() and subitem.parent.name != "__pycache__" and subitem.name not in ("configured_devices.json", "enc_config.json"):
                    pkg.write(subitem.relative_to(thisfile.parent))

        pkg.write("encryption_list.txt")
        pkg.write("file_encrypter.py")

if __name__ == '__main__':
    main()