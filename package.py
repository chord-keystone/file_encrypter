import zipfile, pathlib, subprocess, shutil
from functional import seq
# script that generates a distributable folder which installs the program.

VERSION_STRING = "1.2"

def main():

    # get the python package dependencies:
    out = subprocess.run(["py", "-m", "pip", "freeze", "-l"], capture_output=True)
    out = out.stdout.decode()
    with open(".\\etc\\dependencies.conf", 'wb') as dep:
        dep.write(seq(out.splitlines()).filter(lambda x: x.find("numpy")==-1).make_string("\n").encode())
    
    # make zip file with the necessary install components:
    thisfile = pathlib.Path(__file__)
    fldr_list = [pathlib.Path(thisfile.parent) / ele for ele in ("context", "etc", "file_encrypter_utils", "resources")]
    with zipfile.ZipFile(zip_path:=(pathlib.Path(thisfile.parent) / "package.zip"), 'w') as pkg:
        for item in fldr_list:
            pkg.write(item.relative_to(thisfile.parent))
            for subitem in item.rglob("*"):
                if subitem.is_file() and subitem.parent.name != "__pycache__" and subitem.name not in ("configured_devices.json", "enc_config.json"):
                    pkg.write(subitem.relative_to(thisfile.parent))

        pkg.write("file_encrypter.py")
        pkg.write("uninstall.bat")
        pkg.write("_uninstall_.py")

    # make a folder for the dist:
    container = pathlib.Path(".") / ("file_encrypter_v" + VERSION_STRING)
    if not container.is_dir():
        container.mkdir()

    # copy everything into that folder
    shutil.copyfile(zip_path, container / "package.zip")
    shutil.copyfile("_install_.py", container / "_install_.py")
    shutil.copyfile("install.bat", container / "install.bat")

if __name__ == '__main__':
    main()
    