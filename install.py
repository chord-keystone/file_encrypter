import platform, json, yaml, pathlib

from pyuac import main_requires_admin
from os import getenv
from shutil import copyfile
from zipfile import ZipFile
from functional import seq


def install_windows():

    import winreg # will need this shortly

    # set up destination install path
    # prog_files_dir = pathlib.Path(getenv("ProgramFiles"))
    prog_files_dir = pathlib.Path("C:/") / "Users" / "cason" / "Desktop" / "test"
    
    installroot = prog_files_dir / "file_encryptor"
    if not installroot.is_dir():
        installroot.mkdir()
    else:
        # remove prior installation:
        existing_installation = seq(installroot.rglob("*"))
        existing_installation.filter(lambda x: x.is_file()).for_each(lambda x: x.unlink())
        existing_installation.filter(lambda x: x.is_dir()).for_each(lambda x: x.rmdir())
        
    # verify installation package:
    this_folder = pathlib.Path(__file__).parent
    assert (package:=(this_folder / "package.zip")).is_file

    with ZipFile(package, "r") as z:
        z.extractall(installroot)


    for subfolder in ("context", "etc", "file_encrypter_utils", "resources"):
        assert((installroot / subfolder).is_dir())

    # verify required files:
    for file in (required_files:=(
        installroot / "context" / "enc_config.json",
        installroot / "context" / "supported_devices.json",
        
        installroot / "resources" / "dual_ring_spinner.gif",
        context_menu_icon:=(installroot / "resources" / "icons8-data-matrix-code-24.png"),
        desktop_icon:=(installroot / "resources" / "icons8-data-matrix-code-48.ico"),
        installroot / "resources" / "icons8-data-matrix-code-48.png",
        installroot / "resources" / "icons8-data-matrix-code-96.png"
    )):
        assert file.is_file()

    # generate new files:
    (installroot / "context" / "configured_devices.json").touch()
    (installroot / "etc" / "config.yml").touch()


    etc_vars = {"root":str(installroot)}
    
    # create registry entry:
    try:
        reg_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\file_encryptor")
        winreg.SetValueEx(reg_key, "homepath", 0, winreg.REG_SZ, installroot)
        winreg.CloseKey(reg_key)
    except Exception as e:
        print("An error occurred while creating the registry entry.")
        print(e)
        return
    
    target_fe = json.load(open(".\\context\\enc_config.json", "r"))["file_extension"]["value"]

    # create file extension association:
    try:
        ext_key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, target_fe)
        winreg.SetValueEx(ext_key, "", 0, winreg.REG_SZ, "NCENC")
        winreg.CloseKey(ext_key)

        # get the python executable location from registry:
        py_core_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Python\PythonCore")
        
        # get latest version:
        id = 0
        py_available_versions = []
        while True:
            try:
                py_available_versions.append(winreg.EnumKey(py_core_key, id))
            except OSError:
                break # no more keys
            id += 1
        
        py_latest_version = sorted(py_available_versions, reverse=True)[0]
        pyexe_key = winreg.OpenKey(py_core_key, fr"{py_latest_version}\InstallPath")
        py_exe_path = winreg.QueryValueEx(pyexe_key, "")[0] + "python.exe"

        path_to_script = "C:\\Users\\cason\\Documents\\Important_secure\\Security\\file_encrypter\\file_encrypter.py" #TODO: change to the install path
        class_key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r"NCENC\shell\open\command")
        winreg.SetValueEx(class_key, "", 0, winreg.REG_SZ, f"cmd /k {py_exe_path} {path_to_script} -f %1")
        winreg.CloseKey(class_key)

    except Exception as e:
        print("An error occurred while creating file associations.")
        print(e)
        return


    with (installroot / "etc" / "config.yml").open('w') as config_stream:
        yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)

# @main_requires_admin
def main():
    match platform.uname().system:
        case "Windows":
            install_windows()
        case _:
            raise OSError("Only Windows is supported at this time")
        
if __name__ == "__main__":
    main()