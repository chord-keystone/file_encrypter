import platform, json, yaml, pathlib, venv, subprocess, pyshortcuts, os, shutil
from ttkbootstrap.dialogs import Messagebox

# from pyuac import main_requires_admin
from zipfile import ZipFile
from functional import seq

def install_windows():

    import winreg # will need this shortly

    # set up destination install path
    # prog_files_dir = pathlib.Path(getenv("ProgramFiles"))
    print("Setting default installation dir...")
    prog_files_dir = pathlib.Path("C:/") / "Users" / "cason" / "Desktop" / "test"
    
    print("Checking installation folder...")
    installroot = prog_files_dir / "file_encrypter"
    if not installroot.is_dir():
        installroot.mkdir()
    else:
        # remove prior installation:
        existing_installation = seq(installroot.rglob("*"))
        existing_installation.filter(lambda x: x.is_file()).for_each(lambda x: x.unlink())
        existing_installation.filter(lambda x: x.is_dir()).for_each(lambda x: x.rmdir())
        
    # verify installation package, and unzip
    print("Verifying installation package...")
    this_folder = pathlib.Path(__file__).parent
    assert (package:=(this_folder / "package.zip")).is_file

    print("Copying files...")
    try:
        with ZipFile(package, "r") as z:
            z.extractall(installroot)
    except Exception as e:
        Messagebox.show_error(f"Error unzipping: {e}", "Error")
        return        

    # create venv at the install location
    print("Building python environment...")
    try:
        builder = venv.EnvBuilder(symlinks=False, with_pip=True, system_site_packages=False, clear=True)
        builder.create((v_env_path:=installroot / ".venv"))

        # package dependencies
        print("Installing package dependencies...")
        subprocess.check_call(f"{str(v_env_path / "Scripts" / "activate.bat")} && \
            python -m ensurepip --default-pip && \
            python -m pip install numpy && \
            python -m pip install -r {str(installroot / "etc" / "dependencies.conf")}", shell=True)
        
    except Exception as e:
        Messagebox.show_error(f"Error encountered while generating python dependencies: {e}. Rolling back installation")
        shutil.rmtree(installroot / ".venv")
        return
        
    try:
    # verify
        for subfolder in ("context", "etc", "file_encrypter_utils", "resources"):
            assert((installroot / subfolder).is_dir())

        # verify required files:
        for file in (required_files:=(
            # installroot / "context" / "enc_config.json",
            installroot / "context" / "supported_devices.json",
            installroot / "resources" / "dual_ring_spinner.gif",
            installroot / "resources" / "icons8-data-matrix-code-24.png",
            desktop_icon:=(installroot / "resources" / "icons8-data-matrix-code-48.ico"),
            context_menu_icon:=(installroot / "resources" / "icons8-data-matrix-code-48.png"),
            installroot / "resources" / "icons8-data-matrix-code-96.png"
        )):
            assert file.is_file()

    except AssertionError as e:
        Messagebox.show_error(f"Error validating installation files: {e}")
        return

    # generate new files:
    (config_devices_file:=(installroot / "context" / "configured_devices.json")).touch()    
    with config_devices_file.open('w') as ff:
        # write a default empty object in the file:
        ff.write("{}")

    (installroot / "etc" / "config.yml").touch()

    # correct the naming for the encryption config file
    enc_config_file = installroot / "context" / "enc_config.json"
    san_enc_config = installroot / "context" / "enc_config_san.json"
    san_enc_config.rename(enc_config_file)

    # set up the /etc/yaml variables, which will be referenced by the program later
    etc_vars = {"root":str(installroot)}
    with (installroot / "etc" / "config.yml").open('w') as config_stream:
            yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)

    reg_keys = {}
    shortcut_paths = {}
    
    # make shortcut:
    py_exe_path = installroot / ".venv" / "Scripts" / "pythonw.exe"
    path_to_script = installroot / "file_encrypter.py"
    desktop_path = pathlib.Path("C:\\") / "Users" / os.getenv("USERNAME") / "Desktop"
    
    from pyshortcuts import utils
    def temp_func(input:str):
        return input
    
    utils.fix_filename = temp_func

    try:
        # make the shortcut
        shortcut = pyshortcuts.make_shortcut(str(py_exe_path) + " " + str(installroot / "file_encrypter.py -mnormal"), "File Encrypter", str(installroot), None, str(desktop_icon), str(desktop_path), None)

        # rename without an underscore and save the link paths:
        temp_path = (desktop_path.absolute() / shortcut.name).with_suffix(".lnk")
        temp_path.rename(temp_newname:=str(temp_path).replace("File_Encrypter", "File Encrypter"))
        shortcut_paths['desktop_shortcut'] = temp_newname

        temp_path = (pathlib.Path(shortcut.startmenu_dir) / shortcut.name).with_suffix(".lnk")
        temp_path.rename(temp_newname:=str(temp_path).replace("File_Encrypter", "File Encrypter"))
        shortcut_paths['startmenu_shortcut'] = temp_newname

    except Exception as e:
        Messagebox.show_warning(f"Could not generate shortcut: {e}")
        
    finally:
        etc_vars['shortcut_paths'] = shortcut_paths
        with (installroot / "etc" / "config.yml").open('w') as config_stream:
            yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)

    try:
        # registry editing:
        target_file_ext = json.load((installroot / "context" / "enc_config.json").open("r"))["file_extension"]["value"]
        file_ext_key_name = target_file_ext.lstrip(".").upper()
        
        # file extension association
        reg_keys["extension_key"] = (winreg.HKEY_CLASSES_ROOT, target_file_ext)
        extension_key = winreg.CreateKey(*reg_keys["extension_key"])
        winreg.SetValueEx(extension_key, "", 0, winreg.REG_SZ, file_ext_key_name)
        winreg.CloseKey(extension_key)    

        # file extension open description:
        reg_keys["open_key"] = (winreg.HKEY_CLASSES_ROOT, f"{file_ext_key_name}\\shell\\open")
        open_key = winreg.CreateKey(*reg_keys["open_key"])
        winreg.SetValueEx(open_key, "", 0, winreg.REG_SZ, "Encrypt/decrypt with File Encrypter")
        winreg.CloseKey(open_key)    
        
        # file extension command
        reg_keys["class_key"] = (winreg.HKEY_CLASSES_ROOT, f"{file_ext_key_name}\\shell\\open\\command")
        class_key = winreg.CreateKey(*reg_keys["class_key"])
        winreg.SetValueEx(class_key, "", 0, winreg.REG_SZ, f"{py_exe_path} {path_to_script} -mtarget -t%1")
        winreg.CloseKey(class_key)

        # and icon
        reg_keys["icon_key"] = (winreg.HKEY_CLASSES_ROOT, f"{file_ext_key_name}\\DefaultIcon")
        icon_key = winreg.CreateKey(*reg_keys["icon_key"])
        winreg.SetValueEx(icon_key, "", 0, winreg.REG_SZ, str(context_menu_icon))

        # context menu entry for folders (old context menu)
        reg_keys["dir_key"] = (winreg.HKEY_CLASSES_ROOT, f"Directory\\shell\\file_encrypter")
        dir_key = winreg.CreateKey(*reg_keys["dir_key"])
        winreg.SetValueEx(dir_key, "", 0, winreg.REG_SZ, "Encrypt/decrypt with File Encrypter")
        winreg.SetValueEx(dir_key, "Icon", 0, winreg.REG_SZ, str(context_menu_icon))
        winreg.CloseKey(dir_key)

        reg_keys["dir_command_key"] = (winreg.HKEY_CLASSES_ROOT, f"Directory\\shell\\file_encrypter\\command")
        dir_command_key = winreg.CreateKey(*reg_keys["dir_command_key"])
        winreg.SetValueEx(dir_command_key, "", 0, winreg.REG_SZ, f"{py_exe_path} {path_to_script} -mtarget -t%1")
        winreg.CloseKey(dir_command_key)

        # context menu entry for files (old context menu)
        reg_keys["file_key"] = (winreg.HKEY_CLASSES_ROOT, f"*\\shell\\file_encrypter")
        file_key = winreg.CreateKey(*reg_keys["file_key"])
        winreg.SetValueEx(file_key, "", 0, winreg.REG_SZ, "Encrypt/decrypt with File Encrypter")
        winreg.SetValueEx(file_key, "Icon", 0, winreg.REG_SZ, str(context_menu_icon))
        winreg.CloseKey(file_key)

        reg_keys["file_command_key"] = (winreg.HKEY_CLASSES_ROOT, f"Directory\\shell\\file_encrypter\\command")
        file_command_key = winreg.CreateKey(*reg_keys["file_command_key"])
        winreg.SetValueEx(file_command_key, "", 0, winreg.REG_SZ, f"{py_exe_path} {path_to_script} -mtarget -t%1")
        winreg.CloseKey(file_command_key)

    except Exception as e:
        Messagebox.show_error(f"Error generating file extension associations and/or context menu shortcuts: {e}. Rolling back:")
        for k, v in reg_keys:
            winreg.DeleteKey(*v)
        return 
        
    finally:
        etc_vars["reg_keys"] = reg_keys
        with (installroot / "etc" / "config.yml").open('w') as config_stream:
            yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)
    
    print("Complete")

# @main_requires_admin
def main():
    match platform.uname().system:
        case "Windows":
            install_windows()
        case _:
            raise OSError("Only Windows is supported at this time") 
        
if __name__ == "__main__":
    main()