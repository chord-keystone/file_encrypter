import platform, json, yaml, pathlib, venv, subprocess, pyshortcuts, os, shutil
from secrets import token_bytes

# from pyuac import main_requires_admin
from zipfile import ZipFile
from functional import seq

def has_admin_windows():
    try:
        temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
    except:
        return False
    else:
        return True

def install_windows():

    if not has_admin_windows():
        print("Admin privilege is needed for install. Rerun as admin.")
        input("Press enter to continue")
        return

    import winreg # will need this shortly

    # set up destination install path
    prog_files_dir = pathlib.Path(os.getenv("ProgramFiles"))
    print("Setting default installation dir...")
        
    print("Checking installation folder...")
    installroot = prog_files_dir / "file_encrypter"
    if not installroot.is_dir():
        installroot.mkdir()
    else:
        # remove prior installation, besides config files:
        for item in installroot.rglob("*"):
            if item.is_file() and item.name not in ("configured_devices.json", "enc_config.json", "encryption_list.txt"):
                item.unlink()
        
        for item in installroot.glob("*"):
            if item.is_dir() and item.name not in ("context"):
                shutil.rmtree(item)
        
    # verify installation package, and unzip
    print("Verifying installation package...")
    this_folder = pathlib.Path(__file__).parent
    assert (package:=(this_folder / "package.zip")).is_file

    print("Copying files...")
    try:
        with ZipFile(package, "r") as z:
            z.extractall(installroot)
    except Exception as e:
        print(f"Error unzipping: {e}")
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
        print(f"Error encountered while generating python dependencies: {e}. Rolling back installation")
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
        print(f"Error validating installation files: {e}")
        return

    # generate new files:
    (config_devices_file:=(installroot / "context" / "configured_devices.json")).touch()
    with config_devices_file.open('r') as ff:
        temp_data = ff.read()

    if len(temp_data) == 0:
        with config_devices_file.open('w') as ff:
            # write a default empty object in configured devices file:
            ff.write("{}")

    # two empty files:
    (installroot / "etc" / "config.yml").touch()
    (installroot / "encryption_list.txt").touch()

    # correct the naming for the encryption config file
    enc_config_file = installroot / "context" / "enc_config.json"
    san_enc_config = installroot / "context" / "enc_config_san.json"

    # only replace if it doesn't exist:
    if not enc_config_file.exists():

        san_enc_config.rename(enc_config_file)
        
        # set up a management salt:
        with enc_config_file.open('r') as file:
            enc_config_data = json.loads(file.read())
        enc_config_data['man_salt'] = token_bytes(16).hex()
        with enc_config_file.open('w') as file:
            file.write(json.dumps(enc_config_data))

    else:
        # if it exists, we don't need the copy.
        san_enc_config.unlink()

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
    
    try:
        # make the shortcut
        shortcut = pyshortcuts.make_shortcut(str(py_exe_path) + " " + str(installroot / "file_encrypter.py -mnormal"), "File Encrypter", str(installroot), None, str(desktop_icon), str(desktop_path), None)

        # rename without an underscore and save the link paths:
        temp_path = (desktop_path.absolute() / shortcut.name).with_suffix(".lnk")
        desktop_shortcut_file_name=str(temp_path).replace("File_Encrypter", "File Encrypter")
        if not pathlib.Path(desktop_shortcut_file_name).exists():
            temp_path.rename(desktop_shortcut_file_name)
        else:
            # if it already exists, just replace it
            pathlib.Path(desktop_shortcut_file_name).unlink()
            temp_path.rename(desktop_shortcut_file_name)

        temp_path = (pathlib.Path(shortcut.startmenu_dir) / shortcut.name).with_suffix(".lnk")
        start_menu_shortcut_file_name = str(temp_path).replace("File_Encrypter", "File Encrypter")

        if not pathlib.Path(start_menu_shortcut_file_name).exists():
            temp_path.rename(start_menu_shortcut_file_name)
        else:
            pathlib.Path(start_menu_shortcut_file_name).unlink()
            temp_path.rename(start_menu_shortcut_file_name)

    except Exception as e:
        print(f"Could not generate shortcut: {e}")
        
    finally:
        shortcut_paths['desktop_shortcut'] = desktop_shortcut_file_name
        shortcut_paths['startmenu_shortcut'] = start_menu_shortcut_file_name

        etc_vars['shortcut_paths'] = shortcut_paths
        with (installroot / "etc" / "config.yml").open('w') as config_stream:
            yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)

    # registry keys:
    try:

        command_string = f"\"{py_exe_path}\" \"{path_to_script}\" -mtarget -t\"%1\""
        
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
        winreg.SetValueEx(class_key, "", 0, winreg.REG_SZ, command_string)
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
        winreg.SetValueEx(dir_command_key, "", 0, winreg.REG_SZ, command_string)
        winreg.CloseKey(dir_command_key)

        # context menu entry for files (old context menu)
        reg_keys["file_key"] = (winreg.HKEY_CLASSES_ROOT, f"*\\shell\\file_encrypter")
        file_key = winreg.CreateKey(*reg_keys["file_key"])
        winreg.SetValueEx(file_key, "", 0, winreg.REG_SZ, "Encrypt/decrypt with File Encrypter")
        winreg.SetValueEx(file_key, "Icon", 0, winreg.REG_SZ, str(context_menu_icon))
        winreg.CloseKey(file_key)

        reg_keys["file_command_key"] = (winreg.HKEY_CLASSES_ROOT, f"*\\shell\\file_encrypter\\command")
        file_command_key = winreg.CreateKey(*reg_keys["file_command_key"])
        winreg.SetValueEx(file_command_key, "", 0, winreg.REG_SZ, command_string)
        winreg.CloseKey(file_command_key)

    except Exception as e:
        print(f"Error generating file extension associations and/or context menu shortcuts: {e}. Rolling back:")
        for k, v in reg_keys:
            winreg.DeleteKey(*v)
        return 
        
    finally:
        etc_vars["reg_keys"] = reg_keys
        with (installroot / "etc" / "config.yml").open('w') as config_stream:
            yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)
    
    print("Complete. You may close this terminal.")

def main():
    match platform.uname().system:
        case "Windows":
            install_windows()
        case _:
            raise OSError("Only Windows is supported at this time") 
        
if __name__ == "__main__":
    if (pathlib.Path(__file__).parent / ".git").exists():
        # don't ever ever install to the git repo location. That'd be bad.
        print("Cannot run uninstall script inside of repo.")
    else:
        main()