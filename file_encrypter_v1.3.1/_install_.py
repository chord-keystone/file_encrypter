import platform, json, yaml, pathlib, venv, subprocess, os, shutil
from secrets import token_bytes
from zipfile import ZipFile

# installs the program!

def has_admin_windows() -> bool:
    '''Tells if the current instance of python has elevated privilege.'''

    try:
        temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
    except:
        return False
    else:
        return True

def install_windows():
    '''Procedural Windows program installation'''

    if not has_admin_windows():

        input("Setup requires Admin privilege. Please run again with Admin. Press enter to continue")
        return

    import winreg # will need this shortly

    # set up destination install path
    prog_files_dir = pathlib.Path(os.getenv("ProgramFiles"))
    # prog_files_dir = pathlib.Path(os.getenv("USERPROFILE")) / "Desktop" / "test" #for testing
    print("Setting default installation dir...")
        
    print("Checking installation folder...")
    installroot = prog_files_dir / "file_encrypter"
    if not installroot.is_dir():
        installroot.mkdir()
    else: # the install dir was already there
        # remove prior installation
        for item in installroot.rglob("*"):
            if item.is_file():
                item.unlink()

        for item in installroot.glob("*"):
            if item.is_dir():
                shutil.rmtree(item)

    # make local user accessible path in AppData
    userpath = pathlib.Path(os.getenv("APPDATA")) / "file_encrypter"
    if not userpath.exists():
        userpath.mkdir()

    user_context_dir = userpath / "context"
    if not user_context_dir.exists():
        user_context_dir.mkdir()
        
    # 'verify' installation package
    print("Verifying installation package...")
    this_folder = pathlib.Path(__file__).parent
    assert (package:=(this_folder / "package.zip")).is_file

    # unzip/copy/paste the base files
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
        subprocess.check_call(f"\"{str(v_env_path / "Scripts" / "activate.bat")}\" && \
            python -m ensurepip --default-pip && \
            python -m pip install numpy && \
            python -m pip install -r \"{str(installroot / "etc" / "dependencies.conf")}\"", shell=True)
        
    except Exception as e:
        print(f"Error encountered while generating python dependencies: {e}. Rolling back installation")
        shutil.rmtree(installroot / ".venv")
        return
        
    try:
        # verify that the right dirs are there:
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
            assert file.exists()

    except AssertionError as e:
        print(f"Error validating installation files: {e}")
        return

    # generate new files:
    (config_devices_file:=(userpath / "context" / "configured_devices.json")).touch()
    with config_devices_file.open('r') as ff:
        temp_data = ff.read()

    # if the device config file is empty, write a default empty object (so that ujson has something to decode):
    if len(temp_data) == 0:
        with config_devices_file.open('w') as ff:
            ff.write("{}")

    # init two files
    (installroot / "etc" / "config.yml").touch()
    (userpath / "encryption_list.txt").touch()

    # setup for the enc config file, copying the _san.json to the actual file
    enc_config_file = userpath / "context" / "enc_config.json"
    san_enc_config = installroot / "context" / "enc_config_san.json"

    # only replace enc_config.json it doesn't exist:
    if not enc_config_file.exists():

        shutil.move(san_enc_config, enc_config_file)

        # set up a management salt:
        with enc_config_file.open('r') as file:
            enc_config_data = json.loads(file.read())
        enc_config_data['man_salt'] = token_bytes(16).hex()
        with enc_config_file.open('w') as file:
            file.write(json.dumps(enc_config_data))

    else:
        # if it exists, we don't need the _san copy.
        san_enc_config.unlink()

    # move the supported device file to the user path:
    shutil.move(installroot / "context" / "supported_devices.json", userpath / "context" / "supported_devices.json")

    # clean up our own droppings
    (installroot / "context").rmdir()
    
    # set up the /etc/yaml variables, which will be referenced by the program later
    etc_vars = {"root":str(installroot), "user_path":str(userpath)}
    with (installroot / "etc" / "config.yml").open('w') as config_stream:
            yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)

    reg_keys = {}
    shortcut_paths = {}
    
    # make shortcut(s):
    py_exe_path = installroot / ".venv" / "Scripts" / "pythonw.exe"
    path_to_script = installroot / "file_encrypter.py"
    desktop_path = pathlib.Path(os.getenv("USERPROFILE")) / "Desktop"
    
    try:

        desktop_shortcut_file_name = desktop_path / "File Encrypter.lnk"
        make_obj_command = f"$s=(New-Object -COM WScript.Shell).CreateShortcut('{str(desktop_shortcut_file_name)}');"
        set_path_command = f"$s.TargetPath='\"{str(py_exe_path)}\"'"
        set_args_command = f"$s.Arguments='\"{str(installroot / "file_encrypter.py")}\" -mnormal'"
        set_icon_command = f"$s.IconLocation='{str(desktop_icon)}'"
        save_command = "$s.save()"

        # make desktop shortcut
        output = subprocess.run(["powershell.exe", ";".join((make_obj_command, set_path_command, set_args_command, set_icon_command, save_command))], capture_output=True)
        if output.returncode != 0:
            raise SyntaxError(output.stderr)

        # make start menu shortcut
        start_menu_shortcut_file_name = pathlib.Path(os.getenv("APPDATA")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "File Encrypter.lnk"
        make_obj_command = f"$s=(New-Object -COM WScript.Shell).CreateShortcut('{str(start_menu_shortcut_file_name)}');"
        output = subprocess.run(["powershell.exe", ";".join((make_obj_command, set_path_command, set_args_command, set_icon_command, save_command))], capture_output=True)
        if output.returncode != 0:
            raise SyntaxError(output.stderr)        
        
    except Exception as e:
        print(f"Could not generate shortcut: {e}")
        
    finally:
        # collect/dump the config info:
        shortcut_paths['desktop_shortcut'] = desktop_shortcut_file_name
        shortcut_paths['startmenu_shortcut'] = start_menu_shortcut_file_name

        etc_vars['shortcut_paths'] = shortcut_paths
        with (installroot / "etc" / "config.yml").open('w') as config_stream:
            yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)

    # registry keys:
    try:
        # this is the command to run file-encrypter in any of the context menus:
        command_string = f"\"{py_exe_path}\" \"{path_to_script}\" -mtarget -t\"%1\""
        
        target_file_ext = json.load((userpath / "context" / "enc_config.json").open("r"))["file_extension"]["value"]
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
        winreg.SetValueEx(dir_key, "Icon", 0, winreg.REG_SZ, str(desktop_icon))
        winreg.CloseKey(dir_key)

        reg_keys["dir_command_key"] = (winreg.HKEY_CLASSES_ROOT, f"Directory\\shell\\file_encrypter\\command")
        dir_command_key = winreg.CreateKey(*reg_keys["dir_command_key"])
        winreg.SetValueEx(dir_command_key, "", 0, winreg.REG_SZ, command_string)
        winreg.CloseKey(dir_command_key)

        # context menu entry for files (old context menu)
        reg_keys["file_key"] = (winreg.HKEY_CLASSES_ROOT, f"*\\shell\\file_encrypter")
        file_key = winreg.CreateKey(*reg_keys["file_key"])
        winreg.SetValueEx(file_key, "", 0, winreg.REG_SZ, "Encrypt/decrypt with File Encrypter")
        winreg.SetValueEx(file_key, "Icon", 0, winreg.REG_SZ, str(desktop_icon))
        winreg.CloseKey(file_key)

        reg_keys["file_command_key"] = (winreg.HKEY_CLASSES_ROOT, f"*\\shell\\file_encrypter\\command")
        file_command_key = winreg.CreateKey(*reg_keys["file_command_key"])
        winreg.SetValueEx(file_command_key, "", 0, winreg.REG_SZ, command_string)
        winreg.CloseKey(file_command_key)

    except Exception as e:
        print(f"Error generating file extension associations and/or context menu shortcuts: {e}. Rolling back:")
        for v in reg_keys.values():
            winreg.DeleteKey(*v)
        return 
        
    finally:
        # collect/dump install info:
        etc_vars["reg_keys"] = reg_keys
        with (installroot / "etc" / "config.yml").open('w') as config_stream:
            yaml.dump(etc_vars, config_stream, Dumper=yaml.Dumper)
    
    print("Complete. You may close this terminal.")

def main():
    # OS gateway:
    match platform.uname().system:
        case "Windows":
            install_windows()
        case _:
            raise OSError("Only Windows is supported at this time") 
        
if __name__ == "__main__":
    if (pathlib.Path(__file__).parent / ".git").exists():
        # don't ever ever install to the git repo location. That'd be bad.
        print("Cannot run install script inside of repo.")
    else:
        main()