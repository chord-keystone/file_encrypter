import pathlib, winreg, shutil, yaml, os

def has_admin_windows():
    try:
        temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
    except:
        return False
    else:
        return True

def main():

    if not has_admin_windows():
        print("Admin privilege is needed for install. Rerun as admin.")
        input("Press enter to continue")
        return
    
    confirmation = input("Are you sure you want to uninstall? (yes/no)")
    if confirmation != "yes":
        return
    
    stronger_confirmation = input("WARNING. If you continue and have encrypted files from this program, you will lose access to them. This is PERMANENT and IRREVERSIBLE. If you want it to be reversible, make a backup of the 'file_encrypter/context' folder and use it later. Continue with uninstall? Yes/No")
    if stronger_confirmation != "yes":
        return
    
    etc_path = (pathlib.Path(__file__).parent / "etc").absolute()
    if not etc_path.exists():
        print("Installation configuration file location does not appear to exist")
        return
    
    with (etc_path / "config.yml").open('r') as buf:
        config = yaml.load(buf, yaml.Loader)
    
    # remove shortcuts:
    if 'shortcut_paths' in config:
        for v in config['shortcut_paths'].values():
            if (temp:=pathlib.Path(v)).exists():
                temp.unlink()

    # remove the registry keys
    if 'reg_keys' in config:
        for v in config["reg_keys"].values():
            try:
                winreg.DeleteKey(*v)
            except FileNotFoundError as e:
                print(f"Reg. Key {v[-1]} not found: {e}")

    # remove the installation directory
    for item in (temp_root_path:=pathlib.Path(config['root'])).rglob("*"):
        if item.is_file() and item.name not in ("enc_config.json", "configured_devices.json", "encryption_list.txt"):
            item.unlink()

    for item in temp_root_path.glob("*"):
        if item.is_dir() and item.name not in ("context"):
            shutil.rmtree(item)

    print("Uninstall Complete. Encryption configuration files still remain just in case. You may close this terminal.")

if __name__ == "__main__":
    if (pathlib.Path(__file__).parent / ".git").exists():
        print("Cannot run uninstall script inside of repo.")
    else:
        main()