import pathlib, winreg, shutil, yaml, os
# uninstall script. using minimal packages so we don't have to activate the venv, which messes up the uninstall by holding some packages there.

def has_admin_windows():
    '''Tells if the current instance of python has elevated privilege.'''

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
    
    # issue several warnings to deter frivolity
    confirmation = input("Are you sure you want to uninstall? (yes/no): ")
    if confirmation != "yes":
        return
    
    stronger_confirmation = input("WARNING. If you continue and have encrypted files from this program, you will lose access to them. If you delete the config files in <user>/AppData/file_encrypter, this becomes PERMANENT and IRREVERSIBLE. Continue with uninstall? (yes/no): ")
    if stronger_confirmation != "yes":
        return
    
    # if the install config file doesn't exist, we definitely can't uninstall
    etc_path = (pathlib.Path(__file__).parent / "etc").absolute()
    if not etc_path.exists():
        print("Installation configuration file location does not appear to exist")
        return
    
    # load the install config
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

    # lasty remove the installation directory
    shutil.rmtree(config['root'])
    
    print("Uninstall Complete. Encryption configuration files still remain just in case. You may close this terminal.")

if __name__ == "__main__":
    if (pathlib.Path(__file__).parent / ".git").exists():
        print("Cannot run uninstall script inside of repo.")
    else:
        main()