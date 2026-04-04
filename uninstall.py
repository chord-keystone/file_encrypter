import pathlib, winreg, shutil, yaml
from ttkbootstrap.dialogs import MessageDialog, Messagebox

def main():
    
    confirm_button = MessageDialog("Are you sure you want to uninstall?", "Confirm", ["Yes", "Cancel"])
    confirm_button.show(wait_for_result=True)
    
    if confirm_button.result != "Yes":
        return

    # closes the ttk menu
    confirm_button.master.destroy()
    
    etc_path = pathlib.Path("C://", "Users", "cason", "Desktop", "test", "file_encrypter", "etc")
    if not etc_path.exists():
        Messagebox.show_error("Installation configuration file location does not appear to exist")
        return
        
    # etc_path = pathlib.Path(".", "etc").absolute()
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
    shutil.rmtree(config['root'])

if __name__ == "__main__":
    main()