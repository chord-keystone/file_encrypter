import yaml, pathlib, ujson
from os import getenv
from winreg import OpenKey, QueryValueEx, HKEY_CURRENT_USER
from file_encrypter_utils.utils import dict_fromhex
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import yubikit.piv as piv

etc_config = yaml.load((pathlib.Path(".") / "etc" / "config.yml").open("r"), Loader=yaml.Loader)
installroot = pathlib.Path(etc_config['root'])

class config_loader:
    
    def __init__(self):
        self.enc = dict_fromhex(ujson.load(open(installroot / "context" / "enc_config.json", "r")))
        self.device = ujson.load(open(installroot / "context" / "configured_devices.json", "r"))
        self.get_tempdir()
        self.installroot = installroot

        self.keytype_piv = {
                "RSA2048": piv.KEY_TYPE.RSA2048,
                "RSA3072": piv.KEY_TYPE.RSA3072,
                "RSA4096": piv.KEY_TYPE.RSA4096,
                "X25519": piv.KEY_TYPE.X25519}

        self.keytype_ec = {
                "X25519": lambda: x25519.X25519PrivateKey.generate()
        }

        self.keytype_encoding = {
                "X25519": (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        }

    def update_enc(self, new_dict:dict):
        
        if not isinstance(new_dict, dict):
            raise TypeError("The new configuration must be a dictionary.")
        
        # handle key type, which is a name/pair (the file extension won't change programmatically)
        if "key_type" in new_dict:
            new_dict["key_type"] = {"value":new_dict["key_type"], "type":"str"}
        
        self.enc.update(new_dict)
        
        with open(installroot / "context" / "enc_config.json", 'r') as current_config:
            current_dict = ujson.load(current_config)

        if set(self.enc.keys()) != set(current_dict.keys()):
            raise KeyError("The new configuration does not match the current configuration keys.")
        
        # overwrite file with new data:
        with open(installroot / "context" / "enc_config.json", 'w') as config_file:
            ujson.dump(self.enc, config_file, indent=4)

        self.__init__()

    def update_device_parameter(self, new_dict:dict):
        if not isinstance(new_dict, dict):
            raise TypeError("The new configuration must be a dictionary.")
        
        if not all([isinstance(new_dict[key], dict) for key in new_dict.keys()]):
            raise TypeError("Input dict must have a sub-dicitonary for each udpated parameter")
        
        if len(new_dict) != 1:
            raise ValueError("Can only update 1 device's parameters at a time.")
        
        device_name = tuple(new_dict.keys())[0]

        required_keys = {"name", "model", "description", "serial_number", "firmware_version", "management_key", "public_key", "key_type"}
        if not set(new_dict[device_name]) <= required_keys:
            raise KeyError("The updated parameter list does not match the allowed keys.")
        
        self.device[device_name].update(new_dict[device_name])
        
        # overwrite file with new data:
        with open(installroot / "context" / "configured_devices.json", 'w') as config_file:
            ujson.dump(self.device, config_file, indent=4)

        self.__init__()

    def update_device(self, new_dict:dict):

        if not isinstance(new_dict, dict):
            raise TypeError("The new configuration must be a dictionary.")

        self.device.update(new_dict)
        required_keys = {"name", "model", "description", "serial_number", "firmware_version", "management_key", "public_key", "key_type"}

        for key, value in new_dict.items():
            if set(value.keys()) != required_keys:
                raise KeyError(f"The new configuration for device '{key}' does not match the template keys.")

        with open(installroot / "context" / "configured_devices.json", 'w') as config_file:
            ujson.dump(self.device, config_file, indent=4)

        self.__init__()

    @property
    def rsa_or_ec(self):
        ktype = self.enc["key_type"]
        if "RSA" in ktype:
            return "rsa"
        else:
            return "ec"

    def get_tempdir(self):

        tempdir = pathlib.Path(getenv("TEMP"))
        tempdir = tempdir / "file_encryptor"

        if not tempdir.exists():
            tempdir.mkdir()

        self.temp_dir = tempdir


def main():
    pass

if __name__ == "__main__":
    main()