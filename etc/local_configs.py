import yaml, pathlib, ujson
from os import getenv
from file_encrypter_utils.utils import dict_fromhex
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import yubikit.piv as piv

# this file handles configuration options, mostly organizing a bunch of dicts.

# "bootstrapping":
etc_config = yaml.load((pathlib.Path(__file__).parent / "config.yml").open("r"), Loader=yaml.Loader)
installroot = pathlib.Path(etc_config['root'])
userpath = pathlib.Path(etc_config['user_path'])

class config_loader:
    '''Configuration Handler. Loads by itself based on relative file paths to expected .json files.'''
    
    def __init__(self):

        # load the encryption config file:
        try:
            self.enc = dict_fromhex(ujson.load(open(userpath / "context" / "enc_config.json", "r")))
        except FileNotFoundError as e:
            raise FileNotFoundError("Encryption settings configuration file not found. Check installation.")
        
        # load the configured devices config file:
        try:
            self.device = ujson.load(open(userpath / "context" / "configured_devices.json", "r"))
        except FileNotFoundError as e:
            raise FileNotFoundError("Supported devices configuration file not found. Check installation.")

        # self.get_tempdir() # makes a folder in AppData/Temp - currently unused

        self.installroot = installroot
        self.userpath = userpath

        # some dicts - kept as dicts in the code and not config files due to some python typing
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
        '''udpates the encryption config file.

            :param dict new_dict: a dict, assumed to be an additional property or change - not an entirely new dict.
        
        '''
        
        if not isinstance(new_dict, dict):
            raise TypeError("The new configuration must be a dictionary.")
        
        # handle key type, which is a name/pair (the file extension won't change programmatically)
        if "key_type" in new_dict:
            new_dict["key_type"] = {"value":new_dict["key_type"], "type":"str"}
        
        self.enc.update(new_dict)
        
        # cross-reference the old config file - the keys should not change
        with open(userpath / "context" / "enc_config.json", 'r') as current_config:
            current_dict = ujson.load(current_config)

        if set(self.enc.keys()) != set(current_dict.keys()):
            raise KeyError("The new configuration does not match the current configuration keys.")
        
        # overwrite file with new data:
        with open(userpath / "context" / "enc_config.json", 'w') as config_file:
            ujson.dump(self.enc, config_file, indent=4)

        self.__init__()

    def update_device_parameter(self, new_dict:dict):
        '''Updates a level-2 nested object's parameter in the device configuration file

        :param dict new_dict: A scalar dict with a sub-dict for each updated parameter
        '''

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
        with open(userpath / "context" / "configured_devices.json", 'w') as config_file:
            ujson.dump(self.device, config_file, indent=4)

        self.__init__()

    def update_device(self, new_dict:dict):
        '''udpates the device config file.

            :param dict new_dict: a dict, assumed to be an additional property or change - not an entirely new dict.
        
        '''

        if not isinstance(new_dict, dict):
            raise TypeError("The new configuration must be a dictionary.")

        self.device.update(new_dict)

        # this time the keys are set in stone and defined here:
        required_keys = {"name", "model", "description", "serial_number", "firmware_version", "management_key", "public_key", "key_type"}

        # validate that they match up
        for key, value in new_dict.items():
            if set(value.keys()) != required_keys:
                raise KeyError(f"The new configuration for device '{key}' does not match the template keys.")

        # write output
        with open(userpath / "context" / "configured_devices.json", 'w') as config_file:
            ujson.dump(self.device, config_file, indent=4)

        self.__init__()

    @property
    def rsa_or_ec(self):
        '''Returns "rsa" if the key type is rsa, and "ec" if the key type is "ec".'''
        ktype = self.enc["key_type"]
        if "RSA" in ktype:
            return "rsa"
        else:
            # completely ignoring any emergent type of asymmetric cryptograph
            return "ec"

    def get_tempdir(self):
        '''Generates a dir in C:\\Users\\user\\AppData\\Temp. Not Used'''

        tempdir = pathlib.Path(getenv("TEMP"))
        tempdir = tempdir / "file_encryptor"

        if not tempdir.exists():
            tempdir.mkdir()

        self.temp_dir = tempdir

def main():
    pass

if __name__ == "__main__":
    main()