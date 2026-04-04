# full imports:
import ujson, threading, pathlib

# program-specific imports:
from file_encrypter_utils import paranoid_random, ec_lite, utils, ui_utils
from etc import local_configs as cfg

# cryptography core
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec, x25519
import cryptography.hazmat.primitives.asymmetric.padding as apad
from cryptography.hazmat.primitives.ciphers import aead, algorithms, modes, Cipher
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# yubikit imports
import yubikit.piv as piv
import yubikit.core
import yubikit.core.smartcard as ysmart
from ykman.device import list_all_devices, _UsbCompositeDevice, DeviceInfo
from ykman.pcsc import CardConnectionException

# specific imports
from enum import Enum
from math import ceil
from datetime import datetime, timedelta
from sys import getsizeof
from functional.pipeline import Sequence
from functional import seq
from dataclasses import dataclass
from threading import Lock
from multiprocessing.managers import ListProxy, ValueProxy
from multiprocessing import Manager
from multiprocessing import Pool
from argparse import ArgumentParser
from time import sleep
from os import startfile, cpu_count, utime
from base64 import urlsafe_b64decode, urlsafe_b64encode
from zipfile import ZipFile
from functools import partial
from datetime import datetime
from secrets import token_bytes
from hashlib import sha256
from time import time_ns

# ui imports:
from ttkbootstrap.dialogs import Messagebox, QueryDialog
import ttkbootstrap as ttk

# global instances:
try:
    config = cfg.config_loader()
except FileNotFoundError as e:
    Messagebox.show_error(e.strerror, "Error")

FILE_BUFFER_MAX = 2**31-1
MAX_PATH = 255
PAD_TGT = 125
GRAIN_ENCRYPTION = 180
FIRST_BYTES_LEN = len(config.enc['signature_device'])
MAX_HEADER = 390 + 2**16 + FIRST_BYTES_LEN

SIG_DEV = config.enc['signature_device']
SIG_PWD = config.enc['signature_password']

@dataclass
class compatible_device:
    name: str
    serial_number: str
    handle: _UsbCompositeDevice
    info: DeviceInfo

@dataclass
class split_exception_msg:
    before:str
    msglist:list[str]
    after:str

class encrypt_action(Enum):
    encrypt_password = 0
    decrypt_password = 1
    encrypt_device = 2
    decrypt_device = 3

class file_encrypter:

    _mutex = Lock()
    
    def __init__(self, 
        file_source: Sequence,
        action:encrypt_action,
        filename_obcuration:bool = False,
        cached_pin:str = ""
        ):
        """ File encrypter/decrypter class.
            :param file_source: list of files to encrypt/decrypt
            :param action: the action to perform (from encrypt_action enum)
            :param filename_obcuration: whether to encrypt the file names
            :param cached_pin: cached PIN for device authentication
        """
        
        if not isinstance(file_source, Sequence) or not file_source:
            raise ValueError("File source must be a non-empty seq of file paths.")
        elif not file_source.map(lambda x: isinstance(x, pathlib.Path)).all():
            raise TypeError("File source must be a list of strings (of paths).")
        
        _action_map = {
            encrypt_action.encrypt_device: self._symmetric_encrypt,
            encrypt_action.encrypt_password: self._symmetric_encrypt, 
            encrypt_action.decrypt_device : self._symmetric_decrypt,
            encrypt_action.decrypt_password : self._symmetric_decrypt
        }

        _print_success_map = {
                encrypt_action.encrypt_device: f"Encrypted {file_source.len()} files.",
                encrypt_action.encrypt_password: f"Encrypted {file_source.len()} files.",
                encrypt_action.decrypt_device : f"Decrypted {file_source.len()} files.",
                encrypt_action.decrypt_password : f"Decrypted {file_source.len()} files.",
        }
        
        self.header = {}
        self.returned_files = []
        self.cached_pin = cached_pin
        self.filename_obscuration = filename_obcuration

        self.header.update({
            "symmetric_type": config.enc["symmetric_type"],
            "symmetric_kdf": config.enc["symmetric_kdf"],
            "checksum_value": config.enc["checksum_value"]})
        
        using_pool : bool = (n_pool:= file_source.len()//GRAIN_ENCRYPTION + 1) > 1
        using_pbar : bool = file_source.len() > 5

        if using_pool:
            _manager = Manager()
            _returned_list : ListProxy = _manager.list()
            counter : ValueProxy = _manager.Value(int, 0)

        else:
            # just do a simple list if not using parallel
            _returned_list :list = []
            counter:int = 0

        # if using parallelism, include the progress ui:
        if using_pbar:
            pbar_container = ttk.Toplevel("Progress", size=(600, 160))
            pbar = ttk.Progressbar(pbar_container, value=0, maximum=file_source.len(), length=550, bootstyle="info-striped", mode="determinate")
            pbar.grid(column=0, row=0, columnspan=2, padx=10, pady=10)
            plabel = ttk.Label(pbar_container, text="Encrypting...", wraplength=550)
            if action in (encrypt_action.decrypt_device, encrypt_action.decrypt_password):
                plabel['text'] = "Decrypting..."
            plabel.grid(column=0, row=1, columnspan=2, sticky='w')
            pbar_container.withdraw()
        
        def error_callback_fcn(e:BaseException):
            print(f"Error: {str(e)}")

        match action:

            case encrypt_action.encrypt_password:

                self.head_first_bytes = config.enc["signature_password"]
                self.header["method"] = "password"
                if len(self.cached_pin) != 0:
                    password = self.cached_pin
                else:
                    try:
                        password = self.get_password(action)
                    except ValueError:
                        return

                _symm_key = password.encode()

            case encrypt_action.decrypt_password:
                
                try:
                    password = self.get_password(action)
                    self.cached_pin = password
                except ValueError:
                    return
                
                _symm_key = password.encode()
                
            case encrypt_action.encrypt_device:

                self.head_first_bytes = config.enc["signature_device"]
                self.header["method"] = "device"
                match config.rsa_or_ec:
                   
                    case "rsa":

                        if config.enc["skey_base"] == "00":
                            Messagebox.show_error("Device symmetric key is either not set up or configured to EC when device is set up for RSA. Select 'New Symmetric Key' from the configuration menu.")
                            return

                        try:
                            _symm_key = self._asymmetryc_decrypt(config.enc["skey_base"])
                        except ValueError as v:
                            Messagebox.show_error(f"Failed to decrypt symmetric key: {v}", title="Error")
                            return
                        except CardConnectionException as c:
                            Messagebox.show_error(f"Error: {c}.", title="Error")
                            return
                        except ysmart.ApduError as a:
                            Messagebox.show_error(f"Device is not configured correctly. Run Configuration first: {a}", title="Error")
                            return
                        
                    case "ec":
                        try:
                            _symm_key = self._ec_asym_keyex()
                        except ValueError as v:
                            Messagebox.show_error(f"Failed to decrypt symmetric key: {v}", title="Error")
                            return
                        except CardConnectionException as c:
                            Messagebox.show_error(f"Error: {c}.", title="Error")
                            return
                        except ysmart.ApduError as a:
                            Messagebox.show_error(f"Device is unconfigured. Run Configuration first: {a}", title="Error")
                            return
                
            case encrypt_action.decrypt_device:

                match config.rsa_or_ec:
                    case "rsa":
                        try:
                            _symm_key = self._asymmetryc_decrypt(config.enc["skey_base"])
                        except ValueError as v:
                            Messagebox.show_error(f"Failed to derive symmetric key: {v}", title="Error")
                            return
                        except CardConnectionException as c:
                            Messagebox.show_error(f"Error: {c}.", title="Error")
                            return
                        except ysmart.ApduError as a:
                            Messagebox.show_error(f"Device is not configured correctly. Run Configuration first: {a}", title="Error")
                            return
                        
                    case "ec":
                        try:
                            _symm_key = self._ec_asym_keyex()
                        except ValueError as v:
                            Messagebox.show_error(f"Failed to derive symmetric key: {v}", title="Error")
                            return
                        except CardConnectionException as c:
                            Messagebox.show_error(f"Error: {c}.", title="Error")
                            return
                        except ysmart.ApduError as a:
                            Messagebox.show_error(f"Device is unconfigured. Run Configuration first: {a}", title="Error")
                            return

        if using_pbar: pbar_container.deiconify()
        if using_pool:

            pool = Pool( max(min(n_pool, cpu_count() - 2), 2))
            result = pool.map_async(
                partial(
                    _action_map[action], 
                    raw_key=_symm_key, 
                    _tracking=(_returned_list, counter)
                    ),
                file_source, 
                chunksize=GRAIN_ENCRYPTION, 
                error_callback=error_callback_fcn
            )
                
            while not result.ready():
                with self._mutex:
                    pbar['value'] = counter.value
                # plabel['text'] = file
                pbar_container.update()
                pbar_container.lift()
                sleep(0.2)

            pool.close()
            pool.join()

        else:
            for ff in file_source:
                _action_map[action](ff, raw_key=_symm_key, _tracking=(_returned_list, counter))
                if using_pbar:
                    pbar['value'] += 1
                    # plabel['text'] = file
                    pbar_container.update()
                    pbar_container.lift()

        # print the success messagebox if we got this far.
        Messagebox.show_info(_print_success_map[action], title="Complete")

        # cleanup:
        if using_pbar: pbar_container.destroy()
        self.header = token_bytes(getsizeof(self.header))  # destroy the header
        self.returned_files = list(_returned_list) # update the returned file list
        
    def _symmetric_encrypt(self, file:pathlib.Path, raw_key:bytes, _tracking: tuple[ListProxy|list, ValueProxy|int]):
        """ Heavy hitting symmetric encryption function.
            Encrypts the input file with ChaCha20-Poly1305 AEAD encryption, given a secure key.
            Exports the header into the associated authenticated data in the encryption stream for data integrity.
            :param file: the file to encrypt
        """

        this_header = {}
        this_header.update(self.header)

        # create a salt:
        this_salt = token_bytes(32)
        this_header["salt"] = this_salt.hex()
        
        _skey = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=this_salt,
            info=None).derive(raw_key)

        nonce = token_bytes(12+16)
        this_header["nonce"] = nonce.hex() #Nonce goes into the header
        this_header["extension"] = file.suffix
        this_header["filename_obscuration"] = self.filename_obscuration

        file_stat = file.stat()
        this_header["time_attrs"] = (file_stat.st_ctime_ns, file_stat.st_mtime_ns)
        
        # get the header:
        head = ujson.dumps(this_header).encode('utf-8')

        # mask the head up to this point (used in the checksum for chacha20-poly1305):
        h_obs = head_obscuration().generate_head()
        masked_head = self.mask_text(head, mask=h_obs["mask"])
        head_length = len(masked_head).to_bytes(4)

        if self.filename_obscuration:
            
            # get filename in plain text
            filename_plaintext = file.name.encode()
        
            # pad the filename if it's short for additional security:
            if len(filename_plaintext) < PAD_TGT:

                # get padding length, accounting for the file path potentially being too long (MAX_PATH=255 usually):
                total_len = (min(MAX_PATH - len(str(file.parent.with_suffix(config.enc["file_extension"]))), PAD_TGT) * 3/4).__floor__()
                n_pad = total_len - len(filename_plaintext)
                
                # pad
                padded_filename = filename_plaintext + b"\x00" * (n_pad - 1)
                padded_filename += (len(filename_plaintext)).to_bytes() #last byte is the length of the filename itself

            else:
                # the filename is longer than the minimuim padding target, so we use the original file name
                padded_filename = filename_plaintext #the file already exists if it got to this point, so the path cannot be too long.

            fname_enc = Cipher(
                algorithm=algorithms.Camellia(_skey),
                mode=modes.OFB(nonce[12:])
                ).encryptor()
            
            filename_ciphertext = fname_enc.update(padded_filename) + fname_enc.finalize()
            urlsafe_filename = urlsafe_b64encode(filename_ciphertext).decode("utf-8")
            new_file = file.parent / urlsafe_filename

        else:
            # no filename obscuration
            new_file = file

        new_file = new_file.with_suffix(config.enc["file_extension"])

        # update live update/output lists
        with self._mutex:
            _tracking[0].append(new_file)
            if isinstance(_tracking[1], ValueProxy):
                _tracking[1].value += 1

        # write the encrypted file:
        with open(new_file, 'wb') as f_new:
            f_new.write(self.head_first_bytes) # specifies device vs password encryption
            f_new.write(h_obs['signature'])
            f_new.write(head_length)
            f_new.write(masked_head) # write the masked head

            # read file
            with open(file, 'rb') as f_old:

                total_file_size = f_old.seek(0, 2)
                f_old.seek(0, 0)

                if total_file_size >= FILE_BUFFER_MAX:
                    
                    # stream until it's done
                    n_iter = 0
                    while f_old.tell() < total_file_size:
                        file_contents_plaintext = f_old.read(FILE_BUFFER_MAX)
                        cipher_text = aead.ChaCha20Poly1305(_skey).encrypt((int.from_bytes(nonce[:12])+n_iter).to_bytes(12), file_contents_plaintext, head)
                        offset = int(len(cipher_text) - len(file_contents_plaintext)).to_bytes(length=4, byteorder="big", signed=True)
                        f_new.write(offset)
                        f_new.write(cipher_text)
                        n_iter+=1

                else:
                    file_contents_plaintext = f_old.read()

                    # encrypt
                    cipher_text = aead.ChaCha20Poly1305(_skey).encrypt(nonce[:12], file_contents_plaintext, head)
                    # cipher_text = aead.AESGCM(_skey).encrypt(nonce[:12], file_contents_plaintext, head)

                    f_new.write(cipher_text)

        self.secure_destroy(file)  # securely destroy the original file

        # destroy the key
        _skey = token_bytes(len(_skey))

    def _symmetric_decrypt(self, file:pathlib.Path, raw_key:bytes, _tracking: tuple[ListProxy|list, ValueProxy|int]):
        """ Symmetric decryption function.
            Decrypts the input file with ChaCha20-Poly1305 AEAD encryption, given a secure key in raw_key.
            Reads the file header to get the nonce, salt, etc, authenticates the header, and decrypts the file.
            :param file: the file to decrypt
        """

        # read the header:
        try:
            this_header = file_encrypter.read_header(file)
        except ValueError as v:
            raise v

        # get the hashed key:
        that_salt = bytes.fromhex(this_header["salt"])
        _skey = HKDF(algorithm=hashes.SHA256(),
                            length = 32,
                            salt = that_salt,
                            info=None).derive(raw_key)
        
        nonce = bytes.fromhex(this_header["nonce"])

        # handle file name obscuration
        if this_header['filename_obscuration']:

            # get the file name, decode from base64 to bytes
            filename_ciphertext = file.with_suffix('').name
            decode_ct = urlsafe_b64decode(filename_ciphertext.encode())

            # camellia decryptor
            filename_dec = Cipher(
                algorithm=algorithms.Camellia(_skey),
                mode=modes.OFB(nonce[12:])
                ).decryptor()
            
            filename_plaintext = filename_dec.update(decode_ct) + filename_dec.finalize()

            # remove padding
            if filename_plaintext[-2] == 0:
                filename_plaintext = filename_plaintext[:filename_plaintext[-1]]

            new_file = file.parent / filename_plaintext.decode()

        else:
            # no obscuration
            new_file = file.with_suffix(this_header["extension"])

        try:
            utime(new_file, tuple(this_header["time_attrs"]))
        except Exception as o:
            pass

        with self._mutex:
            _tracking[0].append(new_file)
            if isinstance(_tracking[1], ValueProxy):
                _tracking[1].value += 1

         # write file
        with new_file.open('wb') as f_new:
            
            # read file and decrypt
            with file.open('rb') as f_old:

                total_file_size = f_old.seek(0, 2)
                contents_size = total_file_size - FIRST_BYTES_LEN - this_header["header_length"]
                f_old.seek(FIRST_BYTES_LEN+this_header["header_length"], 0)

                if contents_size > FILE_BUFFER_MAX:
                    n_iter = 0
                    while f_old.tell() < total_file_size:
                        offset = int.from_bytes(f_old.read(4), byteorder="big", signed=True)
                        cipher_text = f_old.read(FILE_BUFFER_MAX+offset)
                        plain_text = aead.ChaCha20Poly1305(_skey).decrypt((int.from_bytes(nonce[:12])+n_iter).to_bytes(12), cipher_text, this_header["bstring"])
                        f_new.write(plain_text)
                        n_iter+=1
                else:

                    cipher_text = f_old.read()
            
                    # decrypt step:
                    plain_text = aead.ChaCha20Poly1305(_skey).decrypt(nonce[:12], cipher_text, this_header["bstring"])
                    # plain_text = aead.AESGCM(_skey).decrypt(nonce[:12], cipher_text, this_header["bstring"])

                    f_new.write(plain_text)

        # destroy original file:
        self.secure_destroy(file)

        # destroy the key
        _skey = token_bytes(len(_skey))

    def _asymmetryc_decrypt(self, skey_base:bytes) -> bytes:
        """ Decrypts symmetric key using the private key on the device.
            Returns the decrypted symmetric key.
            :param skey_base: the wrapped symmetric key to decrypt
        """

        try:
            device = device_interface.get_device()
        except ConnectionError as c:
            raise CardConnectionException("No configured device found. Please connect valid device")
        except IndexError as e:
            raise CardConnectionException("No configured device found. Please connect valid device")

        with device.handle.open_connection(ysmart.SmartCardConnection) as connection:
            
            # open session and auth
            session = piv.PivSession(connection=connection)

            try:
                key_info = session.get_slot_metadata(piv.SLOT.KEY_MANAGEMENT)
            except ysmart.ApduError as a:
                raise a
            
            self.cached_pin = device_interface.pin_authenticate(session, self.cached_pin)
            
            # decrypt:
            skey_long = session.decrypt(
                slot=piv.SLOT.KEY_MANAGEMENT,
                cipher_text=skey_base,
                padding = apad.OAEP(
                        mgf=apad.MGF1(
                            algorithm=hashes.SHA256()
                            ), 
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            
            return skey_long
        
    def _ec_asym_keyex(self) -> bytes:
        """ Performs key exchange to derive the key
        """

        try:
            device = device_interface.get_device()
        except ConnectionError as c:
            raise CardConnectionException("No configured device found. Please connect valid device")
        except IndexError as e:
            raise CardConnectionException("No configured device found. Please connect valid device")
        
        if config.enc["dual_device"]:

            if len(config.device) != 2:
                raise ValueError("Dual device key exchange requires two configured devices.")

            # dual device key uses the other devices' public key
            pubkey = (seq(config.device.values())
                .map(lambda x: (x["name"], x["public_key"]))
                .filter(lambda x: x[0]!= device.name)
                .map(lambda x: bytes.fromhex(x[1]))[0]
            )
            
            if config.enc["key_type"] == "X25519":
                sender_public = x25519.X25519PublicKey.from_public_bytes(pubkey)
            else:
                sender_public = serialization.load_der_public_key(pubkey)
            
        else:
            # why did X25519 have to be special...
            if config.enc["key_type"] == "X25519":
                sender_public = x25519.X25519PublicKey.from_public_bytes(config.enc["public_key"])
            else:
                sender_public = serialization.load_der_public_key(config.enc["public_key"])


        with device.handle.open_connection(ysmart.SmartCardConnection) as connection:
            
            # open session and auth
            session = piv.PivSession(connection=connection)

            try:
                session.get_slot_metadata(piv.SLOT.KEY_MANAGEMENT)
            except ysmart.ApduError as a:
                raise a
            
            self.cached_pin = device_interface.pin_authenticate(session, self.cached_pin)

            skey_short = session.calculate_secret(
                slot=piv.SLOT.KEY_MANAGEMENT,
                peer_public_key=sender_public,
            )
                                    
        return skey_short
        
    @staticmethod
    def secure_destroy(file:pathlib.Path) -> None:
        """ Triple pass overwrite """

        with file.open('r+b') as f:

            file_size = f.seek(0, 2)
            
            # first pass all zeros
            f.seek(0, 0)
            while f.tell() < file_size:

                file_contents = f.read(min(FILE_BUFFER_MAX, file_size))
                this_buffer_length = len(file_contents)
                this_pos=f.tell()

                f.seek(this_pos - this_buffer_length, 0)
                f.write(0x00.to_bytes()*this_buffer_length)
                f.seek(this_pos + this_buffer_length, 0)

            # second pass all 1's
            f.seek(0, 0)
            while f.tell() < file_size:

                file_contents = f.read(min(FILE_BUFFER_MAX, file_size))
                this_buffer_length = len(file_contents)
                this_pos=f.tell()

                f.seek(this_pos - this_buffer_length, 0)
                f.write(0xff.to_bytes()*this_buffer_length)
                f.seek(this_pos + this_buffer_length, 0)

            # third pass random
            f.seek(0, 0)
            while f.tell() < file_size:

                file_contents = f.read(min(FILE_BUFFER_MAX, file_size))
                this_buffer_length = len(file_contents)
                this_pos=f.tell()
                
                seed = token_bytes(32)
                enc = aead.AESSIV(seed)
                random_bytes = enc.encrypt(0x00.to_bytes()*this_buffer_length, None)
                
                # overwrite file with random data
                f.seek(this_pos - this_buffer_length, 0)
                f.write(random_bytes)
                f.seek(this_pos + this_buffer_length, 0)

        file.unlink()  # Remove the scrambled file

    @staticmethod
    def read_header(file:pathlib.Path) -> dict:
        
        with file.open('rb') as f:

            file_data = f.read(MAX_HEADER)
            file_data = file_data[FIRST_BYTES_LEN:] # skip the device/pwd signatures
            deobscured_head = head_obscuration().read_head(file_data)
            
            pos = 8 + len(deobscured_head["mask"]) + deobscured_head["pad_length"]
            # read the header length and data:
            header_length = int.from_bytes(file_data[pos:pos+4])

        pos +=4
        header = file_data[pos:pos+header_length]

        # unmask the header:
        header = file_encrypter.mask_text(header, deobscured_head["mask"])
        header_json = ujson.loads(header.decode('utf-8'))
        header_json["header_length"] = header_length + 4 + 8 + len(deobscured_head["mask"]) + deobscured_head["pad_length"]
        header_json["bstring"] = header

        return header_json
    
    @staticmethod
    def check_encryption_method(file:pathlib.Path) -> encrypt_action | None:

        with file.open('rb') as ff:
            first_bytes : bytes = ff.read(FIRST_BYTES_LEN)

        if first_bytes == SIG_DEV:
            return encrypt_action.decrypt_device
        elif first_bytes == SIG_PWD:
            return encrypt_action.decrypt_password
        else:
            raise ValueError(f"File {file} appears to be incorrect. Cannot decrypt.")

    @staticmethod
    def mask_text(plaintext:bytes, mask:bytes) -> bytes:
            # mask the header with the key
            sized_mask = mask * ceil(len(plaintext) / len(mask))
            sized_mask = sized_mask[:len(plaintext)]
            return file_encrypter.simple_encrypt(plaintext, sized_mask)
    
    @staticmethod
    def simple_encrypt(plaintext:bytes, full_cipher:bytes) -> bytes:
        
        if len(plaintext) != len(full_cipher):
            raise ValueError("Key must be the same length as the plaintext.")
        elif not isinstance(plaintext, bytes) or not isinstance(full_cipher, bytes):
            raise TypeError("Plaintext and key must be bytes.")
        
        return bytes(a ^ b for a, b in zip(plaintext, full_cipher))

    @staticmethod
    def is_encrypted(file:pathlib.Path) -> bool:

        # if the file extension is wrong, then this is easy
        if file.suffix != config.enc["file_extension"]:
            return False

        # otherwise, let's check if it was ackshually done with this program.
        # 20 byte pwd vs device specifier is probably good enough.

        with file.open("rb") as ff:
            first_bytes = ff.read(FIRST_BYTES_LEN)

        if first_bytes in (SIG_PWD, SIG_DEV):
            return True
        else:
            return False
                    
    @staticmethod
    def get_password(action:encrypt_action) -> str:

        if action == encrypt_action.encrypt_password:
            dlg = ui_utils.PasswordQueryDialog(
                prompt = "Enter Password\nRe-enter Password",
                title = "Password Input",
            )
            dlg.show(None, True)
            
        elif action == encrypt_action.decrypt_password:

            dlg = QueryDialog(
                prompt = "Enter Password",
                title = "Password Input"
                )
            dlg.show(None, True)
            
        if not dlg.result:
            raise ValueError("No password entered.")

        return dlg.result

class device_interface:
    """ Interface for device management. 
        Contains methods for authenticating, getting devices, and configuring keys.
    """
    @staticmethod
    def update_management_password() -> None:

        if len(config.enc["management_auth"]) > 0:
            
            # get current pw:
            try:
                old_pw = file_encrypter.get_password(encrypt_action.decrypt_password)
            except ValueError:
                return

            # verify current pw:
            key = Argon2id(
                memory_cost=64*1024,
                iterations=3,
                lanes=4,
                length=32,
                salt=config.enc["man_salt"]
            )

            try:
                key.verify(old_pw.encode(), config.enc["management_auth"])
            except InvalidKey as e:
                Messagebox.show_error("Invalid management password. Exiting Program.", title="Error")
                raise SystemExit
            
            management_encryptor = HKDF(
            algorithm=hashes.SHA256(),
            length=24,
            salt=config.enc["management_auth"],
            info=None).derive(old_pw.encode())

            unwrapped_mgmt_keys = {}
            for name, info in config.device.items():
                unwrapped_mgmt_keys[name] = file_encrypter.simple_encrypt(bytes.fromhex(info["management_key"]), management_encryptor)

            try:
                new_pw = file_encrypter.get_password(encrypt_action.encrypt_password)
            except ValueError:
                return
            
            new_deriver = Argon2id(
                memory_cost=64*1024,
                iterations=3,
                lanes=4,
                length=32,
                salt=(new_salt:=token_bytes(16))
            )

            new_hash = new_deriver.derive(new_pw.encode())
            config.update_enc({"management_auth": new_hash.hex()})
            config.update_enc({"man_salt": new_salt.hex()})

            new_management_encryptor = HKDF(
                algorithm=hashes.SHA256(),
                length=24,
                salt=new_hash,
                info=None).derive(new_pw.encode())
            
            for name in config.device.keys():
                config.update_device_parameter({name: {"management_key": file_encrypter.simple_encrypt(unwrapped_mgmt_keys[name], new_management_encryptor).hex()}})

            Messagebox.show_info("Management password updated.", title="Success")

        else: 
        # new management password!
            if len(config.device) != 0:
                Messagebox.show_error("Cannot reset management password while devices are configred. Remove all configured devices first.")
                return

            try:
                new_pw = file_encrypter.get_password(encrypt_action.encrypt_password)
            except ValueError:
                return
            
            new_deriver = Argon2id(
                memory_cost=64*1024,
                iterations=3,
                lanes=4,
                length=32,
                salt=(new_salt:=token_bytes(16))
            )

            new_hash = new_deriver.derive(new_pw.encode())
            config.update_enc({"management_auth": new_hash.hex()})
            config.update_enc({"man_salt": new_salt.hex()})

            Messagebox.show_info("Management password updated.", title="Success")
           
    @staticmethod
    def management_authenticate() -> dict[str, bytes]:

        pwgetter = QueryDialog(
            prompt="Enter Management Password",
            title="Management Authentication"
        )
        pwgetter.show(None, True)
        if not pwgetter.result:
            Messagebox.show_error("No password entered. Exiting Program.", title="Error")
            raise SystemExit
        
        password = pwgetter.result
        
        key = Argon2id(
            memory_cost=64*1024,
            iterations=3,
            lanes=4,
            length=32,
            salt=config.enc['man_salt'])

        try:
            key.verify(password.encode(), config.enc["management_auth"])
        except InvalidKey as e:
            Messagebox.show_error("Invalid management password. Exiting Program.", title="Error")
            raise SystemExit
        
        management_encryptor = HKDF(
            algorithm=hashes.SHA256(),
            length=24,
            salt=config.enc["management_auth"],
            info=None).derive(password.encode())
        
        unwrapped_keys = {}

        unwrapped_keys = (seq(zip(config.device.keys(), config.device.values()))
            .map(lambda x: (x[0], bytes.fromhex(x[1]['management_key'])))
            .map(lambda x: (x[0], file_encrypter.simple_encrypt(x[1], management_encryptor)))
        ).to_dict()

        unwrapped_keys["password"] = password.encode()
        
        return unwrapped_keys

    @staticmethod
    def get_device(include_unconfigured=False, prompt=True) -> compatible_device | list[compatible_device]:
        """ Gets the connected devices, cross references with the config file. If multiple are found, 
            prompts the user to select one.
            Returns a compatible device dataclass or a list of compatible devices.
        """

        device_list = seq(list_all_devices())

        if not device_list:
            raise ConnectionError("No devices found. Please connect a valid device.")
        
        connected_serials = device_list.map(lambda x: (str(x[1].serial), (x[0], x[1])))

        configured_names = seq(config.device.keys()).enumerate()
        configured_serials = seq(config.device.values()).\
            enumerate().\
            map(lambda x: (x[0], x[1]["serial_number"])).\
            join(configured_names).\
            map(lambda x: x[1])
        
        connected_configured = configured_serials.join(connected_serials, "inner")
        connected_unconfigured = configured_serials.join(connected_serials, "outer").\
            filter(lambda x: x[1][0] is None)
        
        # if nothing connected, return error
        if not connected_serials:
            raise ConnectionError("No devices found. Please connect a valid device.")

        if not include_unconfigured:
            
            if not connected_configured:
            # no configured devices

                raise ConnectionError("No configured devices found. Please connect a valid device.")
            
            elif not prompt and connected_configured.len() > 1:

                # return list of configured devices
                return connected_configured.map(lambda x: compatible_device(
                    name=x[1][0], 
                    serial_number=x[0], 
                    handle=x[1][1][0], 
                    info=x[1][1][1])).to_list()

            elif connected_configured.len() > 1:
            # multiple configured devices, prompt user to choose one
                
                dev_str_list = (connected_configured
                            .map(lambda x: f"Name: {x[1][0]}, S/N: {x[0]}\n")
                            .to_list()
                            )
            
                dlg = ui_utils.ButtonOptionsDialog(
                    prompt="Multiple devices found. Which one would you like to use?",
                    items=dev_str_list,
                    title="Select Device"
                )
                dlg.show(None, True)
                if dlg.result is None:
                    raise ConnectionError("No device selected.")

                return compatible_device(
                    name=connected_configured[dlg.result][1][0], 
                    serial_number=connected_configured[dlg.result][0], 
                    handle=connected_configured[dlg.result][1][1][0], 
                    info=connected_configured[dlg.result][1][1][1])

            elif connected_configured.len() == 1:
            # exactly 1 configured, this is the easy case:

                return compatible_device(
                    name=connected_configured[0][1][0], 
                    serial_number=connected_configured[0][0], 
                    handle=connected_configured[0][1][1][0], 
                    info=connected_configured[0][1][1][1])

        else: # include unconfigured devices

            all_connected = connected_configured + connected_unconfigured

            if not prompt and all_connected.len() > 1:
                # return list of all devices
                return all_connected.map(lambda x: compatible_device(
                    name=x[1][0] if x[1][0] is not None else "unconfigured", 
                    serial_number=x[0], 
                    handle=x[1][1][0], 
                    info=x[1][1][1])).to_list()
            
            elif all_connected.len() > 1:
                # multiple devices, configured or unconfigured, prompt user to choose one
                
                dev_str_list = (all_connected
                            .map(lambda x: f"Name: {x[1][0] if x[1][0] is not None else 'unconfigured'}, S/N: {x[0]}\n")
                            .to_list()
                            )
            
                dlg = ui_utils.ButtonOptionsDialog(
                    prompt="Multiple devices found. Which one would you like to use?",
                    items=dev_str_list,
                    title="Select Device"
                )
                dlg.show(None, True)
                if dlg.result is None:
                    raise ConnectionError("No device selected.")

                return compatible_device(
                    name=all_connected[dlg.result][1][0] if all_connected[dlg.result][1][0] is not None else "unconfigured", 
                    serial_number=all_connected[dlg.result][0], 
                    handle=all_connected[dlg.result][1][1][0], 
                    info=all_connected[dlg.result][1][1][1])

            elif all_connected.len() == 1:
            # exactly 1 device, return it

                return compatible_device(
                    name=all_connected[0][1][0] if all_connected[0][1][0] is not None else "unconfigured", 
                    serial_number=all_connected[0][0], 
                    handle=all_connected[0][1][1][0], 
                    info=all_connected[0][1][1][1])
        
        if connected_unconfigured and include_unconfigured:
            ui_utils.ui_utils.ListMessageDialog.show_info(
                "Including Unconfigured devices with SNs:",
                connected_unconfigured.map(lambda x: x[0]).to_list()
            )

        if not include_unconfigured and not connected_configured:
            raise ConnectionError("No configured devices found. Please connect a valid device.")


        if connected_configured.len() > 1:
            # multiple configured devices

            pass
        
        elif connected_serials.len() == 1:
            # only one device, configured or unconfigured
            
            if include_unconfigured and connected_unconfigured:
                return compatible_device(
                    name="unconfigured", 
                    serial_number=connected_unconfigured[0][0], 
                    handle=connected_unconfigured[0][1][1][0], 
                    info=connected_unconfigured[0][1][1][1])
            else:
                return compatible_device(
                    name=connected_configured[0][1][0], 
                    serial_number=connected_configured[0][0], 
                    handle=connected_configured[0][1][1][0], 
                    info=connected_configured[0][1][1][1])
            
        elif connected_serials.len() > 1 and not connected_configured and include_unconfigured:
            
            # multiple devices, none configured
            dev_str_list = (connected_serials
                            .map(lambda x: f"S/N: {x[0]}\n")
                            .to_list()
                            )
            
            dlg = ui_utils.ButtonOptionsDialog(
                prompt="Multiple devices found. Which one would you like to use?",
                items=dev_str_list,
                title="Select Device"
            )
            dlg.show(None, True)
            if dlg.result is None:
                raise ConnectionError("No device selected.")

            return compatible_device(
                name="unconfigured", 
                serial_number=connected_serials[dlg.result][0], 
                handle=connected_serials[dlg.result][1][0],
                info=connected_serials[dlg.result][1][1])
            
        else:
            # exactly 1 configured device:
            pass

    @staticmethod
    def pin_authenticate(session:piv.PivSession, cachepin:str = "") -> str:
        """ PIN Authentication for the user given an open PIV session
            :param session: open PIV session
        """ 
        if not cachepin:
            pin_getter = QueryDialog(
                prompt="Enter PIN",
                title="PIN"
            )
            pin_getter.show(None, True)
            if not pin_getter.result:
                raise ValueError("User Canceled")
            else:
                userpin = pin_getter.result
        else:
            userpin = cachepin

        pin_auth = False
        while not pin_auth:
            try:
                session.verify_pin(userpin)
                pin_auth = True
            except yubikit.core.InvalidPinError as e:
                # wrong pin
                if e.attempts_remaining > 0:
                    
                    pin_getter = QueryDialog(
                        prompt=f"Enter PIN ({e.attempts_remaining} attempts remaining)",
                        title="PIN"
                        )

                    pin_getter.show(None, True)
                    if not pin_getter.result:
                        userpin = ""
                    else:
                        userpin = pin_getter.result

                else:
                    Messagebox.show_error("PIN is locked. Unlock in Authenticator App.", title="Error")
                    raise SystemExit
            except CardConnectionException as e:
                # card was disconnected
                raise CardConnectionException("Card disconnected during authentication.")
        
        return userpin

    @staticmethod
    def new_single_symmetric_key(unprompted:bool=False) -> None:
        
        rng = paranoid_random.paranoid_random(256)

        if not unprompted:
            # confirm
            conf_dlg = ui_utils.ButtonOptionsDialog(
                prompt="Setting up new key. This will overwrite the existing key. Are you sure?",
                items=["Yes", "No"],
                title="Confirm"
            )
            conf_dlg.show(None, True)
            if conf_dlg.result != 0:
                return
                
            stronger_warning = ui_utils.ButtonOptionsDialog(
                prompt=f"WARNING. If you continue and have encrypted files that used this device, you will PERMANENTLY lose access to these. Continue?",
                items=["Yes", "No"],
                title="Confirmation"
            )
            stronger_warning.show(None, True)
            if stronger_warning.result != 0:
                return
            
            # authenticate
            device_interface.management_authenticate()

        match config.rsa_or_ec:
            case "rsa":
                try:
                    public = serialization.load_der_public_key(config.enc["public_key"])
                except ValueError:
                    raise ValueError("Configured public key is invalid for the selected key type. Re-run device 'Generate Device Key'.")
                
                # generate new symmetric key
                new_symmetric_key = rng.random_bytes(64)

                # encrypted with the public key (roundabout way of wrapping)
                skey_base = public.encrypt(new_symmetric_key, 
                        apad.OAEP(
                            mgf=apad.MGF1(
                                algorithm=hashes.SHA256()
                                ), 
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
            case "ec":
                
                # generate the new EC key:
                keyfun = config.keytype_ec[config.enc["key_type"]]
                sender_private = keyfun() # generates private key objet

                # gets the public key formatted bytes according to config
                public = sender_private.public_key().public_bytes(*config.keytype_encoding[config.enc["key_type"]])

                # write the public key.
                config.update_enc({"public_key": public.hex()})
                
                del sender_private  # throw away the key

                # this intentionally throws out the private key, but we write a random number to the file as a dummy
                skey_base = token_bytes(64)

        # update config with wrapped symmetric key
        for k, v in config.device.items():
            config.update_device_parameter({k: {"public_key": "00"}})

        config.update_enc({"skey_base": skey_base.hex()})
        config.update_enc({"dual_device":{"value": False, "type": "bool"}})
        Messagebox.show_info("Success.", title="Success")

    @staticmethod
    def new_dual_key_symmetric_key() -> None:

        conf_dlg = ui_utils.ButtonOptionsDialog(
            prompt="Setting up new key for both configured devices. This will overwrite the slots in 9D. Are you sure?",
            items=["Yes", "No"],
            title="Confirm"
        )
        conf_dlg.show(None, True)
        if conf_dlg.result != 0:
            return
        
        stronger_warning = ui_utils.ButtonOptionsDialog(
            prompt=f"WARNING. If you continue and have encrypted files that used either of these devices alone, you will PERMANENTLY lose access to these. Continue?",
            items=["Yes", "No"],
            title="Confirmation"
        )
        stronger_warning.show(None, True)
        if stronger_warning.result != 0:
            return

        # check to see if 2 devices are even set up:
        if not config.device or len(config.device) < 2:
            raise KeyError("Dual key setup requires two configured devices.")
        
        if config.rsa_or_ec != "ec":
            raise ValueError("Dual key setup is only supported for EC keys.")
        else:
            # check if there are two public keys in the config dict for each device:
            for k, v in config.device.items():
                if "key_type" in v and (v["key_type"] == "None" or v["key_type"].find("RSA") != -1):
                    raise ValueError(f"Device '{k}' does not have a valid EC public key. Re-run 'Generate Device Key'.")
            
            if len(nonunique_keytypes:=seq(config.device.values()).map(lambda x: x["key_type"]).distinct().to_list()) > 1:
                raise ValueError(f"Both devices must have the same key type; instead they were of type: {', '.join(nonunique_keytypes)}. Re-run device configuration.")
                                           
        config.update_enc({"dual_device":{"value":True, "type":"bool"}})
        config.update_enc({"skey_base":"00"}) #no storage for symmetric key
        config.update_enc({"public_key":"00"}) #no public key either.

        Messagebox.show_info("Success.", title="Success")
        
    @staticmethod
    def change_encryption_default() -> None:
        
        enc_def_dlg = QueryDialog(
            prompt=f"Select New Defalt (Current: {config.enc['key_type']})",
            title="Encryption Key Default",
            items=list(config.keytype_piv.keys())
        )
        enc_def_dlg.show(None, True)
        if not enc_def_dlg.result:
            return
        
        config.update_enc({"key_type": enc_def_dlg.result})
        Messagebox.show_info("Key Type Updated.", title="Success")

    @staticmethod
    def generate_device_key() -> None:

        # look for devices: 
        try:
            device = device_interface.get_device()
        except ConnectionError as e:
            raise ValueError(f"{e}")

        # authenticate
        man_keys = device_interface.management_authenticate()

        conf_dlg = ui_utils.ButtonOptionsDialog(
            prompt="Configuration will overwrite slot 9d. Proceed?",
            items=["Yes", "No"],
            title="Confirm",
        )
        conf_dlg.show(None, True)
        if conf_dlg.result != 0:
            return
        
        stronger_warning = ui_utils.ButtonOptionsDialog(
            prompt=f"WARNING. If you continue and have encrypted files that used this device, you will PERMANENTLY lose access to these. Continue?",
            items=["Yes", "No"],
            title="Confirmation"
        )
        stronger_warning.show(None, True)
        if stronger_warning.result != 0:
            return
        
        # we will need the correct management key:
        this_mgmt_key = man_keys[device.name]

        with device.handle.open_connection(ysmart.SmartCardConnection) as connection:
            
            session = piv.PivSession(connection=connection)
            
            # auth with pin and management key:
            try:
                device_interface.pin_authenticate(session)
            except Exception as v:
                Messagebox.show_error(str(v), "Error")
                return

            session.authenticate(this_mgmt_key)

            # remove any existing certs/keys in 9d:
            try:
                session.delete_certificate(piv.SLOT.KEY_MANAGEMENT)
                session.delete_key(piv.SLOT.KEY_MANAGEMENT)
            except ysmart.ApduError as e:
                # don't care if there's no certs/keys there
                if e.sw != 27272:
                    raise e
                
            ktype = config.keytype_piv[config.enc["key_type"]]
        
            session.generate_key(piv.SLOT.KEY_MANAGEMENT, ktype)
            new_pub_key = session.get_slot_metadata(piv.SLOT.KEY_MANAGEMENT).public_key
            
            if config.enc["key_type"] == "X25519":
                pubkey_bytes = new_pub_key.public_bytes_raw()
            else:
                pubkey_bytes = new_pub_key.public_bytes(
                    encoding=serialization.Encoding.DER, 
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
       
            # update config:
            config.update_device_parameter({device.name: {"public_key": pubkey_bytes.hex()}})
            config.update_device_parameter({device.name: {"key_type": config.enc["key_type"]}})
            config.update_enc({"public_key": pubkey_bytes.hex()})

            dummy_private_key = ec.generate_private_key(ec.SECT163R2(), None)

            # generate dummy certificate:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "File Encrypter")])
            cert = x509.CertificateBuilder()\
                .subject_name(subject)\
                .issuer_name(issuer)\
                .public_key(new_pub_key)\
                .serial_number(x509.random_serial_number())\
                .not_valid_before(datetime.now())\
                .not_valid_after(datetime.today() + timedelta(days=10000))\
                .sign(dummy_private_key, hashes.SHA256())

            session.put_certificate(piv.SLOT.KEY_MANAGEMENT, cert)
            
        Messagebox.show_info("Device key generated.", title="Success")

    @staticmethod
    def remove_device() -> None:
        """ Remove a device from the configuration file.
        """

        if not config.device:
            Messagebox.show_info("No configured devices found.", title="Info")
            return
        
        # auth:
        device_interface.management_authenticate()

        dev_str_list = seq()
        for ele in config.device.keys():
            dev_str_list += [f"Device Name: {ele}"]

        dlg = ui_utils.ButtonOptionsDialog(
            prompt="Select device to remove from configuration",
            items=dev_str_list.to_list(),
            title="Select Device"
        )
        dlg.show(None, True)
        if dlg.result is None:
            return
        
        conf_dlg = ui_utils.ButtonOptionsDialog(
            prompt=f"Confirm: Remove device '{list(config.device.keys())[dlg.result]}' from configuration?",
            items=["Yes", "No"],
            title="Confirmation"
        )
        conf_dlg.show(None, True)
        if conf_dlg.result != 0:
            return
        
        stronger_warning = ui_utils.ButtonOptionsDialog(
            prompt=f"WARNING. If you continue and have encrypted files that used this device, you will PERMANENTLY lose access to these. Continue?",
            items=["Yes", "No"],
            title="Confirmation"
        )
        stronger_warning.show(None, True)
        if stronger_warning.result != 0:
            return
                
        # remove the device:
        with open(config.installroot / "context" / "configured_devices.json", 'r') as f:
            configured = ujson.load(f)
        del configured[list(config.device.keys())[dlg.result]]
        with open(config.installroot / "context" / "configured_devices.json", 'w') as f:
            ujson.dump(configured, f, indent=4)

        Messagebox.show_info("Device removed from configuration.", title="Success")
        # reload config:
        config.__init__()

    
    @staticmethod
    def first_time_device_setup() -> None:
        """ First time device setup. Updates the device configuration file with the new information.
        """

        if len(config.enc["management_auth"]) == 0:
            Messagebox.show_error("No management password set up. Select 'Change Management Key' from the configuration menu.")
            return

        try:
            device = device_interface.get_device(include_unconfigured=True, prompt=False)
        except ConnectionError as e:
            raise e

        # this catches the case of multiple connected devices:
        if isinstance(device, list) and len(device) > 1:
            unconfigured_devices = seq(device).filter(lambda x: x.name == "unconfigured")
            if unconfigured_devices.len() > 1:
                raise ValueError("Multiple unconfigured devices found. Disconnect all but one.")
            elif unconfigured_devices.len() == 0:
                raise ValueError("No unconfigured device found or selected. Please connect an unconfigured device.")
        
            device = unconfigured_devices.to_list()[0]


        # this catches the case where one device is plugged and it's already configg'd 
        if device.name != "unconfigured":
            raise ValueError("The available device is already configured.")
        
        with open(config.installroot / "context" / "supported_devices.json", 'r') as f:
            supported_devices = ujson.load(f)
            
        if (pid_str:=hex(device.handle.pid.value)) not in supported_devices:
            raise ValueError(f"Device is not supported. Please insert a device on the supported device list.")
                
        config_entry = {}

        name_dlg = QueryDialog(
            prompt="Enter a name for this device (32 or fewer characters):",
            title="Device Name"
            )
        name_dlg.show(None, True)
        name_input = name_dlg.result

        if not name_input:
            return # cancel
    
        evil_chars = '\n\t=+*\\{\\}[]^*%@#$`~;<>' #why would anyone be putting these in a name besides some sort of code injection
        isnt_evil = lambda x: not any([ii for ii in x if ii in evil_chars])

        while not (name_input.isascii() and len(name_input) <= 32 and isnt_evil(name_input) and name_input.strip() != ""):
            Messagebox.show_error("Name must be non-empty and ASCII characters only (less than 32 characters).", title="Error")
            name_dlg.show(None, True)
            name_input = name_dlg.result

        config_entry[name_input] = {}
        config_entry[name_input]["name"] = name_input
        config_entry[name_input]["model"] = supported_devices[pid_str]
        config_entry[name_input]["description"] = device.handle.fingerprint
        config_entry[name_input]["serial_number"] = device.serial_number
        config_entry[name_input]["firmware_version"] = device.info.version_name
            
        # ask user for management key (which should be hex)
        mgmt_key_dlg = QueryDialog(
            prompt="Enter the device management key (at least 48 hex characters):",
            title="Management Key"
        )
        mgmt_key_dlg.show(None, True)
        raw_mgmt_key = mgmt_key_dlg.result

        if not raw_mgmt_key:
            return # cancel

        while True:
            try:
                bytes.fromhex(raw_mgmt_key)
                int(raw_mgmt_key, 16)
                if len(raw_mgmt_key) < 48:
                    raise ValueError
            except ValueError:
                Messagebox.show_error("Management key must be at least 48 hex characters (even number).", title="Error")
                mgmt_key_dlg.show(None, True)
                raw_mgmt_key = mgmt_key_dlg.result
            else:
                break
                        
        with device.handle.open_connection(ysmart.SmartCardConnection) as connection:
            session = piv.PivSession(connection=connection)
            
            # auth with pin and management key:
            try:
                device_interface.pin_authenticate(session)
            except Exception as v:
                Messagebox.show_error(str(v), "Error")
                return
            
            try:
                session.authenticate(bytes.fromhex(raw_mgmt_key))
            except ysmart.ApduError as e:
                Messagebox.show_error("Invalid management key. Exiting", title="Error")
                raise SystemExit

        auth = device_interface.management_authenticate()
        
        management_encryptor = HKDF(
            algorithm=hashes.SHA256(),
            length=24,
            salt=config.enc["management_auth"],
            info=None).derive(auth["password"])
        
        config_entry[name_input]["management_key"] = file_encrypter.simple_encrypt(management_encryptor, bytes.fromhex(raw_mgmt_key)).hex()

        # default empty public key
        config_entry[name_input]["public_key"] = (b"\x00"*64).hex()

        # key type:
        config_entry[name_input]["key_type"] = "None"

        # update the config file:
        config.update_device(config_entry)
        Messagebox.show_info("Device successfully set up. Run 'New Symmetric Key' to set up key", title="Success")

class head_obscuration:

    hasher = sha256()
    seed = 0x1ddfdf5b334ce54234725d0fe71bd1f0b225787fe4aa575d45b3264421d9a88
    startx = 0xb8af69d3c717c7dd927d36e4a27d669cc0657514c656d3ff574f56816e7d43c3
    start_point: ec_lite.ec_point

    def __init__(self):
        # origin and start points
        self.p0 = ec_lite.ec_point(self.seed, y=None)
        self.start = ec_lite.ec_point(self.startx, y=None)
    
    def generate_head(self) -> bytes:
    
        this_time:int = time_ns()
        bytime:bytes = this_time.to_bytes(8, "big", signed=False)

        final_coordinate = self.p0.point_multiply(int.from_bytes(bytime), self.start)
        final_bytes = final_coordinate.x.to_bytes(64, "big", signed=False)

        pad_length = 255*final_bytes[12] + final_bytes[19] # take two bytes for the pad length
        pad = token_bytes(pad_length)

        return {"signature":bytime + final_bytes + pad, "mask":final_bytes}
    
    def read_head(self, data:bytes) -> bytes:
        
        # first 8 bytes is timestamp:
        timestamp:int = int.from_bytes(data[:8], "big", signed=False)

        final_coordinate = self.p0.point_multiply(timestamp, self.start)
        final_bytes = final_coordinate.x.to_bytes(64, byteorder="big", signed=False)

        if final_bytes != data[8:64+8]:
            raise TypeError("File is not encrypted with this program. Cannot decrypt.")

        pad_length = 255*final_bytes[12] + final_bytes[19] # take two bytes for the pad length
               
        return {"time": timestamp, "mask": final_bytes, "pad_length": pad_length}

class uiroot(ttk.Window):
    
    def __init__(self, *args, **kwargs):
        """ Main program entrypoint
        """
        super().__init__(*args, **kwargs)
        
        self.title("File Encrypter")
        self.geometry("950x400")
        self.minsize(950, 400)
        
        row_id = 0
        # add ui elements
        enc_but = ttk.Button(self,
                text = "Encrypt All", 
                command = self.encrypt_all,
                bootstyle="PRIMARY")
        enc_but.grid(column=0, row=row_id, pady=10, padx=10, sticky="ew")

        dec_but = ttk.Button(self, 
                text = "Decrypt All", 
                command = self.decrypt_all,
                bootstyle="PRIMARY")
        dec_but.grid(column=1, row=row_id, pady=10, padx=10, sticky="ew")

        filedisp_but = ttk.Button(self,
                text = "Display File List",
                command = self.display_filelist,
                bootstyle="PRIMARY")
        filedisp_but.grid(column=2, row=row_id, pady=10, padx=10, sticky="ew")

        row_id += 1
        self.obscuration_toggle = ttk.BooleanVar(self, value=config.enc["filename_obscuration"])
        fname_obs_option = ttk.Checkbutton(self,
                text="Filename Obscuration",
                variable=self.obscuration_toggle,
                onvalue=True,
                offvalue=False,
                style="primary.Roundtoggle.Toolbutton",
                command = lambda: config.update_enc({"filename_obscuration": {"value":self.obscuration_toggle.get(), "type":"bool"}})
        )
        fname_obs_option.grid(column=1, row=row_id, pady=10, padx=10, columnspan=2)

        row_id += 1
        config_but = ttk.Button(self,
                text = "Configuration", 
                command = self.config_menu,
                bootstyle="LIGHT")
        config_but.grid(column=0, row=row_id, pady=10, padx=10, sticky="ew", columnspan=2)

        exit_but = ttk.Button(self,
                text = "Exit",
                command = self.destroy,
                bootstyle="DANGER")
        exit_but.grid(column=2, row=row_id, pady=10, padx=10, sticky="ew")

        self.rowconfigure(tuple(range(0, row_id)), weight=1)

        self.updatevars()

    def update_after(func):
        def wrapper(self):
            result = func(self)
            self.updatevars()
            return result
        return wrapper

    def updatevars(self):

        if hasattr(self, 'config_root') and self.busy_status():
            # skip the update loop if the user is in the config menu
            return
        
        self.refuse_to_encrypt = False

        # get the list of files to encrypt
        try:
            self.file_list = utils.file_entry_manager(pathlib.Path(config.installroot) / "encryption_list.txt")
        except FileNotFoundError as e:
            ui_utils.ListMessageDialog.show_error(
                e.full_message.before,
                e.full_message.msglist,
                e.full_message.after
            )
            return
        except ValueError as v:
            if hasattr(v, "full_message"):
                ui_utils.ListMessageDialog.show_error(
                    v.full_message.before,
                    v.full_message.msglist,
                    v.full_message.after
                )
            else:
                Messagebox.show_error(f"{v}", title="Error")

            # set flags to not allow encrypt/decrypt in the main loop
            self.refuse_to_encrypt = True
            self.none_are_encrypted = False

        if not self.refuse_to_encrypt:

            self.encrypted_files = (self.file_list.entries
                .filter(file_encrypter.is_encrypted)
            )

            self.unencrypted_files = self.file_list.entries.filter(lambda x: x not in self.encrypted_files) # anything that's not in the enc. list

            if self.file_list.entries.len() == 0:
                # everything isn't encrypted if there's nothing to begin with
                self.refuse_to_encrypt = True
                Messagebox.show_error("No files found in the file list.", title="Error")

            self.none_are_encrypted = not self.encrypted_files.len()

        return super().update()
        
    @update_after
    def display_filelist(self):
        fv = ui_utils.FileView(self, self.file_list)
        fv.wait_window()

    @update_after
    def encrypt_all(self) -> None:

        # encrypt all files on the list that are not encrypted
        if self.refuse_to_encrypt:
            Messagebox.show_error("Cannot encrypt. Fix errors before continuing.", title="Error")
        elif self.unencrypted_files.len() == 0:
            # nothing that's not already encrypted:
            Messagebox.show_warning("No unencrypted files found.", title="Warning")
        else:
            
            # pass to yubikey
            devices = list_all_devices()
            
            if devices:
                # I wrote a whole device management interface for this,
                # but if it ain't broke, don't fix
                serial_number = str(devices[0][0]._key[0])

                if serial_number in seq(config.device.values()).map(lambda x: x['serial_number']):
                    
                    dlg = ui_utils.ButtonOptionsDialog(
                        prompt="Configured Device found. Proceed with device, or switch to password?",
                        items=["Device", "Password"],
                        title="Selection",
                        parent=self,
                    )
                    dlg.show(None, True)
                    if dlg.result is None:
                        return

                    match dlg.result:
                        case 0: action = encrypt_action.encrypt_device
                        case 1: action = encrypt_action.encrypt_password
                else:
                    action = encrypt_action.encrypt_password
                    Messagebox.show_warning("Found a device, but is not configured. Switching to password encryption.", title="Warning")

            else:
                action = encrypt_action.encrypt_password

            conf_dlg = ui_utils.ListedDialog(
                message_beforelist="Proceed with encrypting files:",
                list_message=self.unencrypted_files.to_list(),
                message_afterlist="Cannot be undone.",
                buttons=["Yes", "No"]
            )
            conf_dlg.show()

            if conf_dlg._result == "Yes":
                e = file_encrypter(
                    file_source=self.unencrypted_files,
                    action=action,
                    filename_obcuration=self.obscuration_toggle.get()
                    )
            else:
                return

    @update_after
    def decrypt_all(self) -> None:
        
        # decrypt all
        if self.none_are_encrypted:
            Messagebox.show_info("No files are encrypted.", title="Info")
        elif self.refuse_to_encrypt:
            Messagebox.show_error("Cannot decrypt. Fix errors before continuing.", title="Error")
        else:

            CHECK_GRAIN:int = 300
            use_pool_for_check_method = (n_pool := self.encrypted_files.len()//CHECK_GRAIN + 1) > 1

            # paralell-version to call get_encryption_method()
            if use_pool_for_check_method:
                
                _map_it = self.encrypted_files.to_list() # picklable list "map iterator"
                
                # spawn UI to display spinner animation/gif:
                toplevel = ttk.Toplevel("Waiting...", "", (400, 300))
                gif = ui_utils.AnimatedGif(toplevel,
                        file_path = pathlib.Path(__file__).parent / "resources" / "dual_ring_spinner.gif",
                        text_input= "Building Encrypted File List..."
                        )
                gif.pack(fill="both", expand=ttk.YES)
                
                # function that will close the ttk.Toplevel and exit its mainloop:
                def await_fcn(evt:threading.Event, this_toplevel:ttk.Toplevel, this_gif:ui_utils.AnimatedGif):
                    evt.wait()
                    this_gif.destroy()
                    this_toplevel.destroy()
                    this_toplevel.quit()

                # thread that will call the function that closes the ttk.Toplevel and exit its mainloop:
                stop_event = threading.Event()
                stop_th = threading.Thread(target=await_fcn, args=(stop_event, toplevel, gif))
                stop_th.start()

                # error callback for the process pool:
                def error_callback(e:BaseException):
                    raise e

                # startup the pool
                pool = Pool(max(min(n_pool, cpu_count() - 2), 2))
                action_list = pool.map_async(
                    uiroot.check_with_key, # this just calls check encryption method
                    _map_it, # the list from earlier
                    None, # don't actually specify the chunksize.
                    callback=lambda _: stop_event.set(), # tells the toplevel mainloop to stop in the future
                    error_callback=error_callback # error callback
                )
                toplevel.mainloop() # starts the toplevel mainloop

                # join/close all the threads
                stop_th.join()
                pool.close()
                pool.join()

                # compile the action list
                action_list = seq(action_list.get())

            else:
                # serial version of calling check_encryption_method
                action_list = self.encrypted_files.map(lambda x: (file_encrypter.check_encryption_method(x), x))
            
            grouped_files = action_list.group_by_key()

            # run decryption
            try:
                grouped_files.for_each(lambda x: file_encrypter(
                    file_source = seq(x[1]),
                    action=x[0]))
            except (InvalidTag, InvalidKey) as e:
                Messagebox.show_error(f"Incorrect Key", title="Error")
            except BaseException as e:
                Messagebox.show_error(f"{e}", title="Error")

    @staticmethod
    def check_with_key(x:str):
        return (file_encrypter.check_encryption_method(x), x)
    
    @update_after
    def new_symm_key(self) -> None:
        
        # set up a new symemtric key/exchange
        if self.encrypted_files:
            Messagebox.show_error(
                f"There are encrypted files in the list. Decrypt these before device configuration: \
                {self.encrypted_files.make_string(',\n')}", 
                title="Error"
            )
            return
        
        try:
            device_interface.new_single_symmetric_key()
        except Exception as e:
            Messagebox.show_error(f"Setup Failed: {e}", title="Error")
            return
            
    @update_after
    def setup_dual_key(self) -> None:
        
        # set up dual key exchange
        if self.encrypted_files:
            Messagebox.show_error(
                f"There are encrypted files in the list. Decrypt these before device configuration: \
                {self.encrypted_files.make_string(',\n')}", 
                title="Error"
            )
            return

        try:
            device_interface.new_dual_key_symmetric_key()
        except Exception as e:
            Messagebox.show_error(f"Setup Failed: {e}", title="Error")
            return

    @update_after
    def first_time_device_setup(self) -> None:
        try:
            device_interface.first_time_device_setup()
        except Exception as e:
            Messagebox.show_error(f"Setup Failed: {e}", title="Error")
            return

    @update_after
    def generate_device_key(self) -> None:
        # reconfig/config a device
        if self.encrypted_files:
            Messagebox.show_error(
                f"There are encrypted files in the list. Decrypt these before device configuration: \
                {self.encrypted_files.make_string(',\n')}", 
                title="Error"
            )

        try:
            device_interface.generate_device_key()
        except Exception as v:
            Messagebox.show_error(f"Configuration Failed: {v}", title="Error")

    @update_after
    def change_asym_default(self) -> None:
        device_interface.change_encryption_default()
    
    @update_after
    def new_mgmt_pass(self) -> None:

        if self.encrypted_files:
            Messagebox.show_error(
                f"There are encrypted files in the list. Decrypt these before proceeding: \
                {self.encrypted_files.make_string(',\n')}", 
                title="Error"
            )
            return

        try:
            device_interface.update_management_password()
        except Exception as v:
            Messagebox.show_error(f"Failed: {v}", title="Error")
            return

    @update_after
    def remove_device(self) -> None:

        if self.encrypted_files:
            Messagebox.show_error(
                f"There are encrypted files in the list. Decrypt these before device removal: \
                {self.encrypted_files.make_string(',\n')}", 
                title="Error"
            )
            return

        try:
            device_interface.remove_device()
        except Exception as v:
            Messagebox.show_error(f"Remove Failed: {v}", title="Error")

    def config_menu(self) -> None:

        if not hasattr(self, 'config_root'):

            self.config_root = ttk.Toplevel(self)
            self.config_root.title("Configuration Menu")
            self.config_root.geometry("400x600")
            self.config_root.minsize(400, 600)
            self.config_root.columnconfigure(0, weight=1)
            self.config_root.columnconfigure(1, weight=1)
            self.config_root.rowconfigure(tuple(range(6)), weight=1)

            row_id = 0
            mgmt_but = ttk.Button(self.config_root,
                        text="Change Management Key",
                        command=self.new_mgmt_pass,
                        bootstyle=("LIGHT", "OUTLINE"))
            mgmt_but.grid(row=row_id, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
            row_id += 1

            devsetup_but = ttk.Button(self.config_root,
                        text="First Time Device Setup", 
                        command=self.first_time_device_setup,
                        bootstyle=("LIGHT", "OUTLINE"))
            devsetup_but.grid(row=row_id, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
            row_id += 1

            keytype_but = ttk.Button(self.config_root,
                        text="Change Key Type", 
                        command=self.change_asym_default,
                        bootstyle=("LIGHT", "OUTLINE"))
            keytype_but.grid(row=row_id, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
            row_id += 1

            cfgdev_but = ttk.Button(self.config_root,
                        text="Generate Device Key",
                        command=self.generate_device_key,
                        bootstyle=("LIGHT", "OUTLINE"))
            cfgdev_but.grid(row=row_id, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
            row_id += 1

            skey_but = ttk.Button(self.config_root,
                        text="New Symmetric Key", 
                        command=self.new_symm_key,
                        bootstyle=("LIGHT", "OUTLINE"))
            skey_but.grid(row=row_id, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
            row_id += 1

            dual_but = ttk.Button(self.config_root,
                        text="Generate Paired Device Key", 
                        command=self.setup_dual_key,
                        bootstyle=("LIGHT", "OUTLINE"))
            dual_but.grid(row=row_id, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
            row_id += 1
            
            devrem_but = ttk.Button(self.config_root,
                        text="Remove Device", 
                        command=self.remove_device,
                        bootstyle=("LIGHT", "OUTLINE"))
            devrem_but.grid(row=row_id, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
            row_id += 1
            
            # print some help for the user
            info_but = ttk.Button(self.config_root, 
                                  text="Info", 
                                  command=self.print_config_information,
                                  bootstyle=("INFO", "OUTLINE"))
            info_but.grid(row=row_id, column=0, columnspan=1, pady=10, padx=10, sticky="ew")

            # OK button to complete configuration
            ok_but = ttk.Button(self.config_root,
                        text="OK", 
                        command=lambda: self.config_root.withdraw() or self.busy_forget(),
                        bootstyle="DANGER")
            ok_but.grid(row=row_id, column=1, columnspan=1, pady=10, padx=10, sticky="ew")
            row_id += 1

            # you can't get rid of the babadook
            self.config_root.protocol("WM_DELETE_WINDOW", lambda: self.config_root.withdraw() or self.busy_forget())
            self.busy()

        else: 
            self.config_root.deiconify()
            self.config_root.lift()
            self.busy()

    @staticmethod
    def print_config_information():
        info_dlg = ui_utils.ListedDialog(
            message_beforelist="Configuration Menu Information:",
            list_message=["1. Change Management Key - set up or change the device management key. Run this first, before setting up any devices.", "",
                            "2. First Time Device Setup - configures a device for the first time, sets up the management authority to add keys to the device slots",  "",
                            "3. Change Key Type - select the type of asymmetric device key you would like to use. If you don't know what these options are, a quick online search can tell you all you need to know", "",
                            "4. Generate Device Key - creates a new private/public key pair on the device slot 9D. Overwrites any existing keys that are there. You must have configured the device, and have the management key handy", "",
                            "5. New Symmetric Key - creates a new encrypted symmetric key locally, which only the device's asymmetric key can unlock. Device-based encryption is always performed with this symmetric key.", "",
                            "6. Generate Paired Device Key - if you have two configured devices, this sets up a Diffie-Hellman exchange where both devices can decrypt the symmetric key and perform device-based encryption. Requires two configured devices, and you must run Generate Device Key on both, with the key type set to an EC Key.", "",
                            "7. Remove Device - removes a device from the configured devices list"
                            ],
            message_afterlist="Press OK to continue",
            buttons=["OK"]
        )
        info_dlg.show()


def single_target_mode(target_path:pathlib.Path) -> None:

    # check to see if the file exists
    if not target_path.exists():
        raise ValueError(f"The input: '{target_path}' does not exist.")
    
    root=ttk.Window(
            title="File Encryptor", 
            themename="superhero")
        
    root.configure(bd=2, relief="raised", takefocus=True, highlightbackground="black")
    root.iconphoto(False, ttk.PhotoImage(file= config.installroot / "resources" / "icons8-data-matrix-code-96.png"))
    ttk.Label(master=root, text="Processing...").pack()

    # check if the file is already encrypted
    if file_encrypter.is_encrypted(target_path):
        
        action = file_encrypter.check_encryption_method(target_path)

        # simple decrypt:
        e = file_encrypter(
                file_source=seq((target_path,)),
                action=action
            )
        
        startfile(e.returned_files[0])
            
    else: # encrypt
        
        # if it wasn't ackshually encrypted and the extension is correct, then it's fishy
        if (target_path.suffix == config.enc["file_extension"]) & (target_path.suffix != ''):
            Messagebox.show_error("Detected mismatched file signature. Cannot decrypt this file using this program.")
            return

       # get devices:
        devices = list_all_devices()
        
        if devices:
            serial_number = str(devices[0][0]._key[0])

            if config.device["primary"]["serial_number"] == serial_number or \
                config.device["secondary"]["serial_number"] == serial_number:
                
                dlg = ui_utils.ButtonOptionsDialog(
                    prompt="Configured Device found. Proceed with device, or switch to password?",
                    items=["Device", "Password"],
                    title="Selection",
                    parent=root,
                )
                dlg.show(None, True)
                if dlg.result is None:
                    return

                match dlg.result:
                    case 0: action = encrypt_action.encrypt_device
                    case 1: action = encrypt_action.encrypt_password

        else:
            action = encrypt_action.encrypt_password

        conf_dlg = ui_utils.ButtonOptionsDialog(
            prompt = f"Proceed with encrypting: {target_path}? Cannot be undone (y/n)",
            items = ["Yes", "No"],
            title = "Confirm"
        )

        conf_dlg.show(None, True)
        if conf_dlg.result == 0:

            # zip up any dirs
            if target_path.is_dir():

                # make zip:
                with ZipFile((zip_target:=target_path.with_suffix(".zip")), "w") as zipped:
                    for file in target_path.rglob("*"):
                        zipped.write(file, file.relative_to(target_path))
                                        
                # remove original copy:
                for file_or_folder in tuple(target_path.rglob("*"))[::-1]:
                    if file_or_folder.is_file():
                        file_encrypter.secure_destroy(file_or_folder)
                    elif file_or_folder.is_dir():
                        file_or_folder.rmdir()
                target_path.rmdir()

                # set target to the zipped file
                target_path = str(zip_target)

            e = file_encrypter(
                file_source=seq([target_path]),
                action=action,
                filename_obcuration=config.enc["filename_obscuration"]
                )
            
if __name__ == "__main__":

    parser = ArgumentParser("File Encrypter interface")
    parser.add_argument("-m", "--mode", choices=('normal', 'target'), default='normal', type=str, required=False)
    parser.add_argument("-t", "--target", type=str, required=False, action="append")

    args = parser.parse_args()
    
    match args.mode:
        case "normal":

            rt = uiroot(title="File Encrypter", 
                        themename="superhero"
                        )
            
            rt.configure(bd=2, relief="raised", takefocus=True, highlightbackground="black")
            rt.iconphoto(False, ttk.PhotoImage(file=config.installroot / "resources" / "icons8-data-matrix-code-96.png"))
            rt.update()
            rt.mainloop()

        case "target":
            if not args.target:
                raise ValueError("Target mode requires a dath argument")
            elif "".join(args.target).find("file_encryptor.py") != -1:
                raise ValueError("Cannot encrypt the encryption program.")
            else:
                single_target_mode(pathlib.Path(args.target[0].strip("'")))
                