import re
import os.path as path
from binascii import unhexlify

from Registry import Registry
from Crypto.Cipher import AES
from Crypto.Hash import SHA256




class LSA():
    
    SYSKEY_LENGTH = 16
    SYSKEY_NAMES = ["JD", "Skew1", "GBG", "Data"]
    SYSKEY_PERMUT = [11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4]
    HEX8_RE = re.compile(r'^[0-9a-fA-F]{1,8}$')


    def __init__(self):
        self.system = None
        self.security = None
        self.software = None

        self.syskey = None
        self.sid = None
        self.sid_str = None
        self.secrets = None

    

    def _open_hive(self, hive_path: str) -> Registry.Registry:
        if not (path.exists(hive_path) and path.isfile(hive_path)):
            raise FileNotFoundError(f"[!] File not found: {hive_path}")
        
        return Registry.Registry(hive_path)
    

    def set_system(self, system_path: str) -> bool:
        self.system = self._open_hive(system_path)
        if self.system is None:
            return False
        return True
    

    def set_security(self, security_path: str) -> bool:
        self.security = self._open_hive(security_path)
        if self.security is None:
            return False
        return True
    

    def set_software(self, software_path: str) -> bool:
        self.software = self._open_hive(software_path)
        if self.software is None:
            return False
        return True
    
    
    def get_syskey(self) -> bool:
        try:
            current = self.system.open(r"Select").value("Current").value()
            ccs = f"ControlSet{current:03d}"
        except Exception as e:
            raise RuntimeError(f"[!] Unable to parse SYSTEM hive: {e}")

        try:
            lsa = self.system.open(rf"{ccs}\Control\LSA")
        except Exception as e:
            raise RuntimeError(f"[!] Unable to access LSA key: {e}")
        
        buffkey = bytearray(16)

        for i, keyname in enumerate(self.SYSKEY_NAMES):
            try:
                key = lsa.subkey(keyname)
            except Exception:
                raise RuntimeError(f"[!] Missing LSA subkey: {keyname}")

            cls = key._nkrecord.classname()[:8]
            dword = int(cls, 16) & 0xFFFFFFFF
            buffkey[i*4:(i+1)*4] = dword.to_bytes(4, byteorder="little")

        self.syskey = bytearray(16)
        for i, b in enumerate(self.SYSKEY_PERMUT):
            if not (0 <= b < 16):
                raise ValueError(f"[!] SYSKEY_PERMUT contains invalid index: {b}")
            self.syskey[i] = buffkey[b]
        return True
    

    def print_syskey(self):
        if self.syskey is None:
            print("[!] SYSKEY not set.")
        else:
            print("[+] SYSKEY:", self.syskey.hex())
    

    def get_secrets(self) -> bool:
        if self.system is None:
            raise RuntimeError("[!] SYSTEM hive not set.")
        if self.security is None:
            raise RuntimeError("[!] SECURITY hive not set.")
        if self.syskey is None:
            raise RuntimeError("[!] SYSKEY not set.")
        
        try:
            policy = self.security.open(r"Policy")
        except Exception as e:
            raise RuntimeError(f"[!] Unable to access Policy key: {e}")
        
        try:
            ek_list = policy.subkey("PolEKList")
            buffer = ek_list.values()[0].value()
        except Exception as e:
            raise RuntimeError(f"[!] Unable to access PolEKList value: {e}")
        
        hash =SHA256.new()
        hash.update(self.syskey)
        lazy_iv = buffer[28:60]

        for i in range(1000):
            hash.update(lazy_iv)
            
        return True
        

    def get_sid(self) -> bool:
        if self.software is None:
            raise RuntimeError("[!] SOFTWARE hive not set.")
        
        try:
            policy = self.software.open(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
        except Exception as e:
            raise RuntimeError(f"[!] Unable to access ProfileList value: {e}")
        try:
            for subkey in policy.subkeys():
                sid_str = subkey.name()
                if "S-1-5-21" in sid_str:
                    break
            if sid_str is None:
                raise RuntimeError("[!] No valid SID found.")
            self.sid_str = sid_str
        except Exception as e:
            raise RuntimeError(f"[!] Unable to parse ProfileList subkeys: {e}")
        
        try:
            sid = self.software.open(rf"Microsoft\Windows NT\CurrentVersion\ProfileList\{sid_str}")
            for value in sid.values():
                if value.name() == "Sid":
                    self.sid = value.value()
                    break
        except Exception as e:
            raise RuntimeError(f"[!] Unable to access Sid value: {e}")
        
        return True
            


if __name__ == "__main__":
    system_path = "../example-data/victim/SYSTEM"
    secrets_path = "../example-data/victim/SECURITY"
    lsa = LSA()
    
    if lsa.set_system(system_path):
        print("[+] SYSTEM hive loaded.")
    if lsa.set_security(secrets_path):
        print("[+] SECURITY hive loaded.")
    if lsa.set_software("../example-data/victim/SOFTWARE"):
        print("[+] SOFTWARE hive loaded.")

    if lsa.get_syskey():
        lsa.print_syskey()
    
    if lsa.get_secrets():
        pass
    
    if lsa.get_sid():
        pass