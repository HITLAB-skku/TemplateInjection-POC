import os.path as path
from Crypto.Hash import SHA1, SHA256, SHA512, HMAC
from Crypto.Cipher import AES, DES3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import struct


class DPAPIError(Exception): pass


class DPAPI:
    CALG_3DES    = 0x6603
    CALG_AES_256 = 0x6610
    CALG_SHA1    = 0x8004
    CALG_SHA_256 = 0x800c
    CALG_SHA_512 = 0x800e


    def __init__(self):
        self.secrets = None
        self.sid = None
        self.sid_str = None
        self.masterkey_blob = None


    def set_secrets(self, secrets: bytes) -> bool:
        self.secrets = secrets
        if self.secrets is None:
            return False
        return True
    

    def set_sid_str(self, sid_str: str) -> bool:
        self.sid_str = sid_str
        if self.sid_str is None:
            return False
        return True
    

    def set_sid(self, sid: bytes) -> bool:
        if sid is None:
            return False
        self.sid = sid
        return True


    def set_masterkey_file(self, masterkey_path: str) -> bool:
        if not (path.exists(masterkey_path) and path.isfile(masterkey_path)):
            raise FileNotFoundError(f"[!] File not found: {masterkey_path}")
        
        with open(masterkey_path, "rb") as f:
            buffer = f.read()

        offset = 0
        dwVersion = int.from_bytes(buffer[offset:offset+4], byteorder="little", signed=False)
        offset += 4
        unk0 = int.from_bytes(buffer[offset:offset+4], byteorder="little", signed=False)
        offset += 4
        unk1 = int.from_bytes(buffer[offset:offset+4], byteorder="little", signed=False)
        offset += 4
        szGuid = buffer[offset:offset+36*2]
        offset += 36*2
        unk2 = int.from_bytes(buffer[offset:offset+4], byteorder="little", signed=False)
        offset += 4
        unk3 = int.from_bytes(buffer[offset:offset+4], byteorder="little", signed=False)
        offset += 4
        dwFlags = int.from_bytes(buffer[offset:offset+4], byteorder="little", signed=False)
        offset += 4
        MasterkeyLen = int.from_bytes(buffer[offset:offset+8], byteorder="little", signed=False)
        offset += 8
        BackupKeyLen = int.from_bytes(buffer[offset:offset+8], byteorder="little", signed=False)
        offset += 8
        CredHistLen = int.from_bytes(buffer[offset:offset+8], byteorder="little", signed=False)
        offset += 8
        DomainKeyLen = int.from_bytes(buffer[offset:offset+8], byteorder="little", signed=False)
        offset += 8
        print(f"{offset: #x}")

        masterkey = buffer[offset:offset+MasterkeyLen]
        offset_masterkey = 0

        masterkey_version = int.from_bytes(masterkey[offset_masterkey:offset_masterkey+4], byteorder="little", signed=False)
        offset_masterkey += 4
        masterkey_salt = masterkey[offset_masterkey:offset_masterkey+16]
        offset_masterkey += 16
        masterkey_rounds = int.from_bytes(masterkey[offset_masterkey:offset_masterkey+4], byteorder="little", signed=False)
        offset_masterkey += 4
        masterkey_hash_algorithm = int.from_bytes(masterkey[offset_masterkey:offset_masterkey+4], byteorder="little", signed=False)
        offset_masterkey += 4
        masterkey_cipher_algorithm = int.from_bytes(masterkey[offset_masterkey:offset_masterkey+4], byteorder="little", signed=False)
        offset_masterkey += 4
        masterkey_blob = masterkey[offset_masterkey:]
        self.masterkey_blob = masterkey_blob
        self.masterkey_salt = masterkey_salt
        self.masterkey_rounds = masterkey_rounds

        

    def get_masterkey(self) -> bool:
        if self.secrets is None:
            raise RuntimeError("[!] SECRETS not set.")
        if self.sid is None:
            raise RuntimeError("[!] SID not set.")
        if self.masterkey_blob is None:
            raise RuntimeError("[!] Masterkey blob not set.")
        
        sid_msg = self.sid
        sha_derived_key = HMAC.new(self.secrets, sid_msg, SHA1).digest()

        key_len   = 32
        block_len = 16
        dk_len    = key_len + block_len
        dk = PBKDF2(password=sha_derived_key, salt=self.masterkey_salt, dkLen=dk_len, count=self.masterkey_rounds, hmac_hash_module=SHA512)
        session_key, iv = dk[:key_len], dk[key_len:]

        cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
        plaintext = cipher.decrypt(self.masterkey_blob)

        hmac_len = 64
        if len(plaintext) < 16 + hmac_len:
            raise RuntimeError("[!] Layout invalid after decryption (lengths).")

        seed   = plaintext[:16]
        tag    = plaintext[16:16 + hmac_len]
        payload= plaintext[16 + hmac_len:]

        hmac1 = HMAC.new(sha_derived_key, seed, SHA512).digest()
        hmac2 = HMAC.new(hmac1, payload, SHA512).digest()

        if hmac2 != tag:
            raise RuntimeError("[!] HMAC integrity check failed.")

        self.masterkey = payload
        return True
    
    def decrypt(self, blob: bytes) -> bytes:
        pass
    

    def encrypt(self, blob: bytes) -> bytes:
        pass


        
        


if __name__ == "__main__":
    masterkey = "../example-data/victim/1072e1d2-ef2d-4803-afac-21e98d0eb71a"
    syskey = bytes.fromhex("beaeafb0421bec4233ab9a38cc14a0d50c6999efe154d86f241b2d90aa3259242bb04e1c38148345")
    from lsa import LSA
    lsa = LSA()
    if lsa.set_software("../example-data/victim/SOFTWARE"):
        print("[+] SOFTWARE hive loaded.")
    if lsa.get_sid():
        print(f"[+] SID: {lsa.sid.hex()}")

    dpapi = DPAPI()
    dpapi.set_syskey(syskey)
    dpapi.get_masterkey_file(masterkey)
    if dpapi.set_sid_str(lsa.sid_str):
        print("[+] SID set.")
    if dpapi.set_sid(lsa.sid):
        print("[+] SID bytes set.")

    if dpapi.temp():
        print(dpapi.decrypted_masterkey.hex())