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

    PK_ENTROPY = b"xT5rZW5qVVbrvpuA\x00"
    PKP_ENTROPY = b"6jnkd5J3ZdQDtrsu\x00"


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
    
    def _pkcs7_pad(b: bytes, block: int = 16) -> bytes:
        padlen = block - (len(b) % block)
        return b + bytes([padlen]) * padlen


    @staticmethod
    def _hmac(key: bytes, data: bytes, algo: int) -> bytes:
        if   algo == DPAPI.CALG_SHA1:    return HMAC.new(key, data, SHA1).digest()
        elif algo == DPAPI.CALG_SHA_256: return HMAC.new(key, data, SHA256).digest()
        elif algo == DPAPI.CALG_SHA_512: return HMAC.new(key, data, SHA512).digest()
        else:                            return HMAC.new(key, data, SHA256).digest()


    @staticmethod
    def _hash_digest_size(algo: int) -> int:
        return {DPAPI.CALG_SHA1:20, DPAPI.CALG_SHA_256:32, DPAPI.CALG_SHA_512:64}.get(algo, 32)


    @staticmethod
    def _pack_guid(guid_str: str) -> bytes:
        p = guid_str.split("-")
        part1 = int(p[0], 16)
        part2 = int(p[1], 16)
        part3 = int(p[2], 16)
        part4 = [int(p[3][i:i+2], 16) for i in range(0, len(p[3]), 2)]
        part5 = [int(p[4][i:i+2], 16) for i in range(0, len(p[4]), 2)]
        return struct.pack("<L2H8B", part1, part2, part3, *part4, *part5)


    @staticmethod
    def _read_guid_le(buf: bytes, ofs: int):
        (l, h1, h2, *b8) = struct.unpack_from("<L2H8B", buf, ofs)
        ofs += struct.calcsize("<L2H8B")
        guid = f"{l:08x}-{h1:04x}-{h2:04x}-{b8[0]:02x}{b8[1]:02x}-{b8[2]:02x}{b8[3]:02x}{b8[4]:02x}{b8[5]:02x}{b8[6]:02x}{b8[7]:02x}"
        return guid, ofs
    

    @staticmethod
    def _eat_len_bytes(buf: bytes, ofs: int):
        (ln,) = struct.unpack_from("<L", buf, ofs); ofs += 4
        data = buf[ofs:ofs+ln]; ofs += ln
        return data, ofs


    @staticmethod
    def _derive_session_key(masterkey: bytes, salt: bytes, hash_alg: int,
                            entropy: bytes|None, strong_password: bytes|None, smartcard_secret: bytes|None) -> bytes:
        material = salt or b""
        if entropy:          material += b"|E|" + entropy
        if strong_password:  material += b"|P|" + strong_password
        if smartcard_secret: material += b"|S|" + smartcard_secret
        return DPAPI._hmac(masterkey, material, hash_alg)


    @staticmethod
    def _kdf_expand(session: bytes, out_len: int, hash_alg: int, info: bytes) -> bytes:
        out, prev, ctr = b"", b"", 1
        while len(out) < out_len:
            prev = DPAPI._hmac(session, prev + info + bytes([ctr]), hash_alg)
            out += prev
            ctr += 1
        return out[:out_len]


    @staticmethod
    def _parse_blob(raw: bytes):
        ofs = 0
        (version,) = struct.unpack_from("<L", raw, ofs); ofs += 4
        provider_guid, ofs = DPAPI._read_guid_le(raw, ofs)

        blob_start = ofs

        (mkversion,) = struct.unpack_from("<L", raw, ofs); ofs += 4
        mkguid, ofs = DPAPI._read_guid_le(raw, ofs)
        (flags,) = struct.unpack_from("<L", raw, ofs); ofs += 4

        descr_bytes, ofs = DPAPI._eat_len_bytes(raw, ofs)
        try:
            description_utf8 = descr_bytes.decode("UTF-16LE").encode("utf-8")
        except Exception:
            description_utf8 = b""

        (cipher_alg_id,) = struct.unpack_from("<L", raw, ofs); ofs += 4
        (key_len,)       = struct.unpack_from("<L", raw, ofs); ofs += 4
        salt,   ofs = DPAPI._eat_len_bytes(raw, ofs)
        strong, ofs = DPAPI._eat_len_bytes(raw, ofs)
        (hash_alg_id,) = struct.unpack_from("<L", raw, ofs); ofs += 4
        (hash_len,)    = struct.unpack_from("<L", raw, ofs); ofs += 4
        hmac_data,   ofs = DPAPI._eat_len_bytes(raw, ofs)
        cipher_text, ofs = DPAPI._eat_len_bytes(raw, ofs)

        blob_for_hmac = raw[blob_start:ofs]
        sign, ofs = DPAPI._eat_len_bytes(raw, ofs)

        return {
            "version": version,
            "provider_guid": provider_guid,
            "mkversion": mkversion,
            "mkguid": mkguid,
            "flags": flags,
            "description_utf8": description_utf8,
            "cipher_alg_id": cipher_alg_id,
            "key_len": key_len,
            "salt": salt,
            "strong": strong,
            "hash_alg_id": hash_alg_id,
            "hash_len": hash_len,
            "hmac_data": hmac_data,
            "cipher_text": cipher_text,
            "blob_for_hmac": blob_for_hmac,
            "sign": sign,
        }

    @staticmethod
    def _derive_keys(masterkey: bytes, salt: bytes, hash_alg_id: int,
                     key_len: int,
                     entropy: bytes|None, strong_password: bytes|None, smartcard_secret: bytes|None):
        session = DPAPI._derive_session_key(masterkey, salt, hash_alg_id, entropy, strong_password, smartcard_secret)
        enc_key  = DPAPI._kdf_expand(session, key_len or 32, hash_alg_id, b"DPAPI-CIPHER-KEY")
        sign_key = DPAPI._kdf_expand(session, DPAPI._hash_digest_size(hash_alg_id), hash_alg_id, b"DPAPI-SIGN-KEY")
        return enc_key, sign_key


    def decrypt(self, blob: bytes,
                *, entropy: bytes|None=None, strong_password: bytes|None=None, smartcard_secret: bytes|None=None) -> bytes:
        if not hasattr(self, "masterkey") or self.masterkey is None:
            raise DPAPIError("Masterkey not available. Call get_masterkey() first.")

        b = self._parse_blob(blob)
        enc_key, sign_key = self._derive_keys(self.masterkey, b["salt"], b["hash_alg_id"], b["key_len"],
                                              entropy, strong_password, smartcard_secret)

        iv = b"\x00" * 16
        cipher = AES.new(enc_key[:32], AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(b["cipher_text"])
        try:
            pt = unpad(pt, 16)
        except ValueError as e:
            raise DPAPIError(f"Invalid padding: {e}")

        computed = self._hmac(sign_key, b["blob_for_hmac"], b["hash_alg_id"])
        if computed[:len(b["sign"])] != b["sign"]:
            raise DPAPIError("DPAPI HMAC verification failed")

        return pt


    def encrypt(self, template_blob: bytes, cleartext: bytes,
                *, entropy: bytes|None=None, strong_password: bytes|None=None, smartcard_secret: bytes|None=None) -> bytes:
        if not hasattr(self, "masterkey") or self.masterkey is None:
            raise DPAPIError("Masterkey not available. Call get_masterkey() first.")

        b = self._parse_blob(template_blob)
        enc_key, sign_key = self._derive_keys(self.masterkey, b["salt"], b["hash_alg_id"], b["key_len"],
                                              entropy, strong_password, smartcard_secret)

        iv = b"\x00" * 16
        ct = AES.new(enc_key[:32], AES.MODE_CBC, iv=iv).encrypt(self._pkcs7_pad(cleartext, 16))

        out = bytearray()
        out += struct.pack("<L", b["version"])
        out += self._pack_guid(b["provider_guid"])
        out += struct.pack("<L", b["mkversion"])
        out += self._pack_guid(b["mkguid"])
        out += struct.pack("<L", b["flags"])

        descr_utf16 = b["description_utf8"].decode("utf-8").encode("UTF-16LE") if b["description_utf8"] else b""
        out += struct.pack("<L", len(descr_utf16)) + descr_utf16

        out += struct.pack("<L", b["cipher_alg_id"])
        out += struct.pack("<L", b["key_len"])
        out += struct.pack("<L", len(b["salt"])) + b["salt"]
        out += struct.pack("<L", len(b["strong"])) + b["strong"]
        out += struct.pack("<L", b["hash_alg_id"])
        out += struct.pack("<L", b["hash_len"])
        out += struct.pack("<L", len(b["hmac_data"])) + b["hmac_data"]

        out += struct.pack("<L", len(ct)) + ct

        blob_for_hmac = bytes(out)[4 + len(self._pack_guid(b["provider_guid"])):]
        sign = self._hmac(sign_key, blob_for_hmac, b["hash_alg_id"])

        out += struct.pack("<L", len(sign)) + sign
        return bytes(out)


        
        


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