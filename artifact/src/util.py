import struct
import dpapick3.crypto as crypto


class Parser(object):
    def __init__(self, raw, offset=0, end=None, endianness="<"):
        self.raw = raw
        self.ofs = offset
        if end is None:
            end = len(raw)
        self.end = end
        self.endianness = endianness


    def prepare_fmt(self, fmt):
        """Internal use. Prepend endianness to the given format if it is not
        already specified.

        fmt is a format string for struct.unpack()

        Returns a tuple of the format string and the corresponding data size.

        """
        if fmt[0] not in ("<", ">", "!", "@"):
            fmt = self.endianness + fmt
        return fmt, struct.calcsize(fmt)


    def read(self, fmt):
        """Parses data with the given format string without taking away bytes.
        
        Returns an array of elements or just one element depending on fmt.

        """
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        return v


    def eat(self, fmt):
        """Parses data with the given format string.
        
        Returns an array of elements or just one element depending on fmt.

        """
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        self.ofs += sz
        return v
    
    
    def write(self, fmt, *values):
        fmt, _ = self.prepare_fmt(fmt)
        packed_data = struct.pack(fmt, *values)
        self.raw += packed_data
        self.ofs += len(packed_data)
        return packed_data
     

    def eat_string(self, length):
        """Eats and returns a string of length characters"""
        return self.eat("%us" % length)


    def eat_length_and_string(self, fmt):
        """Eats and returns a string which length is obtained after eating
        an integer represented by fmt

        """
        l = self.write(fmt)
        return self.write_string(l)
    
    
    def write_string(self, length):
        """Eats and returns a string of length characters"""
        return self.write("%us" % length)


    def eat_length_and_string(self, fmt):
        """Eats and returns a string which length is obtained after eating
        an integer represented by fmt

        """
        l = self.eat(fmt)
        return self.eat_string(l)


    def pop(self, fmt):
        """Eats a structure represented by fmt from the end of raw data"""
        fmt, sz = self.prepare_fmt(fmt)
        self.end -= sz
        v = struct.unpack_from(fmt, self.raw, self.end)
        if len(v) == 1:
            v = v[0]
        return v


    def pop_string(self, length):
        """Pops and returns a string of length characters"""
        return self.pop("%us" % length)


    def pop_length_and_string(self, fmt):
        """Pops and returns a string which length is obtained after poping an
        integer represented by fmt.

        """
        l = self.pop(fmt)
        return self.pop_string(l)
    
    
    def remain(self):
        """Returns all the bytes that have not been eated nor poped yet."""
        return self.raw[self.ofs:self.end]


    def eat_sub(self, length):
        """Eats a sub-structure that is contained in the next length bytes"""
        sub = self.__class__(self.raw[self.ofs:self.ofs+length], endianness=self.endianness)
        self.ofs += length
        return sub


    #def __nonzero__(self):
    def __bool__(self):
        return self.ofs < self.end



class Blob():
    def __init__(self, raw=None):
        """Constructs a DPAPIBlob. If raw is set, automatically calls
            parse().

        """
        self.version = None
        self.provider = None
        self.mkguid = None
        self.mkversion = None
        self.flags = None
        self.description = None
        self.cipherAlgo = None
        self.keyLen = 0
        self.hmac = None
        self.strong = None
        self.hashAlgo = None
        self.hashLen = 0
        self.cipherText = None
        self.salt = None
        self.blob = None
        self.sign = None
        self.cleartext = None
        self.decrypted = False
        self.signComputed = None
        self.raw = raw
        if raw is not None:
            self.parse(Parser(self.raw, endianness="<"))


    def parse(self, data):
        """Parses the given data. May raise exceptions if incorrect data are
            given. You should not call this function yourself; DataStruct does

            data is a DataStruct object.
            Returns nothing.

        """
        self.version = data.eat("L")
        self.provider = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")

        # For HMAC computation
        blobStart = data.ofs

        self.mkversion = data.eat("L")
        self.mkguid = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")

        self.flags = data.eat("L")
        self.description = data.eat_length_and_string("L").decode("UTF-16LE").encode("utf-8")
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.keyLen = data.eat("L")
        self.salt = data.eat_length_and_string("L")
        self.strong = data.eat_length_and_string("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.hashLen = data.eat("L")
        self.hmac = data.eat_length_and_string("L")
        self.cipherText = data.eat_length_and_string("L")

        # For HMAC computation
        self.blob = data.raw[blobStart:data.ofs]
        self.sign = data.eat_length_and_string("L")
        
        
    def pack(self):
        data = Parser(b"")
        data.write("L", self.version)
        data.write("L2H8B", *self._parse_guid(self.provider))
        blob_start = data.ofs
        data.write("L", self.mkversion)
        data.write("L2H8B", *self._parse_guid(self.mkguid))
        data.write("L", self.flags)
        description_utf16 = self.description.decode("utf-8").encode("UTF-16LE")
        data.write("L", len(description_utf16))
        data.raw += description_utf16
        data.ofs += len(description_utf16)
        data.write("L", int(self.cipherAlgo.algnum))
        data.write("L", self.keyLen)
        data.write("L", len(self.salt))
        data.raw += self.salt
        data.ofs += len(self.salt)
        data.write("L", len(self.strong))
        data.raw += self.strong
        data.ofs += len(self.strong)
        data.write("L", int(self.hashAlgo.algnum))
        data.write("L", self.hashLen)
        data.write("L", len(self.hmac))
        data.raw += self.hmac
        data.ofs += len(self.hmac)
        data.write("L", len(self.cipherText))
        data.raw += self.cipherText
        data.ofs += len(self.cipherText)
        self.blob = data.raw[blob_start:data.ofs]
        data.write("L", len(self.sign))
        data.raw += self.sign
        data.ofs += len(self.sign)
        self.raw = data.raw
        self.parse(Parser(data.raw, endianness="<"))
    
    
    def _parse_guid(self, guid):
        parts = guid.split("-")
        part1 = int(parts[0], 16)
        part2 = int(parts[1], 16)
        part3 = int(parts[2], 16)
        part4 = [int(parts[3][i:i+2], 16) for i in range(0, len(parts[3]), 2)]
        part5 = [int(parts[4][i:i+2], 16) for i in range(0, len(parts[4]), 2)]
        return (part1, part2, part3, *part4, *part5)
        
        
    def encrypt(self, masterkey, entropy=None, strongPassword=None, smartCardSecret=None):
        """Encrypt the blob using the provided parameters.
        :rtype : bool
        :param masterkey: decrypted masterkey value
        :param entropy: optional entropy for encrypting the blob
        :param strongPassword: optional password for encrypting the blob
        :param smartCardSecret: MS Next Gen Crypto secret (e.g. from PIN code)
        """
        for algo in [crypto.CryptSessionKeyType1, crypto.CryptSessionKeyType2]:
            sessionkey = algo(masterkey, self.salt, self.hashAlgo, entropy=entropy, smartcardsecret=smartCardSecret, strongPassword=strongPassword)
            key = crypto.CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo)
            
            # Initialize the cipher based on the algorithm
            if self.cipherAlgo == "RC4":
                cipher = self.cipherAlgo.module.new(key[:int(self.cipherAlgo.keyLength)],
                                                    IV=b'\x00' * int(self.cipherAlgo.ivLength))
            else:
                cipher = self.cipherAlgo.module.new(key[:int(self.cipherAlgo.keyLength)],
                                                    mode=self.cipherAlgo.module.MODE_CBC,
                                                    IV=b'\x00' * int(self.cipherAlgo.ivLength))

            # Perform encryption
            padded_data = self._pad(self.cleartext)  # Ensure the data is properly padded
            self.cipherText = cipher.encrypt(padded_data)
            self.pack()

            # Compute HMAC for integrity verification
            self.signComputed = algo(masterkey, self.hmac, self.hashAlgo, entropy=entropy, smartcardsecret=smartCardSecret, verifBlob=self.blob)
            
            # Store the computed HMAC
            self.sign = self.signComputed

            # Encryption was successful
            self.pack()
            self.encrypted = True
            return True
        
        # Encryption failed
        self.encrypted = False
        return False


    def _pad(self, data):
        padding_len = int(self.cipherAlgo.blockSize - (len(data) % self.cipherAlgo.blockSize))
        return data + bytes([int(padding_len)] * padding_len)


    def decrypt(self, masterkey: bytes, entropy: bytes =None, strongPassword: bytes =None, smartCardSecret: bytes =None) -> bool:
        """Try to decrypt the blob. Returns True/False
        :rtype : bool
        :param masterkey: decrypted masterkey value
        :param entropy: optional entropy for decrypting the blob
        :param strongPassword: optional password for decrypting the blob
        :param smartCardSecret: MS Next Gen Crypto secret (e.g. from PIN code)
        """
        for algo in [crypto.CryptSessionKeyType1, crypto.CryptSessionKeyType2]:
            sessionkey = algo(masterkey, self.salt, self.hashAlgo, entropy=entropy, smartcardsecret=smartCardSecret, strongPassword=strongPassword)
            key = crypto.CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo)
            #RC4 is a stream cipher, and so we need to call module without the mode parameter
            if self.cipherAlgo == "RC4":
              cipher =  self.cipherAlgo.module.new(key[:int(self.cipherAlgo.keyLength)],
                                                  IV=b'\x00' * int(self.cipherAlgo.ivLength))
            else:
              cipher = self.cipherAlgo.module.new(key[:int(self.cipherAlgo.keyLength)],
                                                mode=self.cipherAlgo.module.MODE_CBC,
                                                IV=b'\x00' * int(self.cipherAlgo.ivLength))
            self.cleartext = cipher.decrypt(self.cipherText)
            padding = self.cleartext[-1]
            if padding <= self.cipherAlgo.blockSize:
                self.cleartext = self.cleartext[:-padding]
            # check against provided HMAC
            self.signComputed = algo(masterkey, self.hmac, self.hashAlgo, entropy=entropy, smartcardsecret=smartCardSecret, verifBlob=self.blob)
            self.decrypted = self.signComputed == self.sign
            if self.decrypted:
                # print(self.sign.hex())
                return True
        self.decrypted = False
        return self.decrypted


    def __repr__(self):
        s = ["DPAPI BLOB",
             "\n".join(("\tversion      = %(version)d",
                        "\tprovider     = %(provider)s",
                        "\tmkey         = %(mkguid)s",
                        "\tflags        = %(flags)#x",
                        "\tdescr        = %(description)s",
                        "\tcipherAlgo   = %(cipherAlgo)r",
                        "\thashAlgo     = %(hashAlgo)r")) % self.__dict__,
             "\tsalt         = %s" % self.salt.hex(),
             "\thmac         = %s" % self.hmac.hex(),
             "\tcipher       = %s" % self.cipherText.hex(),
             "\tsign         = %s" % self.sign.hex()]
        if self.signComputed is not None:
            s.append("\tsignComputed = %s" % self.signComputed.hex())
        if self.cleartext is not None:
            s.append("\tcleartext    = %r" % self.cleartext)
        return "\n".join(s)
    
    
    