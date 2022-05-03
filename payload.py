
from argparse import ArgumentParser, Namespace
from capstone import *
from keystone import *
import os
import pefile
import string
import importlib
import sys


PATH_EXCLUSION = [
    "__init__",
    "__pycache__",
    "loader"
]


class Payloads(object):
    def __init__(self):
        self.config = Namespace()
        self.module_dir = os.path.dirname(__file__)
        self.payloads_dir = os.path.join(self.module_dir, "payloads")
        self.config.path = os.path.join(self.module_dir, "configs")
        self.config.stgr_tmpl = os.path.join(self.config.path, "stager_template.txt")
        self.config.stg_tmpl = os.path.join(self.config.path, "stage_template.txt")
        self.config.sigl_tmpl = os.path.join(self.config.path, "single_template.txt")
        
    
    def _filter_excluded(self, x):
        ret = True
        for n in PATH_EXCLUSION:
            if n in x:
                ret = False
                break
        return ret

    
    def _get_list_payloads(self) -> list[str]:
        return [os.path.join(dp, f) for dp, dn, filenames in os.walk(self.payloads_dir) for f in filenames]

    
    def add_payload(self, platform, arch, sctype, name):
        print("[*] ShellStager Payloads")
        payload_dir = os.path.join(self.payloads_dir, "{0}s".format(sctype), platform, arch)
        if not os.path.exists(payload_dir):
            try:
                os.makedirs(payload_dir)
            except Exception:
                pass

        payload_path = os.path.join(payload_dir, "{0}.py".format(name))
        if os.path.exists(payload_path):
            print("[X] ERROR: {0} already exist. Please use another name.".format(name))
            return

        data = None
        tmpl_file = None
        stagers=None
        if sctype.upper() == "STAGER":
            tmpl_file = self.config.stgr_tmpl
        elif sctype.upper() == "STAGE":
            tmpl_file = self.config.stg_tmpl
        elif sctype.upper() == "SINGLE":
            tmpl_file = self.config.sigl_tmpl
            stagers = "_".join(name.split("_")[1:])

        # Read Template file
        with open(tmpl_file, "r") as tmpl:
            data = tmpl.read()
        # Create payload module
        with open(payload_path, "w") as sct:
            sct.write(string.Template(data).safe_substitute(
                dict(PAYLOAD_NAME=name, PLATFORM=platform, ARCH=arch, STAGERS=stagers, SHELLCODE_TYPE=sctype)))
        print("[-] {0} payload added - {1}".format(sctype.capitalize(), payload_path.replace(self.module_dir, "")[1:]))

    
    def list(self) -> list[str]:
        payload_list = []
        all_payloads = self._get_list_payloads()
        filtered_list = filter(self._filter_excluded, all_payloads)
        try:
            for n in filtered_list:
                fname, ext = os.path.splitext(n)
                if ext != ".py":
                    continue
                if "{0}lib{1}".format(os.path.sep, os.path.sep) in fname or "{0}stagers{1}".format(os.path.sep, os.path.sep) in fname:
                    continue
                modpath = fname.replace(self.module_dir,"").replace(os.path.sep, ".")[1:]
                modname = os.path.basename(fname)
                mod = importlib.import_module(modpath)
                mclass = mod.__getattribute__(modname)()
                if mclass.sctype.upper() == "STAGE":
                    for s in mclass.stagers:
                        payload_list.append(os.path.join(mclass.platform, mclass.arch, modname, s))
                elif mclass.sctype.upper() == "SINGLE":
                    payload_list.append(os.path.join(mclass.platform, mclass.arch, modname))

        except Exception as e:
            print("[X] ERROR: {0}".format(e))
        
        return payload_list
    

    def search_payload(self, search_string):
        list_payload = self.list()
        found_payload = []
        for p in list_payload:
            if search_string.upper() in p.upper():
                found_payload.append(p)
        return found_payload

    
    def assemble_shellcode(self, payload_name, host="127.0.0.1", port=4444, fmt="raw"):
        payload = None
        # Parse Payload Name
        sctype = None
        stage = None
        modname = None
        fname = payload_name.split(os.path.sep)
        modname = fname[-1]
        if len(fname) == 3:
            sctype = "single"
        elif len(fname) == 4:
            # Get the stager of the staged shellcode
            # e.g. windows/x86/shell/reverse_tcp
            # stage: shell, stager/modname: reverse_tcp
            sctype = "stager"
            del fname[-2]
        else:
            print("[X] ERROR: Invalid Payload path format. Payload: <platform>/<arch>/<stage_name>/<stager_name>")
            return

        try:
            payload_name = os.path.sep.join(fname)
            modfullpath = os.path.join(self.payloads_dir, "{0}s".format(sctype), payload_name)
            modpath = modfullpath.replace(self.module_dir, "").replace(os.path.sep,".")[1:]
            mod = importlib.import_module(modpath)
            # Set HOST, PORT and FORMAT global variable
            mod.HOST = host
            mod.PORT = port
            mod.FORMAT = fmt
            mclass = mod.__getattribute__(modname)()
            cnt=0
            payload, cnt = mclass.build_shellcode()
        
        except Exception as e:
            print("[X] ERROR: {0}".format(e))
        
        return payload


    def get_payload(self, name, host, port, fmt):
        sys.stdout.buffer.flush()
        asm = self.assemble_shellcode(name, host, port, fmt)
        sys.stdout.buffer.write(asm)
        sys.stdout.buffer.flush()


    def disasm(self, asm, arch, fmt="raw", offset=0, lines=0):
        try:
            ctr = 0
            cs = Cs(CS_ARCH_X86, CS_MODE_32)
            if "x64" in arch:
                cs = Cs(CS_ARCH_X86, CS_MODE_64)
            
            if fmt.upper() == "EXE" and offset == 0:
                pe = pefile.PE(data=asm)
                # Get FileOffset of EntryPoint
                offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                pe.close()

            print("[*] Showing {0} disassembly:".format("{0} lines".format(lines) if lines > 0 else "full"))
            for n in cs.disasm(asm[offset:], offset):
                print("    0x%x:\t%s\t%s" % (n.address, n.mnemonic, n.op_str))
                ctr+=1
                if lines == 0:
                    continue
                if ctr == lines:
                    break

        except Exception as e:
            print("[X] ERROR: {0}".format(e))


    def call(self, func, *args):
        fn = self.__getattribute__(func)
        return fn(*args)
    


def parse_payload_cmd():
    args = None
    try:
        parser = ArgumentParser(description="ShellStager - tool for penetration testing.")
        parser.add_argument("-l","--list-payloads", action="store_true", help="List all available Payloads.")
        parser.add_argument("-s", "--search-payload", help="List all available Payloads.")        
        
        subparsers = parser.add_subparsers()
        addpload = subparsers.add_parser("add", help="Add new Payload script.")
        addpload.add_argument("--name", required=True, help="Specific name of Payload. Example: shell, exec, uploadexec, downloadexec")
        addpload.add_argument("--arch", required=True, help="Architecture type of shellcode. Examples: x86, x64")
        addpload.add_argument("--platform", required=True, 
                                help="Platform where Payload can be executed. Example: windows, linux, powershell, python")
        addpload.add_argument("--type", choices=["stage", "stager", "single"], 
                    required=True, 
                                help="Type of Payload. \
                                    Choices: \
                                        stages -> small block of shellcode used by stagers, \
                                        stagers -> shellcodes that establishes communications, \
                                        stageless -> stand-alone payloads that contains both stagers and stages.")
        addpload.add_argument("--add", action="store_true", default=True, help="Add flag. Default value is True.")
        
        getpload = subparsers.add_parser("get", help="Get Payload data.")
        getpload.add_argument("--name", required=True, help="Payload full path. Example: windows/x86/shell/reverse_tcp")
        getpload.add_argument("--host", default="127.0.0.1", help="Target host machine.")
        getpload.add_argument("--port", default=4444, type=int, help="Port number.")
        # getpload.add_argument("--arch", default="x86", help="Architecture type of shellcode. Examples: x86, x64")
        getpload.add_argument("-f","--format", choices=["raw", "exe"], default="raw", 
                                help="Output format of the shellcode. Choices: raw, exe")
        getpload.add_argument("--get", action="store_true", default=True, help="Get flag. Default value is True.")
        
        disasmpload = subparsers.add_parser("disasm", help="Show Disassembly of Payload.")
        disasmpload.add_argument("--name", required=True, help="Payload full path. Example: windows/x86/shell/reverse_tcp")
        disasmpload.add_argument("--host", default="127.0.0.1", help="Target host machine.")
        disasmpload.add_argument("--port", default=4444, type=int, help="Port number.")
        # disasmpload.add_argument("--arch", default="x86", help="Architecture type of shellcode. Examples: x86, x64")
        disasmpload.add_argument("-f","--format", choices=["raw", "exe"], default="raw", 
                                help="Output format of the shellcode. Choices: raw, exe")
        disasmpload.add_argument("--offset", type=int, default=0, help="Starting offset of disassembly.")
        disasmpload.add_argument("--lines", type=int, default=0, help="Number of disassembly lines.")
        disasmpload.add_argument("--disasm", action="store_true", default=True, 
                                help="Disassembly flag. Default value is True.")
        
        args = parser.parse_args()
    
    except Exception as e:
        print("[X] ERROR: {0}".format(e))

    return args, parser


def main():
    try:
        args, parser = parse_payload_cmd()
        payload = Payloads()

        if hasattr(args, "add"):
            payload.add_payload(args.platform, args.arch, args.type, args.name)
            return

        elif hasattr(args, "get"):
            payload.get_payload(args.name, args.host, args.port, args.format)
            return

        elif hasattr(args, "disasm"):
            platform, arch, sctype, scname = args.name.split(os.path.sep)
            asm = payload.assemble_shellcode(args.name, args.host, args.port, args.format)
            payload.disasm(asm, arch, args.format, args.offset, args.lines)
            return

        elif args.list_payloads:
            print("[*] ShellStager Payloads")
            ploads = payload.list()
            for p in ploads:
                print("[-]   {0}".format(p))
            return

        elif args.search_payload:
            print("[*] ShellStager Payloads")
            ploads = payload.search_payload(args.search_payload)
            for p in ploads:
                print("[-]   {0}".format(p))            
            return

    except Exception as e:
        print("[X] ERROR: {0}".format(e))


if __name__ == "__main__":
    main()

