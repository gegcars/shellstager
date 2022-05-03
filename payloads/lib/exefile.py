
from keystone import *
import pefile

class exefile(object):
    def __init__(self) -> None:
        # self.mzheader=b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        # self.mzheader+=b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8\x00\x00\x00"
        # self.mzheader+=b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68"
        # self.mzheader+=b"\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f"
        # self.mzheader+=b"\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20"
        # self.mzheader+=b"\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a\x24\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x5d\x17\x1d\xdb\x19\x76\x73\x88\x19\x76\x73\x88\x19\x76\x73\x88"
        # self.mzheader+=b"\xe5\x56\x61\x88\x18\x76\x73\x88\x52\x69\x63\x68\x19\x76\x73\x88"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x50\x45\x00\x00\x4c\x01\x01\x00"
        # self.mzheader+=b"\x63\x1a\x1f\x62\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x0f\x01"
        # self.mzheader+=b"\x0b\x01\x05\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x10\x00\x00\x00\x10\x00\x00\x00\x20\x00\x00\x00\x00\x40\x00"
        # self.mzheader+=b"\x00\x10\x00\x00\x00\x02\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x02\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00"
        # self.mzheader+=b"\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x2e\x74\x65\x78\x74\x00\x00\x00\x60\x01\x00\x00\x00\x10\x00\x00"
        # self.mzheader+=b"\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x20\x00\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # self.mzheader+=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        
        # Initialize MZ-PE Header
        d = [0 for n in range(512)]
        d[0:2] = [0x4d, 0x5a]
        d[0x3c] = 0xa8              # Default PE Offset
        d[0xa8:0xaa] = [0x50,0x45]
        # Fill DOS Header
        self.mz_pe_header = pefile.PE(data=bytes(d))
        self.mz_pe_header.DOS_HEADER.e_magic = 0x5a4d
        self.mz_pe_header.DOS_HEADER.e_cblp = 0x90
        self.mz_pe_header.DOS_HEADER.e_cp = 0x03
        self.mz_pe_header.DOS_HEADER.e_crlc = 0x00
        self.mz_pe_header.DOS_HEADER.e_cparhdr = 0x04
        self.mz_pe_header.DOS_HEADER.e_minalloc = 0x00
        self.mz_pe_header.DOS_HEADER.e_maxalloc = 0xffff
        self.mz_pe_header.DOS_HEADER.e_ss = 0x00
        self.mz_pe_header.DOS_HEADER.e_sp = 0xb8
        self.mz_pe_header.DOS_HEADER.e_csum = 0x00
        self.mz_pe_header.DOS_HEADER.e_ip = 0x00
        self.mz_pe_header.DOS_HEADER.e_cs = 0x00
        self.mz_pe_header.DOS_HEADER.e_lfarlc = 0x40
        self.mz_pe_header.DOS_HEADER.e_ovno = 0x00
        self.mz_pe_header.DOS_HEADER.e_res = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        self.mz_pe_header.DOS_HEADER.e_oemid = 0x00
        self.mz_pe_header.DOS_HEADER.e_oeminfo = 0x00
        self.mz_pe_header.DOS_HEADER.e_res2 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        # self.mz_pe_header.DOS_HEADER.e_lfanew = 0xa8
        dos_asm = '''
            push        cs
            pop         ds
            mov         dx,0000Eh
            mov         ah,9
            int         021h
            mov         ax,04C01h
            int         021h        
        '''
        ks = Ks(KS_ARCH_X86, KS_MODE_16)
        DOS_STUB, cnt = ks.asm(dos_asm)
        dos_mode_str = "This program cannot be run in DOS mode.\x0D\x0D\x0A$"
        DOS_STUB += [ord(n) for n in dos_mode_str] + [0 for n in range(7)]
        # signature between DOS and PE Header
        DOS_STUB += [
            0x5D, 0x17, 0x1D, 0xDB, 0x19, 0x76, 0x73, 0x88, 
            0x19, 0x76, 0x73, 0x88, 0x19, 0x76, 0x73, 0x88, 
            0xE5, 0x56, 0x61, 0x88, 0x18, 0x76, 0x73, 0x88, 
            0x52, 0x69, 0x63, 0x68, 0x19, 0x76, 0x73, 0x88
        ]
        zero_padding = self.mz_pe_header.DOS_HEADER.e_lfanew - (len(DOS_STUB) + 0x40)
        DOS_STUB += [0 for n in range(zero_padding)]
        # Write changes to MZ-PE structure
        # and reload the MZ-PE structure
        self.mz_pe_header = self.mz_pe_header.write()
        self.mz_pe_header[0x40:0x40+len(DOS_STUB)] = DOS_STUB
        self.mz_pe_header = pefile.PE(data=self.mz_pe_header)
        # Fill FILE_HEADER
        self.mz_pe_header.FILE_HEADER.Machine = 0x14C
        self.mz_pe_header.FILE_HEADER.NumberOfSections = 1
        self.mz_pe_header.FILE_HEADER.TimeDateStamp = 0x621f1a63
        self.mz_pe_header.FILE_HEADER.PointerToSymbolTable = 0
        self.mz_pe_header.FILE_HEADER.NumberOfSymbols = 0
        self.mz_pe_header.FILE_HEADER.SizeOfOptionalHeader = 0x00E0
        self.mz_pe_header.FILE_HEADER.Characteristics = 0x10F
        # Fille OPTIONAL_HEADER
        self.mz_pe_header.OPTIONAL_HEADER.Magic = 0x10b                 
        self.mz_pe_header.OPTIONAL_HEADER.MajorLinkerVersion = 0x5
        self.mz_pe_header.OPTIONAL_HEADER.MinorLinkerVersion = 0x0c
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfCode = 0x200
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfInitializedData = 0
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfUninitializedData = 0
        self.mz_pe_header.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        self.mz_pe_header.OPTIONAL_HEADER.BaseOfCode = 0x1000
        self.mz_pe_header.OPTIONAL_HEADER.BaseOfData = 0x2000
        self.mz_pe_header.OPTIONAL_HEADER.ImageBase = 0x400000
        self.mz_pe_header.OPTIONAL_HEADER.SectionAlignment = 0x1000
        self.mz_pe_header.OPTIONAL_HEADER.FileAlignment = 0x200
        self.mz_pe_header.OPTIONAL_HEADER.MajorOperatingSystemVersion = 0x4
        self.mz_pe_header.OPTIONAL_HEADER.MinorOperatingSystemVersion = 0x0
        self.mz_pe_header.OPTIONAL_HEADER.MajorImageVersion = 0x0
        self.mz_pe_header.OPTIONAL_HEADER.MinorImageVersion = 0x0
        self.mz_pe_header.OPTIONAL_HEADER.MajorSubsystemVersion = 0x4
        self.mz_pe_header.OPTIONAL_HEADER.MinorSubsystemVersion = 0x0
        self.mz_pe_header.OPTIONAL_HEADER.Reserved1 = 0x0
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfImage = 0x2000
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfHeaders = 0x200
        self.mz_pe_header.OPTIONAL_HEADER.CheckSum = 0
        self.mz_pe_header.OPTIONAL_HEADER.Subsystem = 0x2
        self.mz_pe_header.OPTIONAL_HEADER.DllCharacteristics = 0
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfStackReserve = 0x100000
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfStackCommit = 0x1000
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfHeapReserve = 0x100000
        self.mz_pe_header.OPTIONAL_HEADER.SizeOfHeapCommit = 0x1000
        self.mz_pe_header.OPTIONAL_HEADER.LoaderFlags = 0
        self.mz_pe_header.OPTIONAL_HEADER.NumberOfRvaAndSizes = 0x10
        # DATA_DIRECTORY -> IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
        self.mz_pe_header.OPTIONAL_HEADER.DATA_DIRECTORY = []

        section = pefile.SectionStructure(self.mz_pe_header.__IMAGE_SECTION_HEADER_format__, pe=self.mz_pe_header)
        section.set_file_offset(0xa8+0xf8)
        section.Name = b".text"
        section.Misc = 0x0000160
        section.Misc_PhysicalAddress = 0x0000160
        section.Misc_VirtualSize = 0x0000160
        section.VirtualAddress = 0x1000
        section.SizeOfRawData = 0x200
        section.PointerToRawData = 0x200
        section.PointerToRelocations = 0
        section.PointerToLinenumbers = 0
        section.NumberOfRelocations = 0
        section.NumberOfLinenumbers = 0
        section.Characteristics = 0x60000020
        
        self.mz_pe_header = self.mz_pe_header.write()
        j = section.dump_dict()
        import struct
        for n in j:
            sizestr = 0
            if n == "Structure":
                continue
            if type(j[n]["Value"]) == int:
                sizestr = 4
                self.mz_pe_header[j[n]["FileOffset"]:j[n]["FileOffset"]+sizestr] = struct.pack("<I", j[n]["Value"])
            else:
                sizestr = 8
                self.mz_pe_header[j[n]["FileOffset"]:j[n]["FileOffset"]+sizestr] = [ord(n) for n in j[n]["Value"]] + [0,0,0]
        
        