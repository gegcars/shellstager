
from keystone import *  # code assembler

HOST="127.0.0.1"    # Default Host Address
PORT=4444           # Default Port Number
FORMAT="raw"        # Default Format

class uploadexec(object):
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
        self.description = "PUT THE SHELLCODE DESCRIPTION HERE"
        # Add your extra configuration here
        

    def build_shellcode(self):
        '''
        CODE HERE FOR BUILDING EXECUTABLE
        '''
        pass

