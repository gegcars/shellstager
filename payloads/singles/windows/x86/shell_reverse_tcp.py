
from keystone import *  # code assembler

HOST="127.0.0.1"    # Default Host Address
PORT=4444           # Default Port Number

class shell_reverse_tcp(object):
    def __init__(self) -> None:
        self.name = type(self).__name__
        self.platform = "windows"
        self.arch = "x86"
        self.sctype = "single"
        self.stagers = "reverse_tcp"
        self.description = "PUT THE SHELLCODE DESCRIPTION HERE"
        # Add your extra configuration here
        

    def build_shellcode(self):
        '''
        CODE HERE FOR BUILDING EXECUTABLE
        '''
        pass

