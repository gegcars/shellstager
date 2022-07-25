
from argparse import ArgumentParser
from payload import parse_payload_cmd
from payload import main as payload_main
from handler import parse_handler_cmd
from handler import main as handler_main
import sys


def parse_shellstager_cmd():
    args = None
    parser = None
    try:
        if len(sys.argv) > 2:
            idx=0
            help_flag = False
            for a in sys.argv:
                if a.upper() == "-H" or a.upper() == "--HELP":
                    help_flag = True
                    del sys.argv[idx]
                    break
                idx+=1

        parser = ArgumentParser(description="ShellStager - Shellcode maker for penetration testing.")
        subparsers = parser.add_subparsers()
        getpload = subparsers.add_parser("payload", help="Payload Options.")
        getpload.add_argument("--payload", action="store_true", default=True, help="Payload Options flag.")
        
        schandler = subparsers.add_parser("handler", help="Service Connection Handler Options.")
        schandler.add_argument("--handler", action="store_true", default=True, help="Service Handler Options flag.")

        args = parser.parse_known_args()
        if help_flag:
            args[1].append("-h")
    
    except Exception as e:
        print("[X] ERROR: {0}".format(e))

    return args, parser


def main():
    args, parser = parse_shellstager_cmd()
    if hasattr(args[0], "payload"):
        sys.argv = ["payload"] + args[1]
        args, parser = parse_payload_cmd()
        payload_main.args = args
        payload_main()

    elif hasattr(args[0], "handler"):
        sys.argv = ["handler"] + args[1]
        args, parser = parse_handler_cmd()
        handler_main.args = args
        handler_main()

if __name__ == "__main__":
    main()