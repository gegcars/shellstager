'''
USE THIS SCRIPT TO TEST THE PAYLOAD YOU ARE DEVELOPING
'''
import os
import importlib

WORKING_DIR = os.getcwd()

PATH_EXCLUSION = [
    "__init__",
    "__pycache__",
    "handler"
]

def filter_excluded(x):
    ret = True
    for n in PATH_EXCLUSION:
        if n in x:
            ret = False
            break
    return ret


def get_list_payloads(dirpath):
    return [os.path.join(dp, f) for dp, dn, filenames in os.walk(dirpath) for f in filenames]


def get_payloads_by_type(sctype) -> list[str]:
    list_payload = get_list_payloads(os.path.join(os.path.dirname(__file__), sctype))
    filtered_payloads = filter(filter_excluded, list_payload)
    payloads = []
    for p in filtered_payloads:
        fname, ext = os.path.splitext(p)
        if ext != ".py":
            continue
        payloads.append(p)
    return payloads


def loadmodule(p):
    module_name = os.path.splitext(os.path.basename(p))[0]
    modpath = os.path.splitext(p)[0].replace(WORKING_DIR,"").replace(os.path.sep, ".")[1:]
    module = None
    try:
        module = importlib.import_module(modpath)
        print("[*] Successfully loaded {0} module.".format(module_name))
    except Exception as e:
        print("[X] Error loading {0} module. {1}".format(module_name, e))

    return module


if __name__ == "__main__":
    payloads_dir = [
        "lib",
        "singles",
        "stagers",
        "stages"
    ]
    for d in payloads_dir:
        p = get_payloads_by_type(os.path.join(WORKING_DIR, "payloads", d))
        for l in p:
            mod = loadmodule(l)
            if hasattr(mod, "reverse_http"):
                mclass = mod.__getattribute__("reverse_http")()
                mclass.build_shellcode()

    
    