import gdb, socket, json

class GhidraSync(gdb.Command):
    def __init__(self):
        super().__init__("ghidra-sync", gdb.COMMAND_USER)
        self.sock = None
        
    def invoke(self, args, from_tty):
        host, port = args.split(":")
        self.connect(host, int(port))
        
    def connect(self, host, port):
        self.sock = socket.socket()
        self.sock.connect((host, port))
        gdb.events.stop.connect(self.sync_state)
        
    def sync_state(self, event):
        regs = {str(reg): int(gdb.parse_and_eval(f"${str(reg)}")) 
               for reg in gdb.selected_frame().architecture().registers()}
        self.sock.send(json.dumps({
            "registers": regs,
            "memory": self.read_memory()
        }).encode())

GhidraSync()
