import sys
import socket
import json
import threading
import pykd
from pykd import eventHandler, dbgCommand

class WinDbgGhidraBridge:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.running = True
        self.lock = threading.Lock()
        
        # Register event handlers
        eventHandler.breakpoint = self.on_breakpoint
        eventHandler.exception = self.on_exception
        eventHandler.execStatus = self.on_exec_status
        
        self.connect()
        self.start_listener()

    def connect(self):
        """Establish TCP connection to Ghidra plugin"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.send_system_info()
        except Exception as e:
            pykd.dprint(f"Connection failed: {str(e)}")
            sys.exit(1)

    def send_system_info(self):
        """Send architecture and module info to Ghidra"""
        info = {
            "type": "system_info",
            "arch": pykd.getCPUArchitecture(),
            "modules": self.get_loaded_modules(),
            "bits": pykd.ptrSize() * 8
        }
        self.send_json(info)

    def get_loaded_modules(self):
        """Retrieve list of loaded modules with base addresses"""
        return [{
            "name": module.name,
            "base": hex(module.base),
            "size": hex(module.size)
        } for module in pykd.loadModules()]

    def on_breakpoint(self, bp):
        """Handle breakpoint events"""
        self.send_context("breakpoint", bp.getOffset())

    def on_exception(self, exception):
        """Handle exception events"""
        self.send_context("exception", exception.exceptionCode)

    def on_exec_status(self, status):
        """Handle execution state changes"""
        if status == pykd.execStatus.Break:
            self.send_context("pause")

    def send_context(self, event_type, data=None):
        """Send current execution context to Ghidra"""
        with self.lock:
            context = {
                "type": event_type,
                "registers": self.get_registers(),
                "disassembly": self.get_disassembly(),
                "stack": self.get_stack_trace(),
                "data": data
            }
            self.send_json(context)

    def get_registers(self):
        """Capture current register values"""
        return {reg.name: hex(reg.value) for reg in pykd.registers()}

    def get_disassembly(self):
        """Get disassembly around current instruction"""
        return pykd.disasm().dump()

    def get_stack_trace(self):
        """Capture stack trace with 10 frames"""
        return [hex(frame.ip) for frame in pykd.getStack()[:10]]

    def start_listener(self):
        """Start thread to handle incoming Ghidra commands"""
        def listener():
            while self.running:
                try:
                    data = self.sock.recv(4096)
                    if not data:
                        break
                    self.handle_command(json.loads(data.decode()))
                except Exception as e:
                    pykd.dprint(f"Receive error: {str(e)}")
                    break
        
        threading.Thread(target=listener, daemon=True).start()

    def handle_command(self, cmd):
        """Process commands from Ghidra"""
        if cmd["type"] == "breakpoint":
            self.set_breakpoint(cmd["address"])
        elif cmd["type"] == "resume":
            pykd.go()
        elif cmd["type"] == "step":
            pykd.stepInto()

    def set_breakpoint(self, address):
        """Set breakpoint from Ghidra request"""
        try:
            bp = pykd.setBp(pykd.ptr64(address))
            pykd.dprint(f"Breakpoint set at {hex(bp.getOffset())}")
        except pykd.DbgException as e:
            pykd.dprint(f"Failed to set BP: {str(e)}")

    def send_json(self, data):
        """Serialize and send JSON data"""
        try:
            self.sock.sendall(json.dumps(data).encode() + b"\n")
        except Exception as e:
            pykd.dprint(f"Send error: {str(e)}")
            self.running = False

    def shutdown(self):
        """Cleanup resources"""
        self.running = False
        if self.sock:
            self.sock.close()

def start_bridge(host="localhost", port=9090):
    """Entry point for WinDbg integration"""
    try:
        bridge = WinDbgGhidraBridge(host, port)
        pykd.dprint("Ghidra bridge activated!")
        return bridge
    except Exception as e:
        pykd.dprint(f"Failed to start bridge: {str(e)}")

# Usage in WinDbg:
# .load pykd
# !py windbg_bridge.py
# ghidra_bridge = start_bridge("ghidra_host", 9090)
