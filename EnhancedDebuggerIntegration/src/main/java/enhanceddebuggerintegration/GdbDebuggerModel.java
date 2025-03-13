import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerModel;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.TargetObject;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

public class GdbDebuggerModel implements DebuggerModel {
    private GdbClient client;
    private DebuggerModelListener listener;
    private DebuggerStatusGUI statusGUI;

    public GdbDebuggerModel(DebuggerStatusGUI statusGUI) {
        this.statusGUI = statusGUI;
    }

    @Override
    public void connect(String host, int port) throws DebuggerModelAccessException {
        TaskLauncher.launchNonModal("GDB Connect", () -> {
            try {
                client = new GdbClient(host, port);
                client.setMessageHandler(this::handleGdbMessage);
                statusGUI.updateConnectionStatus("Connected to " + host + ":" + port);
            } catch (Exception e) {
                Msg.showError(this, null, "Connection Failed", 
                    "Could not connect to GDB at " + host + ":" + port, e);
            }
        });
    }

    private void handleGdbMessage(String json) {
        GdbMessage msg = new Gson().fromJson(json, GdbMessage.class);
        switch (msg.type) {
            case "registers":
                statusGUI.updateRegisters(msg.registers);
                break;
            case "memory":
                statusGUI.updateMemory(msg.memory);
                break;
            case "breakpoint":
                handleBreakpoint(msg.address);
                break;
        }
    }

    private void handleBreakpoint(long address) {
        // Sync breakpoints with Ghidra's BreakpointService
        BreakpointService bpService = tool.getService(BreakpointService.class);
        bpService.addBreakpoint(currentProgram, Long.toHexString(address));
    }

    @Override
    public void disconnect() {
        if (client != null) {
            client.close();
            statusGUI.updateConnectionStatus("Disconnected");
        }
    }

    // Helper class for GDB communication
    private static class GdbClient {
        private final Socket socket;
        private final Thread receiverThread;

        public GdbClient(String host, int port) throws IOException {
            socket = new Socket(host, port);
            receiverThread = new Thread(this::receiveMessages);
            receiverThread.start();
        }

        private void receiveMessages() {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    handleGdbMessage(line);
                }
            } catch (IOException e) {
                Msg.error(this, "GDB connection lost", e);
            }
        }

        public void sendCommand(String command) {
            try {
                socket.getOutputStream().write((command + "\n").getBytes());
            } catch (IOException e) {
                Msg.showError(this, null, "Send Failed", 
                    "Failed to send command to GDB", e);
            }
        }

        public void close() {
            try {
                socket.close();
            } catch (IOException e) {
                // Ignored
            }
        }
    }
}
