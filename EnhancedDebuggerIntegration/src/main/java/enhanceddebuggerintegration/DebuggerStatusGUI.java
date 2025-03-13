import ghidra.app.plugin.core.debug.gui.DebuggerComponentProvider;
import ghidra.dbg.DebuggerModel;
import ghidra.util.datastruct.ListenerSet;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.Map;

public class DebuggerStatusGUI extends DebuggerComponentProvider {
    private JTable registerTable;
    private JTextArea memoryArea;
    private JLabel statusLabel;
    private DefaultTableModel registerModel;

    public DebuggerStatusGUI(PluginTool tool) {
        super(tool, "Debugger Status", "DebuggerStatus");
        buildUI();
    }

    private void buildUI() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Register Table
        registerModel = new DefaultTableModel(new Object[]{"Register", "Value"}, 0);
        registerTable = new JTable(registerModel);
        mainPanel.add(new JScrollPane(registerTable), BorderLayout.WEST);
        
        // Memory Viewer
        memoryArea = new JTextArea(10, 40);
        mainPanel.add(new JScrollPane(memoryArea), BorderLayout.CENTER);
        
        // Status Bar
        statusLabel = new JLabel("Not connected");
        mainPanel.add(statusLabel, BorderLayout.SOUTH);
        
        addMainPanel(mainPanel);
    }

    public void updateRegisters(Map<String, Long> registers) {
        SwingUtilities.invokeLater(() -> {
            registerModel.setRowCount(0);
            registers.forEach((name, value) -> 
                registerModel.addRow(new Object[]{name, String.format("0x%x", value)}));
        });
    }

    public void updateMemory(String hexDump) {
        SwingUtilities.invokeLater(() -> {
            memoryArea.setText(hexDump);
        });
    }

    public void updateConnectionStatus(String status) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(status);
        });
    }

    @Override
    public void setModel(DebuggerModel model) {
        super.setModel(model);
        if (model != null) {
            model.addListener(new DebuggerModelListener() {
                @Override
                public void modelStateChanged() {
                    updateFromModel();
                }
            });
        }
    }

    private void updateFromModel() {
        // Handle model state changes
    }
}
