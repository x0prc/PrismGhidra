package enhanceddebuggerintegration;
@PluginInfo(
    status = PluginStatus.STABLE,
    description = "Multi-Debugger Integration",
    servicesRequired = {DebuggerModelService.class, ProgramManager.class}
)
public class MultiDebuggerPlugin extends Plugin {
    
    private DebuggerModelService modelService;
    private Program currentProgram;

    @Override
    protected void init() {
        modelService = tool.getService(DebuggerModelService.class);
        currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
        
        // Initialize debugger models
        modelService.addModel(new GdbDebuggerModel());
        modelService.addModel(new WinDbgDebuggerModel());
    }
    
    // Debugger event handler
    private void handleDebugEvent(DebuggerModel model, DebuggerEvent<?> event) {
        if (event instanceof RegisterChangeEvent) {
            updateRegisterDisplay(((RegisterChangeEvent)event).getRegisters());
        }
    }
}
