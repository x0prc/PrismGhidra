@PluginInfo(
    status = PluginStatus.STABLE,
    description = "Data Flow Taint Analysis",
    servicesRequired = {DecompilerService.class}
)
public class TaintAnalyzer extends Plugin {
    
    public void analyze(Program program) {
        TaintConfig config = loadConfig();
        TaintEngine engine = new TaintEngine(config);
        
        FunctionManager fm = program.getFunctionManager();
        for(Function func : fm.getFunctions(true)) {
            engine.trackTaint(program, func.getEntryPoint());
        }
        
        new TaintMarker(program).markVulnerabilities(engine.getResults());
    }
    
    private TaintConfig loadConfig() {
        return new TaintConfig(
            getResource("taint_rules/sources.txt"),
            getResource("taint_rules/sinks.txt")
        );
    }
}
