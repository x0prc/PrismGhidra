import ghidra.app.plugin.core.graph.GraphDisplayProvider;
import ghidra.app.services.GraphService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.service.graph.*;
import ghidra.util.task.TaskMonitor;

public class XrefGraphBuilder implements GraphService {

    private final PluginTool tool;
    private final Program program;
    private AttributedGraph graph;

    public XrefGraphBuilder(PluginTool tool, Program program) {
        this.tool = tool;
        this.program = program;
        this.graph = new AttributedGraph("Cross References", "From", "To");
    }

    public void buildFunctionXrefGraph(TaskMonitor monitor) {
        FunctionManager functionManager = program.getFunctionManager();
        
        // Build function nodes
        for (Function function : functionManager.getFunctions(true)) {
            String funcName = function.getName();
            Address entry = function.getEntryPoint();
            
            AttributedVertex source = graph.addVertex(funcName);
            source.setAttribute("Type", "Function");
            source.setAttribute("Address", entry.toString());
            
            // Add called functions edges
            for (Function calledFunc : function.getCalledFunctions(monitor)) {
                AttributedVertex target = getOrCreateVertex(calledFunc);
                graph.addEdge(source, target, "Calls");
            }
            
            // Add data references edges
            addDataReferences(entry, source);
        }
    }

    private AttributedVertex getOrCreateVertex(Function function) {
        String name = function.getName();
        return graph.getVertex(name) != null ? 
            graph.getVertex(name) : 
            graph.addVertex(name).setAttribute("Type", "Function");
    }

    private void addDataReferences(Address address, AttributedVertex source) {
        ReferenceIterator refs = program.getReferenceManager().getReferencesFrom(address);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isData()) {
                AttributedVertex target = graph.addVertex(ref.getToAddress().toString());
                target.setAttribute("Type", "Data");
                graph.addEdge(source, target, "References");
            }
        }
    }

    public void displayGraph() {
        GraphDisplayProvider provider = tool.getService(GraphDisplayProvider.class);
        GraphDisplay display = provider.getGraphDisplay(false, monitor);
        
        display.setGraph(graph, "Cross References", false, monitor);
        display.setLocation(new ProgramLocation(program, program.getMinAddress()));
        
        // Configure visual properties
        display.setVertexLabel("Name", GraphDisplay.ALIGN_HORIZONTAL_CENTER, 12);
        display.setEdgeLabel("Label", GraphDisplay.ALIGN_CENTER, 10);
        display.setVertexColor("Type", 
            attr -> "Function".equals(attr) ? java.awt.Color.CYAN : java.awt.Color.ORANGE);
    }
}
