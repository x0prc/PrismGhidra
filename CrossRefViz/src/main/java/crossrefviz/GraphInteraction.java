package com.visualizer;

import ghidra.graph.viewer.event.mouse.VertexClickListener;
import ghidra.program.util.ProgramLocation;
import ghidra.service.graph.*;

public class GraphInteraction implements VertexClickListener<AttributedVertex> {

    private final Program program;
    private final GraphDisplay display;

    public GraphInteraction(Program program, GraphDisplay display) {
        this.program = program;
        this.display = display;
    }

    @Override
    public void vertexClicked(AttributedVertex vertex) {
        String addressStr = vertex.getAttribute("Address");
        if (addressStr != null) {
            Address address = program.getAddressFactory().getAddress(addressStr);
            display.setLocation(new ProgramLocation(program, address));
        }
        
        // Highlight connected components
        display.selectVertices(List.of(vertex));
        display.setFocusedVertex(vertex);
    }
}
