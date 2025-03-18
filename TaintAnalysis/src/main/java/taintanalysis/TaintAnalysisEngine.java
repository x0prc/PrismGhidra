public class TaintAnalysisEngine extends PcodeEmulator {
    private final Set<Address> taintedAddresses = new HashSet<>();
    private final Map<Varnode, TaintSet> taintMap = new HashMap<>();
    
    public void trackTaint(Program program, Address startAddr) {
        emulate(program, startAddr);
        checkSinks(program);
    }

    @Override
    protected void executeOp(PcodeOp op) {
        switch(op.getOpcode()) {
            case PcodeOp.LOAD:
                propagateMemoryTaint(op);
                break;
            case PcodeOp.STORE:
                checkStoreTaint(op);
                break;
            case PcodeOp.COPY:
                propagateCopyTaint(op);
                break;
        }
    }
    
    private void propagateMemoryTaint(PcodeOp op) {
        Varnode output = op.getOutput();
        Address addr = op.getInput(1).getAddress();
        if(taintedAddresses.contains(addr)) {
            taintMap.put(output, new TaintSet(TaintLevel.HIGH));
        }
    }
}
