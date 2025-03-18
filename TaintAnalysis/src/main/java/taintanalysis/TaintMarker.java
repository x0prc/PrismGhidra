public class TaintMarker {
    public void markVulnerabilities(List<TaintResult> results) {
        BookmarkManager bm = currentProgram.getBookmarkManager();
        DecompInterface decompiler = new DecompInterface();
        
        for(TaintResult result : results) {
            bm.setBookmark(result.address(), "TAINT", 
                "Tainted data flow to " + result.sinkName());
            
            DecompileResults dr = decompiler.decompileFunction(
                result.function(), 30, TaskMonitor.DUMMY
            );
            dr.getHighFunction().getLocalSymbolMap()
                .getSymbols().forEach(sym -> {
                    if(sym.isTainted()) {
                        setHighlight(sym.getStorage(), Color.RED);
                    }
                });
        }
    }
}
