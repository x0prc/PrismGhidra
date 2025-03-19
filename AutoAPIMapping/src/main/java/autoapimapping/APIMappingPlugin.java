@PluginInfo(
    status = PluginStatus.STABLE,
    description = "API Documentation and Vulnerability Mapper",
    servicesRequired = {BookmarkService.class, DecompilerService.class}
)
public class APIMappingPlugin extends Plugin {

    private CVEDatabase cveDb;
    private APIDocumentationService docService;

    @Override
    protected void init() {
        cveDb = new CVEDatabase(getResource("cve_database.json"));
        docService = new APIDocumentationService();
        tool.addService(APIDocumentationService.class, docService);
        
        // Register analyzer
        tool.addPlugin(APIMappingAnalyzer.class);
    }
}
