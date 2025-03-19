public class APIDocumentationService implements ServiceInterface {
    private static final String DOCS_BASE_URL = "https://docs.microsoft.com/en-us/windows/win32/api/";
    private final Map<String, String> docsCache = new ConcurrentHashMap<>();

    public String getDocumentation(String apiName) {
        return docsCache.computeIfAbsent(apiName, this::fetchOnlineDocumentation);
    }

    private String fetchOnlineDocumentation(String apiName) {
        try {
            URL url = new URL(DOCS_BASE_URL + apiName.toLowerCase());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            return parseHTMLDocumentation(conn.getInputStream());
        } catch (Exception e) {
            return "Documentation not available";
        }
    }
    
    private String parseHTMLDocumentation(InputStream htmlStream) {
        // Implementation for extracting relevant docs from HTML
        return "Sample documentation text";
    }
}
