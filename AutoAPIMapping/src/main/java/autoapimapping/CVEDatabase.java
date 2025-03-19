public class CVEDatabase {
    private static final Map<String, List<String>> cveMap = new HashMap<>();

    public CVEDatabase(InputStream cveStream) {
        loadCVEData(cveStream);
    }

    private void loadCVEData(InputStream cveStream) {
        try (Reader reader = new InputStreamReader(cveStream)) {
            Type type = new TypeToken<Map<String, List<String>>>(){}.getType();
            cveMap.putAll(new Gson().fromJson(reader, type));
        } catch (IOException e) {
            Msg.error(this, "Failed to load CVE database", e);
        }
    }

    public static List<String> getCVEsForAPI(String apiName) {
        return cveMap.getOrDefault(apiName, Collections.emptyList());
    }
}
