import ghidra.util.Msg;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class TaintConfig {
    private final List<String> sources = new ArrayList<>();
    private final List<String> sinks = new ArrayList<>();
    private final List<TaintPropagationRule> propagationRules = new ArrayList<>();

    public TaintConfig() {
        // Load default embedded rules
        loadEmbeddedConfig("/resources/sources.txt", sources);
        loadEmbeddedConfig("/resources/sinks.txt", sinks);
        initDefaultPropagation();
    }

    private void loadEmbeddedConfig(String resourcePath, List<String> target) {
        try (InputStream is = getClass().getResourceAsStream(resourcePath);
             BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("#") && !line.trim().isEmpty()) {
                    target.add(line.trim());
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to load taint config: " + resourcePath, e);
        }
    }

    private void initDefaultPropagation() {
        // Default propagation rules based on p-code operations
        propagationRules.addAll(List.of(
            new TaintPropagationRule("LOAD", TaintPropagation.INHERIT_FROM_MEM),
            new TaintPropagationRule("STORE", TaintPropagation.PROPAGATE_TO_MEM),
            new TaintPropagationRule("COPY", TaintPropagation.FORWARD_PROPAGATION)
        ));
    }

    // Getters for analysis components
    public List<String> get
