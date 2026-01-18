package com.learn.api_gateway.util;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class SchemaRegistryLoader {
	// path -> (version -> schema)
    private final Map<String, Map<String, JsonSchema>> requestSchemas = new ConcurrentHashMap<>();
    private final Map<String, Map<String, JsonSchema>> responseSchemas = new ConcurrentHashMap<>();

    @Getter
    private final Set<String> excludedPaths = new HashSet<>();

    private final ObjectMapper objectMapper;
    private final JsonSchemaFactory schemaFactory;

    // Configurable defaults
    private final String defaultVersion;
    private final boolean reloadOnConfigChange;

    private static final Pattern FILENAME_PATTERN =
            Pattern.compile("^(?<name>.+?)(?:-v(?<version>\\d+))?(?<response>-response)?\\.json$");

    public SchemaRegistryLoader(
            ObjectMapper objectMapper,
            @Value("${schema.default-version:v1}") String defaultVersion,
            @Value("${schema.reload-on-config-change:true}") boolean reloadOnConfigChange,
            @Value("${schema.excluded-paths:}") List<String> excluded
    ) {
        this.objectMapper = objectMapper;
        this.schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
        this.defaultVersion = defaultVersion;
        this.reloadOnConfigChange = reloadOnConfigChange;
        if (excluded != null) {
            this.excludedPaths.addAll(excluded);
        }
        loadSchemas();
    }

    /**
     * Main loader – reads all JSON schema files under classpath:schema/**\/*.json
     * Can be extended later to also read from Consul KV or a mounted GitOps volume.
     */
    private synchronized void loadSchemas() {
        requestSchemas.clear();
        responseSchemas.clear();

        PathMatchingResourcePatternResolver resolver =
                new PathMatchingResourcePatternResolver();

        try {
            Resource[] resources = resolver.getResources("classpath:schema/**/*.json");
            log.info("Loading JSON Schemas from classpath:schema/**/*.json (found {} files)", resources.length);

            for (Resource resource : resources) {
                if (!resource.isReadable()) continue;

                String filename = resource.getFilename();
                if (filename == null || !filename.endsWith(".json")) continue;

                String folder = resolveFolderName(resource);
                if (folder == null) {
                    log.warn("Cannot resolve folder for schema resource {} – skipping", resource);
                    continue;
                }

                Matcher matcher = FILENAME_PATTERN.matcher(filename);
                if (!matcher.matches()) {
                    log.warn("Schema filename '{}' does not match expected pattern – skipping", filename);
                    continue;
                }

                String name = matcher.group("name");             // e.g. signup, login, profile-update
                String version = Optional.ofNullable(matcher.group("version"))
                        .map(v -> "v" + v)
                        .orElse(defaultVersion);                 // e.g. v1
                boolean isResponseSchema = matcher.group("response") != null;

                String apiPath = deriveApiPath(folder, name);    // e.g. /auth/signup

                JsonNode schemaNode = objectMapper.readTree(resource.getInputStream());
                JsonSchema jsonSchema = schemaFactory.getSchema(schemaNode);

                Map<String, Map<String, JsonSchema>> target =
                        isResponseSchema ? responseSchemas : requestSchemas;

                target.computeIfAbsent(apiPath, p -> new ConcurrentHashMap<>())
                        .put(version, jsonSchema);

                log.info("Loaded {} schema '{}' → path='{}', version='{}'",
                        isResponseSchema ? "RESPONSE" : "REQUEST",
                        filename, apiPath, version);
            }

            log.info("Schema registry loaded: {} request paths, {} response paths",
                    requestSchemas.size(), responseSchemas.size());

        } catch (Exception ex) {
            log.error("Failed loading JSON schema registry", ex);
        }
    }

    /**
     * Converts /schema/<folder>/... to the folder name.
     * Example: schema/auth/signup-v1.json → "auth".
     */
    private String resolveFolderName(Resource resource) {
        try {
            String url = resource.getURL().toString();
            // .../schema/auth/signup-v1.json → auth/signup-v1.json → auth
            String afterSchema = url.replaceAll(".*?/schema/", "");
            return afterSchema.replaceAll("/.*", "");
        } catch (IOException e) {
            log.warn("Unable to determine folder name for resource {}", resource, e);
            return null;
        }
    }

    /**
     * Map folder and name to external gateway path.
     * These MUST align with your Spring Cloud Gateway routes (before rewrite).
     *
     *   folder=auth, name=signup  → /auth/signup
     *   folder=user, name=update  → /user/update
     *   folder=payment, name=pay  → /payment/pay
     */
    private String deriveApiPath(String folder, String name) {
        return "/" + folder + "/" + name;
    }

    // === Public lookup methods used by filters ===

    public JsonSchema findRequestSchema(String path, String version) {
        return findSchema(requestSchemas, path, version);
    }

    public JsonSchema findResponseSchema(String path, String version) {
        return findSchema(responseSchemas, path, version);
    }

    private JsonSchema findSchema(Map<String, Map<String, JsonSchema>> source,
                                  String path,
                                  String version) {

        Map<String, JsonSchema> byVersion = source.get(path);
        if (byVersion == null || byVersion.isEmpty()) {
            return null;
        }

        if (version != null && byVersion.containsKey(version)) {
            return byVersion.get(version);
        }

        // Fallback: default-version
        if (byVersion.containsKey(defaultVersion)) {
            return byVersion.get(defaultVersion);
        }

        // Fallback: any single version (stable behavior)
        if (byVersion.size() == 1) {
            return byVersion.values().iterator().next();
        }

        log.warn("No schema found for path='{}', version='{}' (available versions: {})",
                path, version, byVersion.keySet());
        return null;
    }

    /**
     * Optional: reload when Spring Cloud detects config changes (Consul/GitOps).
     * Spring Cloud Consul/Config usually publishes EnvironmentChangeEvent.
     */
    @EventListener(EnvironmentChangeEvent.class)
    public void onEnvironmentChange(EnvironmentChangeEvent event) {
        if (!reloadOnConfigChange) {
            return;
        }

        boolean related = event.getKeys().stream().anyMatch(k ->
                k.startsWith("schema.") || k.contains("schema/"));

        if (related) {
            log.info("EnvironmentChangeEvent detected for schema.* – reloading JSON schema registry");
            loadSchemas();
        }
    }
}
