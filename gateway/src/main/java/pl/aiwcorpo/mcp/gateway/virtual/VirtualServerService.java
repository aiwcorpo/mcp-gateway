package pl.aiwcorpo.mcp.gateway.virtual;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;

import pl.aiwcorpo.mcp.gateway.admin.AdminException;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.JsonNode;

/**
 * CRUD of links (C5). A link only narrows (invariant 5): creation refuses every tool the creator may not call,
 * and each MCP call repeats the check with the caller's rights, so a link never keeps a lost permission.
 */
public class VirtualServerService {

    private static final Set<String> CREATE_FIELDS = Set.of("slug", "displayName", "tools", "resourceDefaults");
    private static final Pattern QUALIFIED_TOOL = Pattern.compile(
            "^(?:jira|confluence|gitlab|servicedesk|opensearch)__[a-z][a-z0-9]*(?:_[a-z0-9]+)*$");
    /* Controls and format characters (bidi, zero width) must not reach the portal list or the audit log. */
    private static final Pattern UNSAFE_TEXT = Pattern.compile("[\\p{Cc}\\p{Cf}\\u2028\\u2029]");
    private static final int MAX_TOOLS = 100;

    public record Create(String slug, String displayName, List<String> tools) {
    }

    private final VirtualServerStore store;
    private final ServerRegistry registry;
    private final ToolAuthorizer authorizer;

    private final int maxPerUser;

    public VirtualServerService(VirtualServerStore store, ServerRegistry registry, ToolAuthorizer authorizer, int maxPerUser) {
        this.maxPerUser = maxPerUser;
        this.store = store;
        this.registry = registry;
        this.authorizer = authorizer;
    }

    /**
     * Validates the request body. Order (mcp-contracts README 2.2.1, CC-085): a non-object
     * {@code resourceDefaults} is invalid_request, a non-empty one resource_defaults_unsupported, both before
     * anything else is looked at.
     */
    public Create parse(JsonNode body) {
        if (body == null || !body.isObject()) {
            throw new AdminException(HttpStatus.BAD_REQUEST, "invalid_request");
        }
        if (body.has("resourceDefaults")) {
            JsonNode defaults = body.get("resourceDefaults");
            if (!defaults.isObject()) {
                throw new AdminException(HttpStatus.BAD_REQUEST, "invalid_request");
            }
            if (!defaults.isEmpty()) {
                throw new AdminException(HttpStatus.BAD_REQUEST, "resource_defaults_unsupported");
            }
        }
        for (String name : body.propertyNames()) {
            if (!CREATE_FIELDS.contains(name)) {
                throw new AdminException(HttpStatus.BAD_REQUEST, "invalid_request");
            }
        }
        String slug = text(body.get("slug"));
        String displayName = text(body.get("displayName"));
        JsonNode toolsNode = body.get("tools");
        if (!VirtualServer.validSlug(slug) || displayName == null || displayName.isEmpty()
                || displayName.codePointCount(0, displayName.length()) > 100 || UNSAFE_TEXT.matcher(displayName).find()
                || toolsNode == null || !toolsNode.isArray() || toolsNode.isEmpty() || toolsNode.size() > MAX_TOOLS) {
            throw new AdminException(HttpStatus.BAD_REQUEST, "invalid_request");
        }
        Set<String> tools = new LinkedHashSet<>();
        for (JsonNode tool : toolsNode) {
            String name = text(tool);
            if (name == null || name.length() > 80 || !QUALIFIED_TOOL.matcher(name).matches() || !tools.add(name)) {
                throw new AdminException(HttpStatus.BAD_REQUEST, "invalid_request");
            }
        }
        return new Create(slug, displayName, List.copyOf(tools));
    }

    /** Creates the link; 403 access_denied when any tool is unknown, disabled or not granted to the creator; 400 at the per-user limit. */
    public VirtualServer create(GatewayUser owner, Create request) {
        for (String name : request.tools()) {
            boolean allowed = registry.resolve(name)
                    .map(resolved -> authorizer.decide(owner, resolved.server(), resolved.tool()).allowed())
                    .orElse(false);
            if (!allowed) {
                throw new AdminException(HttpStatus.FORBIDDEN, "access_denied", "not_granted");
            }
        }
        VirtualServer server = new VirtualServer(request.slug(), owner.sub(), request.displayName(), request.tools(),
                Instant.now());
        switch (store.insert(server, maxPerUser)) {
            case SLUG_TAKEN -> throw new AdminException(HttpStatus.CONFLICT, "slug_taken");
            // C5 has no code for this; invalid_request is the nearest one it defines (proposal CC in STATUS.md).
            case LIMIT_REACHED -> throw new AdminException(HttpStatus.BAD_REQUEST, "invalid_request", "virtual_server_limit");
            case CREATED -> {
            }
        }
        return server;
    }

    public List<VirtualServer> list(GatewayUser owner) {
        return new ArrayList<>(store.listByOwner(owner.sub()));
    }

    /** Owner only; a foreign or unknown slug is 404 (invariant 8). */
    public void delete(GatewayUser owner, String slug) {
        if (!VirtualServer.validSlug(slug) || !store.delete(slug, owner.sub())) {
            throw new AdminException(HttpStatus.NOT_FOUND, "not_found_or_denied");
        }
    }

    /** The link a caller may use: only the owner's, otherwise empty (indistinguishable from a missing slug). */
    public Optional<VirtualServer> usableBy(GatewayUser user, String slug) {
        if (!VirtualServer.validSlug(slug)) {
            return Optional.empty();
        }
        return store.find(slug).filter(link -> link.ownerSub().equals(user.sub()));
    }

    private static String text(JsonNode node) {
        return node != null && node.isString() ? node.asString() : null;
    }
}
