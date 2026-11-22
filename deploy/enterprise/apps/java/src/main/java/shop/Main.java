// The test shop API in Java: Jetty 12 servlets behind the ivar-java filter.
package shop;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.ivar.ActionGuard;
import dev.ivar.Ivar;
import dev.ivar.IvarFilter;
import dev.ivar.IvarRuntime;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.ForwardedRequestCustomizer;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

public final class Main {
    static final ObjectMapper JSON = new ObjectMapper();
    record User(String id, String password, List<String> roles) {}
    static final Map<String, User> USERS = new ConcurrentHashMap<>();
    static final Map<String, User> SESSIONS = new ConcurrentHashMap<>();

    static String env(String k) { String v = System.getenv(k); return v == null ? "" : v; }
    static String h(String s) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))); }
    static User userOf(HttpServletRequest r) { String s = r.getHeader("X-Session"); return s == null ? null : SESSIONS.get(s); }
    static void reply(HttpServletResponse res, int code, Object body) throws IOException {
        res.setStatus(code);
        res.setContentType("application/json");
        res.getWriter().write(JSON.writeValueAsString(body));
    }

    public static void main(String[] args) throws Exception {
        for (int i = 1; i <= 200; i++) USERS.put("user" + i + "@corp.test", new User("u" + i, h("pw" + i), new ArrayList<>(List.of(i == 1 ? "admin" : "customer"))));
        Path dir = Path.of(env("IVAR_DIR"));
        IvarRuntime rt = IvarRuntime.shared();
        JsonNode policy = Ivar.verifyPolicyBundle(rt, Files.readString(dir.resolve("policy.bundle")), JSON.readTree(Files.readString(dir.resolve("keyring.json"))), 0);
        Map<String, String> steps = new LinkedHashMap<>();
        steps.put("authenticated_session", env("IVAR_STEP_SESSION"));
        steps.put("ledger_entry", env("IVAR_STEP_LEDGER"));
        steps.put("payout_instruction", env("IVAR_STEP_PAYOUT"));
        Map<String, String> stepKeys = new LinkedHashMap<>();
        steps.forEach((k, s) -> stepKeys.put(k, Ivar.stepPublicKey(rt, s)));
        String root = env("IVAR_ROOT_SEED");
        String rootPub = Ivar.mintIntent(rt, root, "boot", "payout", "boot", Map.of("amount", 1L), 60_000).get("root_public_key").asText();

        IvarFilter.Options o = new IvarFilter.Options();
        o.mode = env("IVAR_MODE").isEmpty() ? "enforce" : env("IVAR_MODE");
        o.identity = r -> { User u = userOf(r); return u == null ? null : u.id(); };
        o.session = r -> r.getHeader("X-Session");
        o.roles = r -> { User u = userOf(r); return u == null ? List.of() : u.roles(); };
        o.coreUrl = env("IVAR_CORE_URL");
        o.coreToken = env("IVAR_CORE_TOKEN");
        o.policy = policy;
        o.redactionKey = Files.readString(dir.resolve("keys/redaction.hex")).trim();
        o.sensorId = env("SENSOR_ID");
        o.onAlert = (k, m) -> System.out.println("{\"ivar_alert\":\"" + k + "\",\"message\":" + JSON.valueToTree(m) + "}");
        o.controlUrl = env("IVAR_CONTROL_URL").isEmpty() ? null : env("IVAR_CONTROL_URL");
        o.policyKeyring = JSON.readTree(Files.readString(dir.resolve("keyring.json")));
        o.policyRefreshMillis = 2_000;
        o.policyStateFile = dir.resolve("policy.state").toString();
        IvarFilter ivar = new IvarFilter(o);
        ActionGuard payoutGuard = ivar.guard("payout", rootPub, stepKeys, null);
        SecureRandom random = new SecureRandom();

        ServletContextHandler ctx = new ServletContextHandler();
        ctx.addFilter(new FilterHolder(ivar), "/*", EnumSet.of(DispatcherType.REQUEST));
        ctx.addServlet(new ServletHolder(new HttpServlet() {
            @Override protected void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
                try {
                    route(req, res);
                } catch (IOException e) {
                    throw e;
                } catch (Exception e) {
                    reply(res, 500, Map.of("error", String.valueOf(e.getMessage())));
                }
            }

            void route(HttpServletRequest req, HttpServletResponse res) throws Exception {
                String path = req.getRequestURI();
                String method = req.getMethod();
                if (path.equals("/healthz")) { res.getWriter().write("ok"); return; }
                if (method.equals("POST") && path.equals("/login")) {
                    JsonNode b = JSON.readTree(req.getInputStream());
                    User u = USERS.get(b.path("email").asText());
                    boolean ok = u != null && u.password().equals(h(b.path("password").asText()));
                    ivar.reportLogin(req, ok, b.path("email").asText());
                    if (!ok) { reply(res, 401, Map.of("error", "invalid credentials")); return; }
                    byte[] sid = new byte[12];
                    random.nextBytes(sid);
                    String session = "ses_" + HexFormat.of().formatHex(sid);
                    SESSIONS.put(session, u);
                    reply(res, 200, Map.of("session", session));
                    return;
                }
                User u = userOf(req);
                if (u == null) { reply(res, 401, Map.of("error", "login required")); return; }
                if (method.equals("GET") && path.startsWith("/accounts/")) {
                    if (!path.substring(10).equals(u.id())) { reply(res, 403, Map.of("error", "not your account")); return; }
                    reply(res, 200, Map.of("id", u.id(), "balance", 100000));
                } else if (method.equals("PATCH") && path.startsWith("/users/")) {
                    JsonNode b = JSON.readTree(req.getInputStream());
                    if (b.hasNonNull("role")) u.roles().add(b.get("role").asText());
                    reply(res, 200, Map.of("id", u.id(), "roles", u.roles()));
                } else if (method.equals("POST") && path.equals("/payouts/intent")) {
                    long amount = JSON.readTree(req.getInputStream()).path("amount").asLong();
                    String t = Ivar.mintIntent(rt, root, "int_" + Long.toHexString(random.nextLong()), "payout", req.getHeader("X-Session"), Map.of("amount", amount), 300_000).get("token").asText();
                    for (var e : steps.entrySet()) t = Ivar.attestStep(rt, e.getValue(), e.getKey(), t, rootPub);
                    reply(res, 200, Map.of("intent", t, "header", IvarFilter.INTENT_HEADER));
                } else if (method.equals("POST") && path.equals("/payouts")) {
                    double amount = JSON.readTree(req.getInputStream()).path("amount").asDouble();
                    if (!payoutGuard.check(req, res, amount, 0, false)) return;
                    reply(res, 200, Map.of("sent", true));
                } else if (method.equals("GET") && path.equals("/admin/users")) {
                    if (!u.roles().contains("admin")) { reply(res, 403, Map.of("error", "admins only")); return; }
                    reply(res, 200, Map.of("users", USERS.size()));
                } else {
                    reply(res, 404, Map.of("error", "not found"));
                }
            }
        }), "/*");

        Server server = new Server();
        HttpConfiguration http = new HttpConfiguration();
        // The gateway is the only peer: its X-Forwarded-For names the client.
        http.addCustomizer(new ForwardedRequestCustomizer());
        ServerConnector connector = new ServerConnector(server, new HttpConnectionFactory(http));
        connector.setHost("127.0.0.1");
        connector.setPort(Integer.parseInt(env("PORT")));
        server.addConnector(connector);
        server.setHandler(ctx);
        server.start();
        server.join();
    }
}
