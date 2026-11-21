package dev.ivar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;
import java.util.function.Function;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Servlet filter for Spring Boot and Jakarta EE. Observe mode records
 * decisions without affecting a request; enforce mode blocks known attacks
 * in the filter and applies core verdicts to later requests. Scoring runs on
 * a worker thread. Faults fail open on public routes and closed on admin routes.
 */
public final class IvarFilter implements Filter {
    public static final String INTENT_HEADER = "Ivar-Intent";

    public static final class Options {
        public String mode = "observe";
        public Function<HttpServletRequest, String> identity = r -> r.getRemoteUser();
        public Function<HttpServletRequest, String> session = r -> null;
        public Function<HttpServletRequest, List<String>> roles = r -> List.of();
        public String coreUrl;
        public JsonNode policy;
        public String redactionKey = "";
        public String sensorId = "java-sdk";
        public List<String> adminPrefixes = List.of("/admin");
        public long budgetNanos = 1_000_000;
        public BiConsumer<String, String> onAlert = (k, m) -> System.err.println("[ivar] " + k + ": " + m);
    }

    final Options opts;
    final IvarRuntime rt;
    final JsonNode policy;
    final Ivar.LocalSensor sensor;
    final Ivar.Core core;
    private final BlockingQueue<JsonNode> queue = new ArrayBlockingQueue<>(10_000);
    private final AtomicLong seq = new AtomicLong();
    // Events submitted but not yet scored, counting the one the worker holds.
    private final AtomicLong pending = new AtomicLong();
    private final Thread worker;
    private final HttpClient http = HttpClient.newHttpClient();

    public IvarFilter(Options opts) {
        if (!opts.mode.equals("observe") && !opts.mode.equals("enforce")) throw new IllegalArgumentException("mode must be observe or enforce");
        this.opts = opts;
        this.rt = IvarRuntime.shared();
        this.policy = opts.policy != null ? opts.policy : Ivar.defaultPolicy(rt);
        this.sensor = new Ivar.LocalSensor(rt, policy);
        this.core = opts.coreUrl == null ? new Ivar.Core(rt, policy, opts.redactionKey.isEmpty() ? "00" : opts.redactionKey) : null;
        // Warm the compiled WebAssembly code so steady state latency applies
        // from the first real request.
        ObjectNode warm = IvarRuntime.JSON.createObjectNode();
        warm.put("activity_name", "http.request").putObject("http_request").put("http_method", "GET").put("url_path", "/");
        warm.putObject("ivar");
        for (int i = 0; i < 500; i++) sensor.decide(warm, Ivar.now());
        this.worker = new Thread(this::drain, "ivar-scoring");
        worker.setDaemon(true);
        worker.start();
    }

    /** Matches ivar_core::redact::keyed_hash. */
    public static String keyedHash(String keyHex, String value) {
        if (value == null || value.isEmpty() || value.startsWith("kh_") || keyHex == null || keyHex.isEmpty()) return value == null ? "" : value;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(java.util.HexFormat.of().parseHex(keyHex), "HmacSHA256"));
            return "kh_" + java.util.HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8))).substring(0, 24);
        } catch (Exception e) {
            return value;
        }
    }

    ObjectNode event(HttpServletRequest r, String activity, int classUid, int status) {
        ObjectNode ev = IvarRuntime.JSON.createObjectNode();
        ev.put("class_uid", classUid).put("category_uid", classUid / 1000).put("activity_id", 1).put("time", Ivar.now()).put("status_id", 1).put("activity_name", activity);
        ObjectNode actor = ev.putObject("actor");
        String id = opts.identity.apply(r);
        if (id != null && !id.isEmpty()) actor.putObject("user").put("uid", keyedHash(opts.redactionKey, id)).put("type", "human");
        String s = opts.session.apply(r);
        if (s != null && !s.isEmpty()) actor.putObject("session").put("uid", s);
        actor.put("authorizations", String.join(",", opts.roles.apply(r)));
        ev.putObject("src_endpoint").put("ip", r.getRemoteAddr());
        ev.putObject("http_request").put("http_method", r.getMethod()).put("url_path", r.getRequestURI()).put("user_agent", String.valueOf(r.getHeader("User-Agent")));
        if (status != 0) ev.putObject("http_response").put("code", status);
        ObjectNode x = ev.putObject("ivar");
        x.put("sensor_id", opts.sensorId).put("sensor_type", "app_sdk").put("observation_point", "app_sdk").put("sensor_seq", seq.incrementAndGet());
        String rid = r.getHeader("X-Request-Id");
        if (rid != null) x.put("request_id", rid);
        return ev;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        boolean admin = opts.adminPrefixes.stream().anyMatch(p -> req.getRequestURI().startsWith(p));
        long started = System.nanoTime();
        JsonNode local;
        try {
            local = sensor.decide(event(req, "http.request", 4002, 0), Ivar.now());
        } catch (RuntimeException e) {
            if (admin) {
                opts.onAlert.accept("sdk_fault", "admin route failed closed: " + e.getMessage());
                json(res, 503, "{\"error\":\"security check unavailable\"}");
                return;
            }
            opts.onAlert.accept("fail_open", String.valueOf(e.getMessage()));
            chain.doFilter(request, response);
            return;
        }
        long elapsed = System.nanoTime() - started;
        if (elapsed > opts.budgetNanos) opts.onAlert.accept("budget_exceeded", "local decision took " + elapsed / 1000 + " us");
        JsonNode v = local.get("verdict");
        if (v != null && !v.isNull() && opts.mode.equals("enforce") && "enforce".equals(v.path("mode").asText())) {
            String d = v.get("decision").asText();
            String id = v.get("verdict_id").asText();
            switch (d) {
                case "block", "contain", "refuse" -> {
                    json(res, 403, "{\"error\":\"request blocked\",\"verdict_id\":\"" + id + "\"}");
                    submit(event(req, "http.request", 4002, 403));
                    return;
                }
                case "challenge" -> {
                    res.setHeader("WWW-Authenticate", "step-up");
                    json(res, 401, "{\"error\":\"step up verification required\",\"verdict_id\":\"" + id + "\"}");
                    submit(event(req, "http.request", 4002, 401));
                    return;
                }
                case "throttle" -> {
                    json(res, 429, "{\"error\":\"slow down\",\"verdict_id\":\"" + id + "\"}");
                    submit(event(req, "http.request", 4002, 429));
                    return;
                }
                default -> {}
            }
        }
        try {
            chain.doFilter(request, response);
        } finally {
            submit(event(req, "http.request", 4002, res.getStatus()));
        }
    }

    static void json(HttpServletResponse res, int code, String body) throws IOException {
        res.setStatus(code);
        res.setContentType("application/json");
        res.getWriter().write(body);
    }

    void submit(JsonNode ev) {
        pending.incrementAndGet();
        if (!queue.offer(ev)) {
            pending.decrementAndGet();
            opts.onAlert.accept("fail_open", "event buffer full");
        }
    }

    private void drain() {
        while (true) {
            JsonNode ev;
            try {
                ev = queue.take();
            } catch (InterruptedException e) {
                return;
            }
            try {
                JsonNode verdicts;
                if (core != null) {
                    verdicts = core.process(ev, Ivar.now()).get("verdicts");
                } else {
                    String body = IvarRuntime.JSON.writeValueAsString(Map.of("sensor_id", opts.sensorId, "events", List.of(ev)));
                    var resp = http.send(HttpRequest.newBuilder(URI.create(opts.coreUrl.replaceAll("/$", "") + "/v1/events")).header("content-type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
                    verdicts = IvarRuntime.JSON.readTree(resp.body()).get("verdicts");
                }
                if (verdicts != null) verdicts.forEach(sensor::pushVerdict);
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                opts.onAlert.accept("sdk_fault", String.valueOf(e.getMessage()));
            } finally {
                pending.decrementAndGet();
            }
        }
    }

    /** Wait until every submitted event was scored and its verdicts applied. */
    public void flush(long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (pending.get() > 0 && System.currentTimeMillis() < deadline) TimeUnit.MILLISECONDS.sleep(5);
    }

    /** Action sink for one high consequence action. */
    public ActionGuard guard(String action, String rootPublicKey, Map<String, String> stepKeys, String intentBinding) {
        Map<String, String> modes = new java.util.HashMap<>();
        policy.path("intent_binding").fields().forEachRemaining(e -> modes.put(e.getKey(), e.getValue().asText()));
        if (intentBinding != null) modes.put(action, intentBinding);
        return new ActionGuard(this, action, new Ivar.Sink(rt, rootPublicKey, stepKeys, policy.path("invariants"), modes.getOrDefault(action, "observe"), modes));
    }
}
