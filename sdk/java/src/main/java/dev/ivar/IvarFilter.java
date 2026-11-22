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
        /** The sensor token the core issued for sensorId. */
        public String coreToken;
        public JsonNode policy;
        public String redactionKey = "";
        public String sensorId = "java-sdk";
        public List<String> adminPrefixes = List.of("/admin");
        public long budgetNanos = 1_000_000;
        public BiConsumer<String, String> onAlert = (k, m) -> System.err.println("[ivar] " + k + ": " + m);
        /** Control plane to poll for newer signed policy, applied while the app runs. Needs policyKeyring. */
        public String controlUrl;
        /** Verifies policy from the control plane or the state file. */
        public JsonNode policyKeyring;
        public long policyRefreshMillis = 30_000;
        /** Keeps the last verified policy, so a restart during a control plane outage resumes at it. */
        public String policyStateFile;
    }

    final Options opts;
    final IvarRuntime rt;
    private volatile JsonNode policy;
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
        if (opts.controlUrl != null || opts.policyStateFile != null) {
            if (opts.policyKeyring == null) throw new IllegalArgumentException("policyKeyring is required with controlUrl or policyStateFile");
            if (opts.policyStateFile != null) {
                try {
                    String saved = java.nio.file.Files.readString(java.nio.file.Path.of(opts.policyStateFile)).trim();
                    if (!saved.isEmpty()) applyPolicy(saved, "state_file");
                } catch (IOException e) {
                    // No saved policy yet.
                }
            }
            if (opts.controlUrl != null) {
                var refresher = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "ivar-policy");
                    t.setDaemon(true);
                    return t;
                });
                refresher.scheduleWithFixedDelay(this::refreshPolicy, 0, opts.policyRefreshMillis, TimeUnit.MILLISECONDS);
            }
        }
    }

    /** The verified PolicyContent in force. */
    public JsonNode policy() {
        return policy;
    }

    /**
     * Poll the control plane once; true when a newer policy was applied. An
     * unreachable control plane leaves the current policy in force.
     */
    public boolean refreshPolicy() {
        try {
            String url = opts.controlUrl.replaceAll("/$", "") + "/v1/policy/bundle?have=" + policy.path("version").asLong()
                + "&sensor=" + java.net.URLEncoder.encode(opts.sensorId, StandardCharsets.UTF_8);
            var res = http.send(HttpRequest.newBuilder(URI.create(url)).timeout(java.time.Duration.ofSeconds(5)).GET().build(), java.net.http.HttpResponse.BodyHandlers.ofString());
            return res.statusCode() == 200 && applyPolicy(res.body(), "control_plane");
        } catch (Exception e) {
            return false;
        }
    }

    /** Verify a signed bundle and adopt it when newer; anything else changes nothing. */
    synchronized boolean applyPolicy(String archive, String source) {
        long have = policy.path("version").asLong();
        JsonNode next;
        try {
            next = Ivar.verifyPolicyBundle(rt, archive.trim(), opts.policyKeyring, have);
        } catch (RuntimeException e) {
            opts.onAlert.accept("policy_rejected", "signed policy from " + source + " refused, current policy kept: " + e.getMessage());
            return false;
        }
        long version = next.path("version").asLong();
        if (version <= have) return false;
        try {
            sensor.updatePolicy(next);
            if (core != null) core.updatePolicy(next, Ivar.now());
        } catch (RuntimeException e) {
            opts.onAlert.accept("policy_rejected", "policy " + version + " refused by the engine, current policy kept: " + e.getMessage());
            return false;
        }
        policy = next;
        if (opts.policyStateFile != null) {
            try {
                var target = java.nio.file.Path.of(opts.policyStateFile);
                var tmp = java.nio.file.Path.of(opts.policyStateFile + ".tmp");
                java.nio.file.Files.writeString(tmp, archive.trim());
                java.nio.file.Files.move(tmp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException e) {
                opts.onAlert.accept("policy_state", "policy " + version + " applied but not saved: " + e.getMessage());
            }
        }
        opts.onAlert.accept("policy_applied", "policy " + version + " applied from " + source);
        return true;
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
        ObjectNode http = ev.putObject("http_request").put("http_method", r.getMethod()).put("url_path", r.getRequestURI()).put("user_agent", String.valueOf(r.getHeader("User-Agent")));
        BodyKeys.of(r).forEach(http.putArray("body_keys")::add);
        if (status != 0) ev.putObject("http_response").put("code", status);
        ObjectNode x = ev.putObject("ivar");
        x.put("sensor_id", opts.sensorId).put("sensor_type", "app_sdk").put("observation_point", "app_sdk").put("sensor_seq", seq.incrementAndGet());
        String rid = r.getHeader("X-Request-Id");
        if (rid != null) x.put("request_id", rid);
        return ev;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = BodyKeys.read((HttpServletRequest) request);
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
            chain.doFilter(req, response);
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
            chain.doFilter(req, response);
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
        boolean failing = false;
        while (true) {
            List<JsonNode> batch = new java.util.ArrayList<>();
            try {
                batch.add(queue.take());
            } catch (InterruptedException e) {
                return;
            }
            // Everything queued so far goes in one request, up to 500 events.
            queue.drainTo(batch, 499);
            try {
                if (core != null) {
                    for (JsonNode ev : batch) {
                        JsonNode verdicts = core.process(ev, Ivar.now()).get("verdicts");
                        if (verdicts != null) verdicts.forEach(sensor::pushVerdict);
                    }
                } else {
                    String body = IvarRuntime.JSON.writeValueAsString(Map.of("sensor_id", opts.sensorId, "events", batch));
                    var req = HttpRequest.newBuilder(URI.create(opts.coreUrl.replaceAll("/$", "") + "/v1/events")).timeout(java.time.Duration.ofSeconds(2)).header("content-type", "application/json");
                    if (opts.coreToken != null && !opts.coreToken.isEmpty()) req.header("authorization", "Bearer " + opts.coreToken);
                    var resp = http.send(req.POST(HttpRequest.BodyPublishers.ofString(body)).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
                    if (resp.statusCode() != 200) {
                        if (!failing) {
                            boolean refused = resp.statusCode() == 401 || resp.statusCode() == 403;
                            opts.onAlert.accept("sdk_fault", refused ? "the core refused this sensor's token (HTTP " + resp.statusCode() + "): check coreToken and the sensor id it is issued for" : "the core answered HTTP " + resp.statusCode());
                        }
                        failing = true;
                    } else {
                        failing = false;
                        JsonNode verdicts = IvarRuntime.JSON.readTree(resp.body()).get("verdicts");
                        if (verdicts != null) verdicts.forEach(sensor::pushVerdict);
                    }
                }
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                if (!failing) opts.onAlert.accept("sdk_fault", "the core is unreachable, events are not scored until it returns: " + e.getMessage());
                failing = true;
            } finally {
                pending.addAndGet(-batch.size());
            }
        }
    }

    /** Report a login so credential spraying and account takeover are correlated. */
    public void reportLogin(HttpServletRequest req, boolean success, String account) {
        ObjectNode ev = event(req, "auth.login", 3002, 0);
        ev.put("status_id", success ? 1 : 2);
        ((ObjectNode) ev.get("ivar")).put("target_entity", "user:" + keyedHash(opts.redactionKey, account));
        submit(ev);
    }

    /** Report a business action such as a payout, a role change or an export. */
    public void reportAction(HttpServletRequest req, String name, double value, long records, boolean destructive) {
        ObjectNode ev = event(req, "business.action", 6003, 0);
        ((ObjectNode) ev.get("ivar")).put("business_action", name).put("value_moved", value).put("records_read", records).put("destructive", destructive);
        submit(ev);
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
