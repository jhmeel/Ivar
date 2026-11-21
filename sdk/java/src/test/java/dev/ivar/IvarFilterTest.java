package dev.ivar;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IvarFilterTest {
    static HttpServletRequest request(String method, String path, String ip, Map<String, String> headers) {
        return (HttpServletRequest) Proxy.newProxyInstance(IvarFilterTest.class.getClassLoader(), new Class<?>[] {HttpServletRequest.class}, (p, m, a) -> switch (m.getName()) {
            case "getMethod" -> method;
            case "getRequestURI" -> path;
            case "getRemoteAddr" -> ip;
            case "getHeader" -> headers.get((String) a[0]);
            default -> null;
        });
    }

    static final class Res {
        int status = 200;
        final StringWriter body = new StringWriter();
        final HttpServletResponse proxy = (HttpServletResponse) Proxy.newProxyInstance(IvarFilterTest.class.getClassLoader(), new Class<?>[] {HttpServletResponse.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "setStatus" -> status = (int) a[0];
                case "getStatus" -> { return status; }
                case "getWriter" -> { return new PrintWriter(body, true); }
                default -> {}
            }
            return null;
        });
    }

    static int run(IvarFilter f, String path, String ip) throws Exception {
        Res r = new Res();
        FilterChain ok = (q, s) -> {};
        f.doFilter(request("GET", path, ip, Map.of()), r.proxy, ok);
        return r.status;
    }

    static IvarFilter filter(String mode) {
        return filter(mode, null);
    }

    /** The spec default policy with DETECTION_MODE enforce. */
    static com.fasterxml.jackson.databind.JsonNode enforcePolicy() {
        com.fasterxml.jackson.databind.node.ObjectNode p = Ivar.defaultPolicy(IvarRuntime.shared()).deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) p.get("settings")).put("detection_mode", "enforce");
        return p;
    }

    static IvarFilter filter(String mode, com.fasterxml.jackson.databind.JsonNode policy) {
        IvarFilter.Options o = new IvarFilter.Options();
        o.mode = mode;
        o.policy = policy;
        o.identity = r -> "svc";
        o.session = r -> r.getHeader("X-Session");
        o.onAlert = (k, m) -> {};
        return new IvarFilter(o);
    }

    @Test
    void observeNeverAffectsRequests() throws Exception {
        assertEquals(200, run(filter("observe"), "/.env.backup", "203.0.113.4"));
    }

    @Test
    void signedObservePolicyNeverBlocks() throws Exception {
        assertEquals(200, run(filter("enforce"), "/.env.backup", "203.0.113.9"));
    }

    @Test
    void enforceBlocksDecoyThenContainsSource() throws Exception {
        IvarFilter f = filter("enforce", enforcePolicy());
        assertEquals(403, run(f, "/.env.backup", "203.0.113.5"));
        f.flush(3000);
        assertEquals(403, run(f, "/hello", "203.0.113.5"));
        assertEquals(200, run(f, "/hello", "198.51.100.8"));
    }

    @Test
    void payoutIntentChain() throws Exception {
        IvarFilter f = filter("enforce");
        IvarRuntime rt = IvarRuntime.shared();
        Map<String, String> seeds = new LinkedHashMap<>();
        seeds.put("authenticated_session", "22".repeat(32));
        seeds.put("ledger_entry", "33".repeat(32));
        seeds.put("payout_instruction", "44".repeat(32));
        Map<String, String> keys = new HashMap<>();
        seeds.forEach((k, s) -> keys.put(k, Ivar.stepPublicKey(rt, s)));
        java.util.function.BiFunction<String, Long, String[]> chain = (id, limit) -> {
            var m = Ivar.mintIntent(rt, "11".repeat(32), id, "payout", "ses_1", Map.of("amount", limit), 60_000);
            String t = m.get("token").asText();
            String root = m.get("root_public_key").asText();
            for (var e : seeds.entrySet()) t = Ivar.attestStep(rt, e.getValue(), e.getKey(), t, root);
            return new String[] {t, root};
        };
        String[] c1 = chain.apply("i1", 5000L);
        ActionGuard g = f.guard("payout", c1[1], keys, "enforce");
        java.util.function.BiFunction<String, Double, Integer> pay = (token, value) -> {
            Map<String, String> h = new HashMap<>(Map.of("X-Session", "ses_1"));
            if (token != null) h.put(IvarFilter.INTENT_HEADER, token);
            Res r = new Res();
            try {
                return g.check(request("POST", "/payouts", "10.0.0.1", h), r.proxy, value, 0, false) ? 200 : r.status;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
        assertEquals(403, pay.apply(null, 100.0));
        assertEquals(200, pay.apply(c1[0], 100.0));
        assertEquals(202, pay.apply(chain.apply("i2", 100_000L)[0], 60_000.0));
    }

    @Test
    void localDecisionLatency() throws Exception {
        IvarFilter f = filter("enforce");
        HttpServletRequest r = request("GET", "/x", "203.0.113.9", Map.of());
        long[] t = new long[1000];
        for (int i = 0; i < t.length; i++) {
            long s = System.nanoTime();
            f.sensor.decide(f.event(r, "http.request", 4002, 0), Ivar.now());
            t[i] = System.nanoTime() - s;
        }
        Arrays.sort(t);
        System.out.println("java local decision p99 " + t[990] / 1000 + " us");
        assertTrue(t[990] < 5_000_000);
    }
}
