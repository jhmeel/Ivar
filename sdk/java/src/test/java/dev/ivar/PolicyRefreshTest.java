package dev.ivar;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** A newer signed policy applies live; a forged one is refused; a restart resumes at the saved one. */
class PolicyRefreshTest {
    static String fixture(String name) throws Exception {
        return Files.readString(Path.of("..", "testdata", "policy", name)).trim();
    }

    static int decoy(IvarFilter f) throws Exception {
        IvarFilterTest.Res r = new IvarFilterTest.Res();
        f.doFilter(IvarFilterTest.request("GET", "/v2-decoy", "198.51.100.4", Map.of()), r.proxy, (q, s) -> {});
        return r.status;
    }

    @Test
    void newerSignedPolicyAppliesLiveAndForgedIsRefused() throws Exception {
        JsonNode keyring = IvarRuntime.JSON.readTree(fixture("keyring.json"));
        JsonNode v1 = Ivar.verifyPolicyBundle(IvarRuntime.shared(), fixture("v1.bundle"), keyring, 0);
        AtomicReference<String> serve = new AtomicReference<>("v2.bundle");
        HttpServer cp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        cp.createContext("/", ex -> {
            byte[] body;
            try {
                body = fixture(serve.get()).getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                body = new byte[0];
            }
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        cp.start();
        try {
            assertNotEquals(403, decoy(IvarFilterTest.filter("enforce", v1)), "v1 has no such decoy");
            List<String> alerts = new ArrayList<>();
            Path state = Files.createTempDirectory("ivar").resolve("policy.state");
            IvarFilter.Options o = new IvarFilter.Options();
            o.mode = "enforce";
            o.policy = v1;
            o.controlUrl = "http://127.0.0.1:" + cp.getAddress().getPort();
            o.policyKeyring = keyring;
            o.policyRefreshMillis = 3_600_000;
            o.policyStateFile = state.toString();
            o.onAlert = (k, m) -> { synchronized (alerts) { alerts.add(k); } };
            IvarFilter f = new IvarFilter(o);
            f.refreshPolicy();
            assertEquals(2, f.policy().path("version").asLong());
            assertEquals(403, decoy(f), "the decoy route added in v2 is enforced");
            serve.set("forged-v3.bundle");
            assertFalse(f.refreshPolicy());
            assertEquals(2, f.policy().path("version").asLong(), "a forged bundle changes nothing");
            synchronized (alerts) { assertTrue(alerts.contains("policy_rejected")); }

            IvarFilter.Options r = new IvarFilter.Options();
            r.mode = "enforce";
            r.policy = v1;
            r.policyKeyring = keyring;
            r.policyStateFile = state.toString();
            r.onAlert = (k, m) -> {};
            assertEquals(2, new IvarFilter(r).policy().path("version").asLong(), "a restart resumes at the saved policy");
        } finally {
            cp.stop(0);
        }
    }
}
