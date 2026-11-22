package dev.ivar;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

/** The decision core, local sensor, action sink and intent tokens. */
public final class Ivar {
    private Ivar() {}

    public static long now() {
        return System.currentTimeMillis();
    }

    public static JsonNode defaultPolicy(IvarRuntime rt) {
        return rt.call("policy.default", Map.of("now_ms", now()), 0);
    }

    /** Verified PolicyContent; rollback and expired bundles are refused. */
    public static JsonNode verifyPolicyBundle(IvarRuntime rt, String archiveBase64, JsonNode keyring, long currentVersion) {
        return rt.call("policy.verify", Map.of("archive_base64", archiveBase64, "keyring", keyring, "current_version", currentVersion, "now_ms", now()), 0);
    }

    abstract static class Handle implements AutoCloseable {
        final IvarRuntime rt;
        final long handle;

        Handle(IvarRuntime rt, String op, Object args) {
            this.rt = rt;
            this.handle = rt.call(op, args, 0).get("handle").asLong();
        }

        @Override
        public void close() {
            rt.call("free", Map.of(), handle);
        }
    }

    /** The full core, embedded. Use it off the request path. */
    public static final class Core extends Handle {
        public Core(IvarRuntime rt, JsonNode policy, String redactionKeyHex) {
            super(rt, "core.new", Map.of("policy", policy, "redaction_key_hex", redactionKeyHex));
        }

        public JsonNode process(Object event, long now) {
            return rt.call("core.process", Map.of("event", event, "now_ms", now), handle);
        }

        public JsonNode evidence() {
            return rt.call("core.evidence", Map.of(), handle);
        }

        /** Apply a newer verified policy. */
        public void updatePolicy(JsonNode policy, long now) {
            rt.call("core.update_policy", Map.of("policy", policy, "now_ms", now), handle);
        }
    }

    /** Known attacks are blocked here with no round trip (section 7.1). */
    public static final class LocalSensor extends Handle {
        public LocalSensor(IvarRuntime rt, JsonNode policy) {
            super(rt, "sensor.new", Map.of("policy", policy));
        }

        public JsonNode decide(Object event, long now) {
            return rt.call("sensor.decide", Map.of("event", event, "now_ms", now), handle);
        }

        /** Adopt a newer verified policy, keeping cached verdicts. */
        public void updatePolicy(JsonNode policy) {
            rt.call("sensor.update_policy", Map.of("policy", policy), handle);
        }

        public void pushVerdict(JsonNode verdict) {
            rt.call("sensor.push_verdict", Map.of("verdict", verdict), handle);
        }
    }

    /** The action sink: intent binding, consequence invariants and time locks. */
    public static final class Sink extends Handle {
        public Sink(IvarRuntime rt, String rootPublicKey, Map<String, String> stepKeys, JsonNode invariants, String defaultMode, Map<String, String> modes) {
            super(rt, "sink.new", Map.of("root_public_key", rootPublicKey, "step_keys", stepKeys, "invariants", invariants, "default_mode", defaultMode, "modes", modes));
        }

        public JsonNode guard(Object request, long now) {
            return rt.call("sink.guard", Map.of("request", request, "now_ms", now), handle);
        }
    }

    public static JsonNode mintIntent(IvarRuntime rt, String rootSeedHex, String intentId, String action, String subject, Map<String, Long> limits, long ttlMs) {
        return rt.call("intent.mint", Map.of("root_seed_hex", rootSeedHex, "intent_id", intentId, "action", action, "subject", subject, "limits", limits, "expiry_ms", now() + ttlMs), 0);
    }

    public static String attestStep(IvarRuntime rt, String stepSeedHex, String step, String token, String rootPublicKey) {
        return rt.call("intent.attest", Map.of("step_seed_hex", stepSeedHex, "step", step, "token", token, "root_public_key", rootPublicKey, "narrowing", Map.of()), 0).get("token").asText();
    }

    public static String stepPublicKey(IvarRuntime rt, String stepSeedHex) {
        return rt.call("intent.step_public_key", Map.of("step_seed_hex", stepSeedHex), 0).get("public_key").asText();
    }
}
