package dev.ivar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Guards one high consequence action. Fails closed. */
public final class ActionGuard {
    private final IvarFilter filter;
    private final String action;
    private final Ivar.Sink sink;

    ActionGuard(IvarFilter filter, String action, Ivar.Sink sink) {
        this.filter = filter;
        this.action = action;
        this.sink = sink;
    }

    /** Returns true when the action may run; otherwise the response was written. */
    public boolean check(HttpServletRequest req, HttpServletResponse res, double value, double records, boolean destructive) throws IOException {
        String identity = filter.opts.identity.apply(req);
        String session = filter.opts.session.apply(req);
        ObjectNode r = IvarRuntime.JSON.createObjectNode();
        r.put("action", action).put("subject", session != null && !session.isEmpty() ? session : identity).put("identity", identity == null ? "" : identity)
                .put("business", "").put("value_moved", value).put("records_read", records).put("destructive", destructive);
        String token = req.getHeader(IvarFilter.INTENT_HEADER);
        if (token != null) r.put("intent_token", token);
        JsonNode d;
        try {
            d = sink.guard(r, Ivar.now());
        } catch (RuntimeException e) {
            filter.opts.onAlert.accept("sdk_fault", "action sink failed closed: " + e.getMessage());
            IvarFilter.json(res, 503, "{\"error\":\"action check unavailable\"}");
            return false;
        }
        JsonNode o = d.get("outcome");
        ObjectNode ev = filter.event(req, "business.action", 6003, 0);
        ((ObjectNode) ev.get("ivar")).put("business_action", action).put("value_moved", value).putObject("attributes").put("sink_outcome", o.get("outcome").asText());
        filter.submit(ev);
        switch (o.get("outcome").asText()) {
            case "executes":
                if (d.hasNonNull("would_refuse")) filter.opts.onAlert.accept("action_refused", "observe: would refuse " + action + ": " + d.get("would_refuse").asText());
                return true;
            case "refused":
                filter.opts.onAlert.accept("action_refused", o.get("reason").asText());
                IvarFilter.json(res, 403, "{\"error\":\"no valid intent chain for this action\"}");
                return false;
            case "blocked_alert":
                filter.opts.onAlert.accept("invariant_breach", o.get("invariant_id").asText());
                IvarFilter.json(res, 409, "{\"error\":\"consequence limit reached\"}");
                return false;
            default:
                filter.opts.onAlert.accept("time_lock", o.get("lock").get("lock_id").asText());
                IvarFilter.json(res, 202, "{\"status\":\"held\",\"lock_id\":\"" + o.get("lock").get("lock_id").asText() + "\"}");
                return false;
        }
    }
}
