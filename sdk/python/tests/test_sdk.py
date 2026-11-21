import asyncio
import json
import time
import unittest

from ivar import Guardian, RequestInfo, attest_step, mint_intent, step_public_key
from ivar.asgi import IvarMiddleware
from ivar.core import default_policy


def enforce_policy(**settings):
    """The spec default policy with DETECTION_MODE enforce, as a deployment
    has after the observe phase exit test passes."""
    p = default_policy()
    p["settings"]["detection_mode"] = "enforce"
    p["settings"].update(settings)
    return p


async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def call(mw, path, ip="203.0.113.7"):
    sent = []

    async def receive():
        return {"type": "http.request"}

    async def send(m):
        sent.append(m)

    asyncio.run(mw({"type": "http", "method": "GET", "path": path, "headers": [], "client": (ip, 1)}, receive, send))
    return sent[0]["status"]


class SdkTest(unittest.TestCase):
    def test_signed_observe_policy_never_blocks_even_in_enforce(self):
        mw = IvarMiddleware(app, mode="enforce", on_alert=lambda k, m: None)
        self.assertEqual(call(mw, "/.env.backup"), 200, "DETECTION_MODE observe in the signed policy wins")

    def test_observe_never_affects_requests(self):
        mw = IvarMiddleware(app, mode="observe", on_alert=lambda k, m: None)
        self.assertEqual(call(mw, "/.env.backup"), 200)
        mw.guardian.flush()
        self.assertTrue(len(mw.guardian.core.evidence()) > 0)

    def test_enforce_blocks_decoy_then_contains_source(self):
        mw = IvarMiddleware(app, mode="enforce", policy=enforce_policy(), on_alert=lambda k, m: None)
        self.assertEqual(call(mw, "/.env.backup"), 403)
        mw.guardian.flush()
        self.assertEqual(call(mw, "/hello"), 403)
        self.assertEqual(call(mw, "/hello", ip="198.51.100.1"), 200)

    def test_payout_intent_chain(self):
        g = Guardian(mode="enforce", on_alert=lambda k, m: None)
        steps = {"authenticated_session": "22" * 32, "ledger_entry": "33" * 32, "payout_instruction": "44" * 32}
        keys = {k: step_public_key(s) for k, s in steps.items()}

        def chain(intent_id, limit):
            m = mint_intent("11" * 32, intent_id, "payout", "ses_1", {"amount": limit})
            t = m["token"]
            for step, seed in steps.items():
                t = attest_step(seed, step, t, m["root_public_key"])
            return t, m["root_public_key"]

        token, root = chain("i1", 5000)
        guard = g.sink("payout", root, keys, intent_binding="enforce")
        info = RequestInfo(method="POST", path="/payouts", client_ip="10.0.0.1", headers={}, identity="svc", session="ses_1")
        self.assertEqual(guard.check(info, None, value=100).status, 403)
        self.assertEqual(guard.check(info, token, value=100).status, 200)
        self.assertEqual(guard.check(info, chain("i2", 100000)[0], value=60000).status, 202)

    def test_latency_budget(self):
        g = Guardian(mode="enforce", on_alert=lambda k, m: None)
        info = RequestInfo(method="GET", path="/x", client_ip="203.0.113.9", headers={})
        times = []
        for _ in range(500):
            t = time.perf_counter()
            g.inspect(info)
            times.append((time.perf_counter() - t) * 1000)
        times.sort()
        p99 = times[int(len(times) * 0.99)]
        print(f"python local decision p99 {p99:.3f} ms")
        self.assertLess(p99, 5)


if __name__ == "__main__":
    unittest.main()
