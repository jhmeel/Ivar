"""Live policy: a newer signed bundle from the control plane takes effect
while the application runs; a forged one is refused and the current policy
stays; a restart resumes at the last verified policy."""
import http.server
import json
import os
import tempfile
import threading
import unittest

from ivar import Guardian, RequestInfo, verify_policy_bundle

DATA = os.path.join(os.path.dirname(__file__), "..", "..", "testdata", "policy")


def read(name):
    with open(os.path.join(DATA, name)) as f:
        return f.read().strip()


KEYRING = json.loads(read("keyring.json"))
V1 = verify_policy_bundle(read("v1.bundle"), KEYRING)


class ControlPlane:
    def __init__(self):
        self.serve = "v2.bundle"
        cp = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = read(cp.serve).encode()
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def decoy(g):
    return g.inspect(RequestInfo(method="GET", path="/v2-decoy", client_ip="198.51.100.4", headers={})).action


class PolicyRefreshTest(unittest.TestCase):
    def test_a_newer_signed_policy_applies_live_and_a_forged_one_is_refused(self):
        cp, alerts = ControlPlane(), []
        state = os.path.join(tempfile.mkdtemp(), "policy.state")
        try:
            self.assertNotEqual(decoy(Guardian(mode="enforce", policy=V1)), "block", "v1 has no such decoy")
            g = Guardian(mode="enforce", policy=V1, control_url=cp.url, policy_keyring=KEYRING, policy_refresh_s=3600,
                         policy_state_file=state, on_alert=lambda k, m: alerts.append(k))
            g.refresher.refresh()
            self.assertEqual(g.policy["version"], 2)
            self.assertEqual(decoy(g), "block", "the decoy route added in v2 is enforced")
            cp.serve = "forged-v3.bundle"
            self.assertFalse(g.refresher.refresh())
            self.assertEqual(g.policy["version"], 2, "a forged bundle changes nothing")
            self.assertIn("policy_rejected", alerts)

            restarted = Guardian(mode="enforce", policy=V1, policy_keyring=KEYRING, policy_state_file=state)
            self.assertEqual(restarted.policy["version"], 2, "a restart resumes at the saved policy")
        finally:
            cp.close()


if __name__ == "__main__":
    unittest.main()
