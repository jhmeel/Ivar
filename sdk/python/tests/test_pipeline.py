import os
import pickle
import socket
import unittest

from ivar.pipeline import LoadBlocked, PipelineSensor


class Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


class PipelineTest(unittest.TestCase):
    def test_enforce_blocks_code_execution_and_egress(self):
        events = []
        s = PipelineSensor(mode="enforce", report=events.append)
        payload = pickle.dumps(Evil())
        with self.assertRaises(LoadBlocked):
            with s.guarded_load("community/evil"):
                pickle.loads(payload)
        self.assertEqual(events[-1]["activity_name"], "dataset.load")
        self.assertEqual(events[-1]["ivar"]["attributes"]["code_execution"], "true")
        with self.assertRaises(LoadBlocked):
            with s.guarded_load("community/evil", allow_hosts={"huggingface.co"}):
                socket.create_connection(("203.0.113.9", 80), timeout=0.1)
        self.assertEqual(events[-1]["activity_name"], "net.connect")

    def test_observe_records_and_benign_loads_pass(self):
        events = []
        s = PipelineSensor(mode="observe", report=events.append)
        with s.guarded_load("ok/dataset") as load:
            self.assertEqual(pickle.loads(pickle.dumps({"a": [1, 2]})), {"a": [1, 2]})
        self.assertEqual(load.findings, [])
        outside = pickle.loads(pickle.dumps([1]))
        self.assertEqual(outside, [1])

    def test_core_flags_the_load(self):
        from ivar import Core, default_policy
        events = []
        s = PipelineSensor(mode="observe", report=events.append)
        with s.guarded_load("community/evil"):
            try:
                pickle.loads(pickle.dumps(Evil()))
            except Exception:
                pass
        core = Core.create(default_policy())
        out = core.process(events[0])
        self.assertTrue(any(f["rule"] == "code_exec_during_load" for f in out["findings"]))


if __name__ == "__main__":
    unittest.main()
