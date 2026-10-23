import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET


BASE = "aceba124fd725f4a43d7016ed3f5651d61f83115"
REGRESSION = "keeps the kernel's trailing-slash rule after following a link"
PROPERTY = (
    "leads where the kernel leads and crosses no link, in Node too, "
    "and is what the C library gives"
)
SSH_REQUIRED = [
    "nc reaches the proxy on 127.0.0.1",
    "as injected on macOS: ls-remote",
    "as injected on macOS: clones 24 MiB intact",
    "as injected on macOS: pushes 24 MiB intact",
    "as injected on macOS: a destination on the deny list is refused in the words configured for it",
    "as injected on macOS: a destination on no list is refused, late, in the words of whoever was asked",
    "the macOS spelling: a wrong token is refused promptly",
    "the macOS spelling: a host that ssh lets through and printf would rewrite goes nowhere",
]
SSH_CONTROL = "recorded macOS no-answer input reaches the expected proxy refusal"
TARGETS = {"property": 240, "ssh": 41}
# Higher empirical 95th quantile of successful current-property/file timings
# in the saved upstream jobs: macos-14-arm64 (39 property, 20 SSH samples),
# macos-15 (15 property, 19 SSH). Intel history used macos-15-large hardware;
# the actual standard runner is calibrated before its sweep is sized.
IMAGE_SECONDS = {
    "macos-14": {"property": 7.76532, "ssh": 16.362196},
    "macos-15-intel": {"property": 8.45749, "ssh": 15.169560},
}
MIN_MARGIN_SECONDS = 180


def report(xml):
    cases = []
    for case in ET.fromstring(xml).iter("testcase"):
        state = "pass"
        if case.find("failure") is not None or case.find("error") is not None:
            state = "fail"
        elif case.find("skipped") is not None:
            state = "skip"
        cases.append({"name": case.get("name"), "state": state})
    if not cases:
        raise ValueError("JUnit report contains no test cases")
    return cases


def require_passes(row, required):
    if row["rc"] != 0 or any(c["state"] == "fail" for c in row["cases"]):
        raise ValueError(f"{row['label']} failed; read {row['log']}")
    for name in required:
        matches = [c for c in row["cases"] if c["name"] == name]
        if len(matches) != 1 or matches[0]["state"] != "pass":
            raise ValueError(f"Required test did not pass exactly once: {name}")


def require_control(row, log):
    failed = [c["name"] for c in row["cases"] if c["state"] == "fail"]
    if (
        row["rc"] != 1
        or failed != [REGRESSION]
        or not re.search(r"kernel \d+:\d+; here ENOTDIR; Node ENOTDIR", log)
    ):
        raise ValueError("Old-code control did not show the expected kernel/ENOTDIR disagreement")


def require_ssh_control(row, log, mode):
    observations = [json.loads(line) for line in log.splitlines()
                    if line.startswith('{"control":"ssh-no-answer"')]
    if len(observations) != 1:
        raise ValueError("SSH control did not report its input and attempts")
    observed = observations[0]
    if observed.get("mode") != mode or observed.get("calls") != 3 or row["proxy_connect_retries"] != 2:
        raise ValueError("SSH control did not exercise exactly two retries")
    if mode == "unabsorbed":
        failed = [c["name"] for c in row["cases"] if c["state"] == "fail"]
        if row["rc"] != 1 or failed != [SSH_CONTROL] or not observed["stderr"].endswith(": no answer\n"):
            raise ValueError("Unabsorbed SSH input did not fail the refusal assertion")
    else:
        require_passes(row, [SSH_CONTROL])
        if "403 asked, and refused" not in observed["stderr"]:
            raise ValueError("Recovered SSH control did not reach the expected refusal")


def retry_verdict(retries):
    return {
        "status": "unexercised" if retries == 0 else "observed_recovery",
        "retried_attempts": retries,
        "effectiveness_bound": None,
        "meaning": (
            "No native retry fired; this run says nothing about retry effectiveness"
            if retries == 0 else
            "Native unanswered/EPERM attempts were retried; accepted unanswered shapes also include proxy defects"
        ),
    }


def sized_plan(profile, pilot, remaining):
    seconds = {key: max(IMAGE_SECONDS[profile][key], max(pilot[key])) for key in TARGETS}
    targets = dict(TARGETS)
    capacity = math.floor((remaining - MIN_MARGIN_SECONDS - targets["ssh"] * seconds["ssh"]) / seconds["property"])
    targets["property"] = min(targets["property"], capacity)
    if targets["property"] < 150:
        raise ValueError("Measured runner cannot fit the minimum trial plan with its margin")
    projected = sum(targets[key] * seconds[key] for key in targets)
    return {"targets": targets, "seconds_per_file": seconds,
            "projected_seconds": projected, "remaining_seconds": remaining,
            "margin_seconds": remaining - projected,
            "minimum_margin_seconds": MIN_MARGIN_SECONDS,
            "limit": "Projection from historical image quantiles and the slowest live pilot; deadline remains enforced"}


def zero_failure_upper(trials):
    return -math.expm1(math.log(0.05) / trials) if trials else None


def trial(root, out, label, file, pattern, deadline, extra_env=None):
    remaining = min(180, deadline - time.monotonic())
    if remaining <= 0:
        raise ValueError("Time budget exhausted: insufficient trials")
    log = out / f"{label}.log"
    junit = out / f"{label}.xml"
    command = [
        "bun", "test", str(root / file), "--reporter=junit",
        f"--reporter-outfile={junit}",
    ]
    if pattern:
        command += ["--test-name-pattern", re.escape(pattern)]
    started = time.monotonic()
    environment = {**os.environ, "FORCE_COLOR": "0"}
    environment.pop("SRT_SSH_RETRY_CONTROL", None)
    environment.update(extra_env or {})
    with log.open("w") as stream:
        proc = subprocess.Popen(
            command, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
            start_new_session=True, env=environment,
        )
        try:
            rc = proc.wait(timeout=remaining)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            raise
    row = {
        "label": label, "rc": rc, "seconds": time.monotonic() - started,
        "command": command, "cwd": str(root), "log": str(log),
        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        "junit": str(junit), "cases": report(junit.read_text()),
        "proxy_connect_retries": len(re.findall(r"\[macOS proxy connect retry [12]/3\]", log.read_text())),
        "control_input": (extra_env or {}).get("SRT_SSH_RETRY_CONTROL"),
    }
    with (out / "trials.jsonl").open("a") as stream:
        stream.write(json.dumps(row) + "\n")
    print(json.dumps({k: v for k, v in row.items() if k != "cases"}), flush=True)
    return row


def old_code_fixture(root, control):
    paths = [
        "test/utils/real-path.test.ts", "test/helpers/platform.ts",
        "src/utils/platform.ts", "package.json",
    ]
    for name in paths:
        target = control / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, target)
    (control / "node_modules").symlink_to(root / "node_modules", target_is_directory=True)
    old = subprocess.check_output(["git", "show", f"{BASE}:src/utils/real-path.ts"], cwd=root)
    (control / "src/utils/real-path.ts").write_bytes(old)
    return old


def run(out, minutes, profile):
    root = Path(__file__).resolve().parents[2]
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + minutes * 60
    summary = {
        "platform": platform.platform(), "macos": platform.mac_ver()[0],
        "machine": platform.machine(), "base": BASE, "target_caps": TARGETS,
        "runner_profile": profile,
        "counts": {key: 0 for key in TARGETS}, "complete": False,
        "proxy_connect_retries": 0,
        "confidence": "One-sided 95% per file, per runner; independent stationary trials assumed",
        "limit": "Bounds final test-file failures with the bounded test retry policy, conditional on this runner image and setup; raw retries remain visible",
    }
    try:
        if sys.platform != "darwin":
            raise ValueError("This validation requires a real macOS kernel")
        expected_major = "14" if profile == "macos-14" else "15"
        if platform.mac_ver()[0].split(".")[0] != expected_major:
            raise ValueError("Runner's observed macOS version does not match its timing profile")
        inputs = ["src/utils/real-path.ts", "test/utils/real-path.test.ts",
                  "test/sandbox/git-over-ssh.test.ts", "package-lock.json"]
        hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in inputs}
        summary["input_sha256"] = hashes
        summary["revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        summary["versions"] = {
            tool: subprocess.check_output([tool, "--version"], text=True).strip()
            for tool in ["node", "bun"]
        }
        # The control imports the baseline source, the current regression and
        # its exact local import closure. The reviewed checkout stays intact.
        control = out / "old-code"
        old = old_code_fixture(root, control)
        summary["old_source_sha256"] = hashlib.sha256(old).hexdigest()
        row = trial(control, out, "known-bad", "test/utils/real-path.test.ts", REGRESSION, deadline)
        require_control(row, Path(row["log"]).read_text())
        summary["known_bad_observed"] = True
        row = trial(root, out, "fixed-regression", "test/utils/real-path.test.ts", REGRESSION, deadline)
        require_passes(row, [REGRESSION])
        for mode in ["unabsorbed", "recovered"]:
            row = trial(root, out, f"ssh-control-{mode}", "test/sandbox/git-over-ssh.test.ts",
                        SSH_CONTROL, deadline, {"SRT_SSH_RETRY_CONTROL": mode})
            require_ssh_control(row, Path(row["log"]).read_text(), mode)
        summary["ssh_controls"] = "Persistent recorded no-answer input failed; transient input reached refusal after two retries (controlled inputs, not native flakes)"
        pilot = {key: [] for key in TARGETS}
        for i in range(3):
            for key in TARGETS:
                file = "test/utils/real-path.test.ts" if key == "property" else "test/sandbox/git-over-ssh.test.ts"
                row = trial(root, out, f"pilot-{key}-{i + 1}", file, PROPERTY if key == "property" else None, deadline)
                require_passes(row, [PROPERTY] if key == "property" else SSH_REQUIRED)
                pilot[key].append(row["seconds"])
                summary["proxy_connect_retries"] += row["proxy_connect_retries"]
        plan = sized_plan(profile, pilot, deadline - time.monotonic())
        summary["plan"] = plan
        summary["targets"] = plan["targets"]
        summary["pilot_seconds"] = pilot
        summary["pilot_trials_in_bounds"] = False
        print(json.dumps({"measured_plan": plan}), flush=True)
        for i in range(max(plan["targets"].values())):
            for key, target in plan["targets"].items():
                if i >= target:
                    continue
                file = "test/utils/real-path.test.ts" if key == "property" else "test/sandbox/git-over-ssh.test.ts"
                row = trial(root, out, f"{key}-{i + 1}", file, PROPERTY if key == "property" else None, deadline)
                summary["proxy_connect_retries"] += row["proxy_connect_retries"]
                require_passes(row, [PROPERTY] if key == "property" else SSH_REQUIRED)
                summary["counts"][key] += 1
        if hashes != {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in inputs}:
            raise ValueError("Validation inputs changed while tests ran")
        summary["complete"] = True
        summary["final_file_failure_upper_95"] = {
            key: zero_failure_upper(count) for key, count in summary["counts"].items()
        }
        summary["ssh_retry_evidence"] = retry_verdict(summary["proxy_connect_retries"])
        if summary["proxy_connect_retries"] == 0:
            print("::warning::Native SSH retry unexercised: this run says nothing about retry effectiveness", flush=True)
    except Exception as error:
        summary["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        if not summary["complete"]:
            summary["ssh_retry_evidence"] = {
                "status": "failed_or_incomplete",
                "retried_attempts": summary["proxy_connect_retries"],
                "effectiveness_bound": None,
            }
        summary["seconds"] = time.monotonic() - started
        text = json.dumps(summary, indent=2)
        (out / "summary.json").write_text(text + "\n")
        (out / "summary.md").write_text("```json\n" + text + "\n```\n")
        print(text, flush=True)


def selftest():
    class Checks(unittest.TestCase):
        def test_required_evidence(self):
            for xml in ["<testsuites/>", "<broken"]:
                with self.assertRaises((ValueError, ET.ParseError)):
                    report(xml)
            for child in ["<skipped/>", "<failure/>", "<error/>"]:
                cases = report(f'<testsuite><testcase name="required">{child}</testcase></testsuite>')
                with self.assertRaises(ValueError):
                    require_passes({"rc": 0, "cases": cases, "label": "fixture", "log": "fixture"}, ["required"])
            clean = report('<testsuite><testcase name="required"/></testsuite>')
            row = {"rc": 0, "cases": clean, "label": "fixture", "log": "fixture"}
            require_passes(row, ["required"])
            for bad in [{**row, "rc": 1}, {**row, "cases": []}, {**row, "cases": clean * 2}]:
                with self.assertRaises(ValueError):
                    require_passes(bad, ["required"])

        def test_control_rejects_unrelated_failure_and_green_old_code(self):
            row = {"rc": 1, "cases": [{"name": REGRESSION, "state": "fail"}]}
            observed = "kernel 1:42; here ENOTDIR; Node ENOTDIR"
            require_control(row, observed)
            for bad, log in [({**row, "rc": 0}, observed), (row, "ERR_NO_TYPESCRIPT"),
                             ({**row, "cases": [{"name": "other", "state": "fail"}]}, observed)]:
                with self.assertRaises(ValueError):
                    require_control(bad, log)

        def test_bound(self):
            self.assertIsNone(zero_failure_upper(0))
            self.assertGreater(zero_failure_upper(298), 0.01)
            self.assertLess(zero_failure_upper(299), 0.01)
            self.assertLess(zero_failure_upper(TARGETS["property"]), 0.013)
            self.assertLess(zero_failure_upper(TARGETS["ssh"]), 0.072)

        def test_unexercised_is_not_effectiveness_evidence(self):
            verdict = retry_verdict(0)
            self.assertEqual(verdict["status"], "unexercised")
            self.assertIsNone(verdict["effectiveness_bound"])
            self.assertIn("says nothing", verdict["meaning"])

        def test_runner_budget(self):
            for profile, values in IMAGE_SECONDS.items():
                pilot = {key: [values[key]] * 3 for key in values}
                plan = sized_plan(profile, pilot, 2900)
                self.assertGreaterEqual(plan["margin_seconds"], MIN_MARGIN_SECONDS)
                self.assertEqual(plan["targets"], TARGETS)
            with self.assertRaises(ValueError):
                sized_plan("macos-15-intel", {"property": [100], "ssh": [100]}, 2900)

        def test_ssh_leg_observes_unabsorbed_input_failing(self):
            root = Path(__file__).resolve().parents[2]
            with tempfile.TemporaryDirectory(prefix="ssh-leg-control-") as temp:
                out = Path(temp)
                for mode in ["unabsorbed", "recovered"]:
                    row = trial(root, out, f"ssh-{mode}", "test/sandbox/git-over-ssh.test.ts",
                                SSH_CONTROL, time.monotonic() + 30,
                                {"SRT_SSH_RETRY_CONTROL": mode})
                    log = Path(row["log"]).read_text()
                    require_ssh_control(row, log, mode)
                    if mode == "unabsorbed":
                        with self.assertRaises(ValueError):
                            require_passes(row, [SSH_CONTROL])
                        with self.assertRaises(ValueError):
                            require_ssh_control({**row, "rc": 0}, log, mode)

        def test_failed_child_and_exhausted_budget_are_observed(self):
            with tempfile.TemporaryDirectory(prefix="macos-flakes-selftest-") as temp:
                root = Path(temp)
                test = root / "control.test.ts"
                test.write_text("import {test, expect} from 'bun:test'; test('known bad', () => expect(1).toBe(2));\n")
                row = trial(root, root, "known-bad-fixture", test.name, None, time.monotonic() + 10)
                self.assertEqual(row["rc"], 1)
                self.assertEqual(row["cases"], [{"name": "known bad", "state": "fail"}])
                with self.assertRaises(ValueError):
                    require_passes(row, ["known bad"])
                with self.assertRaisesRegex(ValueError, "insufficient trials"):
                    trial(root, root, "no-budget", test.name, None, time.monotonic() - 1)

        def test_real_control_import_closure(self):
            root = Path(__file__).resolve().parents[2]
            with tempfile.TemporaryDirectory(prefix="macos-flakes-imports-") as temp:
                out = Path(temp)
                control = out / "old-code"
                old_code_fixture(root, control)
                row = trial(control, out, "original-regression", "test/utils/real-path.test.ts", REGRESSION, time.monotonic() + 45)
                log = Path(row["log"]).read_text()
                if sys.platform == "darwin":
                    require_control(row, log)
                else:
                    require_passes(row, [REGRESSION])
                    with self.assertRaises(ValueError):
                        require_control(row, log)

    return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks)).wasSuccessful()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fork-only macOS known-bad control and bounded flake validation")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--minutes", type=int, default=50)
    parser.add_argument("--runner", choices=list(IMAGE_SECONDS))
    args = parser.parse_args()
    if args.selftest:
        sys.exit(0 if selftest() else 1)
    if args.out is None or args.runner is None or not 1 <= args.minutes <= 50:
        parser.error("--out and --runner are required; --minutes must be between 1 and 50")
    try:
        run(args.out.resolve(), args.minutes, args.runner)
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
