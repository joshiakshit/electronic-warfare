"""Offline launcher checks; all Java and privileged commands are replaced by fakes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import tempfile


class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ewave launcher ")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        shutil.copy(Path(__file__).resolve().parents[1] / "ewave", self.root / "ewave")
        demo = self.root / "src/test/resources/probes/probe-requests.pcap"
        demo.parent.mkdir(parents=True)
        demo.touch()
        (self.root / "pom.xml").touch()
        (self.root / "target").mkdir()
        (self.root / "target/ewave-0.1.0-SNAPSHOT.jar").touch()
        binaries = self.root / "bin"
        binaries.mkdir()
        stub = '''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, time
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["COMMAND_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\\n")
if name == "uname": print("Linux")
elif name == "java" and args == ["-version"]: print('openjdk version "21.0.1"')
elif name == "java" and "-jar" in args and os.environ.get("JAVA_ENV_LOG"):
    pathlib.Path(os.environ["JAVA_ENV_LOG"]).write_text(json.dumps({"home": os.environ["HOME"], "args": args}))
elif name == "javac": print("javac 21.0.1")
elif name == "sudo":
    if os.environ.get("DENY_SUDO"): sys.exit(1)
    if "--" in args: args = args[args.index("--") + 1:]
    if args != ["-v"]:
        child_env = dict(os.environ)
        if "-H" in sys.argv[1:]: child_env["HOME"] = os.environ.get("FAKE_ROOT_HOME", "/root")
        sys.exit(subprocess.run(args, env=child_env).returncode)
elif name == "iw" and "managed" in args and os.environ.get("FAIL_MANAGED"):
    sys.exit(1)
elif name == "iw":
    state = pathlib.Path(os.environ["COMMAND_LOG"]).with_name("radio-mode")
    if args == ["dev"]:
        if os.environ.get("IW_DEV_LIST"):
            print(os.environ["IW_DEV_LIST"])
    elif args[-1:] == ["info"]:
        mode = state.read_text() if state.exists() else os.environ.get("INITIAL_MODE", "managed")
        freq = os.environ.get("INITIAL_FREQ", "2412")
        ch = os.environ.get("INITIAL_CH", "1")
        print(f"Interface lab0mon\\n\\ttype {mode}\\n\\tchannel {ch} ({freq} MHz), width: 20 MHz")
    elif "type" in args:
        mode = args[-1]
        if mode == "monitor" and os.environ.get("FAIL_MONITOR"): sys.exit(1)
        if not os.environ.get("IGNORE_MODE_CHANGE"): state.write_text(mode)
elif name == "ip" and args[:2] == ["-o", "link"]:
    flags = os.environ.get("INITIAL_LINK_FLAGS", "BROADCAST,MULTICAST,UP,LOWER_UP")
    print(f"3: lab0mon: <{flags}> mtu 1500")
elif name == "nmcli" and args[:2] == ["-g", "GENERAL.NM-MANAGED"]:
    print(os.environ.get("INITIAL_NM_MANAGED", "yes"))
elif name == "nmcli" and args[:2] == ["-g", "GENERAL.CONNECTION"]:
    print(os.environ.get("INITIAL_CONNECTION", ""))
elif name == "mvn":
    if os.environ.get("FAIL_BUILD"): sys.exit(1)
    pathlib.Path("target/ewave-0.1.0-SNAPSHOT.jar").touch()
elif name == "node":
    if os.environ.get("FAIL_FRONTEND"):
        print("Vite failed", file=sys.stderr)
        sys.exit(1)
    print("  ➜  Local:   http://127.0.0.1:5174/", flush=True)
    time.sleep(30)
'''
        for name in ("java", "javac", "mvn", "sudo", "tcpdump", "iw", "ip", "nmcli", "systemctl", "uname", "npm", "node"):
            path = binaries / name
            path.write_text(stub)
            path.chmod(0o755)
        self.log = self.root / "commands.jsonl"
        self.env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
                        COMMAND_LOG=str(self.log), TMPDIR=str(self.root))
        self.env.pop("JAVA_HOME", None)

    def run_launcher(self, *args, input=""):
        return subprocess.run([str(self.root / "ewave"), *args], input=input,
                              text=True, capture_output=True, env=self.env, cwd="/tmp", timeout=15)

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def install_fake_frontend(self):
        vite = self.root / "frontend/node_modules/vite/bin/vite.js"
        vite.parent.mkdir(parents=True)
        vite.touch()

    def test_default_menu_and_exit_do_not_start_capture(self):
        result = self.run_launcher(input="invalid\n0\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Live Wi-Fi", result.stdout)
        self.assertIn("Replay a recording", result.stdout)
        self.assertIn("Setup and diagnostics", result.stdout)
        self.assertEqual([], self.commands())

    def test_dashboard_only_starts_idle_api_without_sudo_or_adapter_changes(self):
        result = self.run_launcher(input="4\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([["java", "-version"], ["java", "-jar", str(self.root / "target/ewave-0.1.0-SNAPSHOT.jar")]],
                         self.commands())

    def test_live_wifi_discovers_adapter_ignores_non_netdev_and_starts_unified_backend(self):
        self.env["INITIAL_MODE"] = "monitor"
        self.env["IW_DEV_LIST"] = (
            "phy#0\n"
            "\tUnnamed/non-netdev interface\n"
            "\t\ttype P2P-device\n"
            "\tInterface lab0mon\n"
            "\t\tssid LabNet\n"
            "\t\ttype monitor\n"
            "\t\tchannel 1 (2412 MHz), width: 20 MHz\n"
        )
        result = self.run_launcher(input="1\n1\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("1) lab0mon", result.stdout)
        self.assertNotIn("P2P-device", result.stdout)
        java = next(c for c in self.commands() if c[0] == "java" and "-jar" in c)
        self.assertEqual(["--iface", "lab0mon", "--adaptive"], java[java.index("-jar") + 2:])

    @unittest.skipIf(os.geteuid() == 0, "Root invocation bypasses sudo")
    def test_live_wifi_managed_adapter_prepares_monitor_launches_after_build_and_restores_once(self):
        self.env["IW_DEV_LIST"] = "phy#0\n\tInterface lab0mon\n\t\ttype managed\n"
        (self.root / "target/ewave-0.1.0-SNAPSHOT.jar").unlink()
        result = self.run_launcher(input="1\n1\nmonitor\n")
        self.assertEqual(0, result.returncode, result.stderr)
        commands = self.commands()
        release = ["nmcli", "device", "set", "lab0mon", "managed", "no"]
        down = ["ip", "link", "set", "lab0mon", "down"]
        mode = ["iw", "dev", "lab0mon", "set", "type", "monitor"]
        up = ["ip", "link", "set", "lab0mon", "up"]
        restore_managed = ["iw", "dev", "lab0mon", "set", "type", "managed"]
        restore_nm = ["nmcli", "device", "set", "lab0mon", "managed", "yes"]
        java = next(c for c in commands if c[0] == "java" and "-jar" in c)
        elevated = next(c for c in commands if c[0] == "sudo" and any("java" in arg for arg in c))
        self.assertEqual(["sudo", "-H", "--preserve-env=JAVA_TOOL_OPTIONS", "--",
                          str(self.root / "bin/java"), "-Drf.userHome=" + self.env["HOME"], "-jar"], elevated[:7])
        self.assertLess(commands.index(["mvn", "package"]), commands.index(release))
        self.assertLess(commands.index(release), commands.index(down))
        self.assertLess(commands.index(down), commands.index(mode))
        self.assertLess(commands.index(mode), commands.index(up))
        self.assertLess(commands.index(up), commands.index(java))
        self.assertLess(commands.index(java), commands.index(restore_managed))
        self.assertLess(commands.index(restore_managed), commands.index(restore_nm))
        self.assertEqual(1, commands.count(restore_managed))
        self.assertEqual(1, commands.count(restore_nm))
        self.assertIn(["iw", "dev", "lab0mon", "set", "freq", "2412"], commands)
        self.assertEqual(["--iface", "lab0mon", "--adaptive"], java[java.index("-jar") + 2:])
        self.assertNotIn(["systemctl", "stop", "NetworkManager"], commands)

    @unittest.skipIf(os.geteuid() == 0, "Root invocation bypasses sudo")
    def test_sudo_home_reset_preserves_the_callers_storage_home(self):
        self.env["HOME"] = str(self.root / "operator home")
        self.env["FAKE_ROOT_HOME"] = str(self.root / "root home")
        self.env["JAVA_ENV_LOG"] = str(self.root / "java-env.json")
        self.env["INITIAL_MODE"] = "monitor"
        self.env["IW_DEV_LIST"] = "phy#0\n\tInterface lab0mon\n\t\ttype monitor\n"
        result = self.run_launcher(input="1\n1\n")
        self.assertEqual(0, result.returncode, result.stderr)
        launched = json.loads(Path(self.env["JAVA_ENV_LOG"]).read_text())
        self.assertEqual(self.env["FAKE_ROOT_HOME"], launched["home"])
        self.assertIn("-Drf.userHome=" + self.env["HOME"], launched["args"])
        self.assertEqual("-jar", launched["args"][1])

    def test_live_wifi_preserves_original_monitor_mode_on_exit(self):
        self.env["INITIAL_MODE"] = "monitor"
        self.env["INITIAL_LINK_FLAGS"] = "BROADCAST,MULTICAST"
        self.env["IW_DEV_LIST"] = "phy#0\n\tInterface lab0mon\n\t\ttype monitor\n"
        result = self.run_launcher(input="1\n1\n")
        self.assertEqual(0, result.returncode, result.stderr)
        commands = self.commands()
        self.assertFalse(any(c[0] in ("ip", "nmcli") for c in commands))
        self.assertNotIn(["iw", "dev", "lab0mon", "set", "type", "managed"], commands)

    def test_live_wifi_cancellation_build_failure_and_setup_failure_safety(self):
        self.env["IW_DEV_LIST"] = "phy#0\n\tInterface lab0mon\n\t\ttype managed\n"
        for answer in ("no\n0\n", "\n0\n"):
            self.log.unlink(missing_ok=True)
            result = self.run_launcher(input=f"1\n1\n{answer}")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(any(c[0] == "sudo" or c[:2] == ["java", "-jar"] for c in self.commands()))

        self.log.unlink(missing_ok=True)
        self.env["FAIL_BUILD"] = "1"
        (self.root / "target/ewave-0.1.0-SNAPSHOT.jar").unlink()
        result = self.run_launcher(input="1\n1\n")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(any(c[0] in ("sudo", "ip", "nmcli") or (c[0] == "iw" and "set" in c) for c in self.commands()))
        del self.env["FAIL_BUILD"]
        (self.root / "target/ewave-0.1.0-SNAPSHOT.jar").touch()

        self.log.unlink(missing_ok=True)
        self.env["DENY_SUDO"] = "1"
        result = self.run_launcher(input="1\n1\nmonitor\n")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(any(c[:2] == ["java", "-jar"] for c in self.commands()))
        del self.env["DENY_SUDO"]

        self.log.unlink(missing_ok=True)
        self.env["FAIL_MONITOR"] = "1"
        result = self.run_launcher(input="1\n1\nmonitor\n")
        self.assertNotEqual(0, result.returncode)
        commands = self.commands()
        self.assertEqual(1, commands.count(["iw", "dev", "lab0mon", "set", "type", "managed"]))
        self.assertEqual(1, commands.count(["nmcli", "device", "set", "lab0mon", "managed", "yes"]))
        self.assertFalse(any(c[:2] == ["java", "-jar"] for c in commands))
        del self.env["FAIL_MONITOR"]

        self.log.unlink(missing_ok=True)
        self.env["IGNORE_MODE_CHANGE"] = "1"
        result = self.run_launcher(input="1\n1\nmonitor\n")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(any(c[:2] == ["java", "-jar"] for c in self.commands()))

    def test_replay_runs_without_sudo_starts_frontend_when_installed_and_supports_spaces(self):
        capture = self.root / "example capture.pcap"
        capture.touch()
        (self.root / "target/ewave-0.1.0-SNAPSHOT.jar").unlink()
        self.install_fake_frontend()
        result = self.run_launcher(input=f"2\nc\n{capture}\n")
        self.assertEqual(0, result.returncode, result.stderr)
        commands = self.commands()
        self.assertIn(["mvn", "package"], commands)
        self.assertFalse(any(c[0] == "sudo" for c in commands))
        self.assertIn(["java", "-jar", str(self.root / "target/ewave-0.1.0-SNAPSHOT.jar"),
                       "--replay", str(capture)], commands)
        self.assertTrue(any(c[:2] == ["node", "node_modules/vite/bin/vite.js"] for c in commands))
        self.assertIn("Dashboard: http://127.0.0.1:5174/", result.stdout)
        self.assertNotIn("Dashboard: http://127.0.0.1:5173", result.stdout)

    def test_dashboard_reports_failed_frontend_start_and_still_starts_api(self):
        self.install_fake_frontend()
        self.env["FAIL_FRONTEND"] = "1"
        result = self.run_launcher(input="4\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("Dashboard:", result.stdout)
        self.assertIn("Dashboard failed to start", result.stderr)
        self.assertTrue(any(c[:2] == ["java", "-jar"] for c in self.commands()))
        log, = self.root.glob("ewave-frontend.*.log")
        self.assertEqual("Vite failed\n", log.read_text())

    def test_setup_menu_doctor_build_and_restore(self):
        result = self.run_launcher(input="3\n1\n3\n2\n0\n")
        self.assertEqual(0, result.returncode, result.stderr)
        commands = self.commands()
        self.assertFalse(any(c[0] == "sudo" for c in commands))
        self.assertIn(["mvn", "package"], commands)

        self.log.unlink(missing_ok=True)
        result = self.run_launcher(input="3\n3\nlab0mon\nrestore\n0\n")
        self.assertEqual(0, result.returncode, result.stderr)
        privileged = [c for c in self.commands() if c[0] == "sudo"]
        self.assertEqual([["sudo", "-v"], ["sudo", "ip", "link", "set", "lab0mon", "down"],
                          ["sudo", "iw", "dev", "lab0mon", "set", "type", "managed"],
                          ["sudo", "ip", "link", "set", "lab0mon", "up"],
                          ["sudo", "systemctl", "start", "NetworkManager"],
                          ["sudo", "nmcli", "device", "set", "lab0mon", "managed", "yes"]], privileged)

        self.log.unlink(missing_ok=True)
        self.assertEqual(0, self.run_launcher("restore", "lab0mon", input="no\n").returncode)
        self.assertFalse(any(c[0] in ("sudo", "ip", "systemctl") for c in self.commands()))

        self.log.unlink(missing_ok=True)
        self.assertNotEqual(0, self.run_launcher("restore", "--help", input="restore\n").returncode)
        self.assertFalse(any(c[0] in ("sudo", "iw", "ip", "systemctl") for c in self.commands()))

    def test_unknown_subcommands_are_rejected(self):
        for cmd in ("watch", "scan", "ops", "replay", "probes", "summary", "--iface"):
            with self.subTest(cmd=cmd):
                self.log.unlink(missing_ok=True)
                result = self.run_launcher(cmd, "lab0mon")
                self.assertNotEqual(0, result.returncode)
                self.assertEqual([], self.commands())


if __name__ == "__main__":
    unittest.main()
