"""Offline launcher checks; all Java and privileged commands are replaced by fakes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


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
import json, os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["COMMAND_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\\n")
if name == "uname": print("Linux")
elif name == "java" and args == ["-version"]: print('openjdk version "21.0.1"')
elif name == "javac": print("javac 21.0.1")
elif name == "sudo":
    if os.environ.get("DENY_SUDO"): sys.exit(1)
    if "--" in args: args = args[args.index("--") + 1:]
    if args != ["-v"]: sys.exit(subprocess.run(args).returncode)
elif name == "iw" and "managed" in args and os.environ.get("FAIL_MANAGED"):
    sys.exit(1)
elif name == "iw":
    state = pathlib.Path(os.environ["COMMAND_LOG"]).with_name("radio-mode")
    if args[-1:] == ["info"]:
        mode = state.read_text() if state.exists() else os.environ.get("INITIAL_MODE", "managed")
        print("Interface lab0mon\\n\\ttype " + mode + "\\n\\tchannel 1 (2412 MHz), width: 20 MHz")
    elif "type" in args:
        mode = args[-1]
        if mode == "monitor" and os.environ.get("FAIL_MONITOR"): sys.exit(1)
        if not os.environ.get("IGNORE_MODE_CHANGE"): state.write_text(mode)
elif name == "ip" and args[:2] == ["-o", "link"]:
    print("3: lab0mon: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500")
elif name == "nmcli" and args[:2] == ["-g", "GENERAL.NM-MANAGED"]:
    print("yes")
elif name == "mvn":
    if os.environ.get("FAIL_BUILD"): sys.exit(1)
    pathlib.Path("target/ewave-0.1.0-SNAPSHOT.jar").touch()
'''
        for name in ("java", "javac", "mvn", "sudo", "tcpdump", "iw", "ip", "nmcli", "systemctl", "uname"):
            path = binaries / name
            path.write_text(stub)
            path.chmod(0o755)
        self.log = self.root / "commands.jsonl"
        self.env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
                        COMMAND_LOG=str(self.log))
        self.env.pop("JAVA_HOME", None)

    def run_launcher(self, *args, input=""):
        return subprocess.run([str(self.root / "ewave"), *args], input=input,
                              text=True, capture_output=True, env=self.env, cwd="/tmp", timeout=15)

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_default_menu_and_exit_do_not_start_capture(self):
        result = self.run_launcher(input="invalid\n0\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Live Wi-Fi", result.stdout)
        self.assertIn("Restore Wi-Fi", result.stdout)
        self.assertEqual([], self.commands())

    def test_menu_routes_each_live_mode(self):
        self.env["INITIAL_MODE"] = "monitor"
        for selection, expected in (
                ("1\n1", ["--passive-rf", "--iface", "lab0mon"]),
                ("1\n2", ["--passive-rf", "--adaptive", "--iface", "lab0mon"]),
                ("1\n3", ["--passive-rf", "--ops", "--iface", "lab0mon"]),
                ("4\n3", ["--probes", "--iface", "lab0mon"]),
                ("4\n4", ["--iface", "lab0mon"])):
            with self.subTest(selection=selection):
                self.log.unlink(missing_ok=True)
                freq_prompt = "\n" if selection in ("1\n1", "1\n3") else ""
                result = self.run_launcher(input=f"{selection}\nlab0mon\n{freq_prompt}0\n")
                self.assertEqual(0, result.returncode, result.stderr)
                java = [c for c in self.commands() if c[:2] == ["java", "-jar"]]
                self.assertEqual(expected, java[0][3:])

    def test_watch_tunes_requested_frequency_before_launch(self):
        for mode in ("managed", "monitor"):
            with self.subTest(mode=mode):
                self.env["INITIAL_MODE"] = mode
                self.log.unlink(missing_ok=True)
                (self.root / "radio-mode").unlink(missing_ok=True)
                result = self.run_launcher("watch", "lab0mon", "--freq", "2457", input="monitor\n")
                self.assertEqual(0, result.returncode, result.stderr)
                commands = self.commands()
                tune = ["iw", "dev", "lab0mon", "set", "freq", "2457"]
                java = next(c for c in commands if c[:2] == ["java", "-jar"])
                self.assertLess(commands.index(tune), commands.index(java))

    def test_replay_without_file_opens_bundled_recording(self):
        result = self.run_launcher("replay", "--port", "0")
        self.assertEqual(0, result.returncode, result.stderr)
        java = next(c for c in self.commands() if c[:2] == ["java", "-jar"])
        self.assertEqual(["--replay", str(self.root / "src/test/resources/probes/probe-requests.pcap"),
                          "--port", "0"], java[3:])

    def test_replay_preserves_spaces_in_path(self):
        capture = self.root / "example capture.pcap"
        capture.touch()
        result = self.run_launcher(input=f"2\n{capture}\n0\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(["java", "-jar", str(self.root / "target/ewave-0.1.0-SNAPSHOT.jar"),
                       "--replay", str(capture)], self.commands())

    @unittest.skipIf(os.geteuid() == 0, "Root invocation bypasses sudo")
    def test_all_api_server_modes_elevate_only_after_build(self):
        for args in (("demo",), ("--iface", "lab0mon"), ("live", "lab0mon"),
                     ("--probes", "--iface", "lab0mon")):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                (self.root / "target/ewave-0.1.0-SNAPSHOT.jar").unlink()
                result = self.run_launcher(*args)
                self.assertEqual(0, result.returncode, result.stderr)
                commands = self.commands()
                elevated = next(c for c in commands if c[0] == "sudo")
                self.assertEqual(["sudo", "-H", "--preserve-env=JAVA_TOOL_OPTIONS", "--",
                                  str(self.root / "bin/java"), "-jar"], elevated[:6])
                self.assertLess(commands.index(["mvn", "package"]), commands.index(elevated))
                self.assertEqual(1, sum(c[0] == "sudo" for c in commands))

    @unittest.skipIf(os.geteuid() == 0, "Root invocation bypasses sudo")
    def test_denied_elevation_does_not_start_java_application(self):
        self.env["DENY_SUDO"] = "1"
        result = self.run_launcher("demo")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(any(c[:2] == ["java", "-jar"] for c in self.commands()))

    def test_build_does_not_request_elevation(self):
        self.assertEqual(0, self.run_launcher("build").returncode)
        self.assertFalse(any(c[0] == "sudo" for c in self.commands()))

    def test_full_prepares_and_verifies_monitor_before_starting_inventory(self):
        result = self.run_launcher("full", "lab0mon", "--port", "0", input="monitor\n")
        self.assertEqual(0, result.returncode, result.stderr)
        commands = self.commands()
        release = ["nmcli", "device", "set", "lab0mon", "managed", "no"]
        down = ["ip", "link", "set", "lab0mon", "down"]
        mode = ["iw", "dev", "lab0mon", "set", "type", "monitor"]
        up = ["ip", "link", "set", "lab0mon", "up"]
        java = next(c for c in commands if c[:2] == ["java", "-jar"])
        self.assertLess(commands.index(release), commands.index(down))
        self.assertLess(commands.index(down), commands.index(mode))
        self.assertLess(commands.index(mode), commands.index(up))
        self.assertLess(commands.index(up), commands.index(java))
        self.assertIn(["iw", "dev", "lab0mon", "set", "freq", "2412"], commands)
        self.assertEqual(["--passive-rf", "--ops", "--iface", "lab0mon", "--port", "0"], java[3:])
        self.assertNotIn(["systemctl", "stop", "NetworkManager"], commands)

    def test_full_cancellation_never_changes_network_or_launches_api_server(self):
        for answer in ("no\n", ""):
            self.log.unlink(missing_ok=True)
            result = self.run_launcher("full", "lab0mon", input=answer)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(any(c[0] == "sudo" or c[:2] == ["java", "-jar"] for c in self.commands()))

    def test_full_build_failure_does_not_disconnect_wifi(self):
        self.env["FAIL_BUILD"] = "1"
        (self.root / "target/ewave-0.1.0-SNAPSHOT.jar").unlink()
        result = self.run_launcher("full", "lab0mon", input="monitor\n")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(any(c[0] in ("sudo", "iw", "ip", "nmcli") for c in self.commands()))

    def test_full_failed_setup_rolls_back_and_does_not_launch(self):
        self.env["FAIL_MONITOR"] = "1"
        result = self.run_launcher("full", "lab0mon", input="monitor\n")
        self.assertNotEqual(0, result.returncode)
        commands = self.commands()
        self.assertIn(["iw", "dev", "lab0mon", "set", "type", "managed"], commands)
        self.assertIn(["ip", "link", "set", "lab0mon", "up"], commands)
        self.assertIn(["nmcli", "device", "set", "lab0mon", "managed", "yes"], commands)
        self.assertFalse(any(c[:2] == ["java", "-jar"] for c in commands))

    def test_full_refuses_to_launch_when_driver_does_not_remain_in_monitor_mode(self):
        self.env["IGNORE_MODE_CHANGE"] = "1"
        result = self.run_launcher("full", "lab0mon", input="monitor\n")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(any(c[:2] == ["java", "-jar"] for c in self.commands()))

    def test_full_reuses_existing_monitor_mode(self):
        self.env["INITIAL_MODE"] = "monitor"
        result = self.run_launcher("full", "lab0mon")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(any(c[0] == "ip" or c[0] == "nmcli" for c in self.commands()))

    def test_full_rejects_conflicting_flags_and_invalid_ports_before_setup(self):
        for extra in (("--adaptive",), ("--replay", "capture.pcap"), ("--port", "65536")):
            self.log.unlink(missing_ok=True)
            result = self.run_launcher("full", "lab0mon", *extra, input="monitor\n")
            self.assertNotEqual(0, result.returncode)
            self.assertEqual([], self.commands())

    def test_recovery_cancel_and_eof_never_mutate_network(self):
        for answer in ("no\n", ""):
            self.log.unlink(missing_ok=True)
            self.assertEqual(0, self.run_launcher("restore", "lab0mon", input=answer).returncode)
            self.assertFalse(any(c[0] in ("sudo", "ip", "systemctl") for c in self.commands()))

    def test_recovery_commands_target_only_selected_interface(self):
        result = self.run_launcher(input="3\nlab0mon\nrestore\n0\n")
        self.assertEqual(0, result.returncode, result.stderr)
        privileged = [c for c in self.commands() if c[0] == "sudo"]
        self.assertEqual([["sudo", "-v"], ["sudo", "ip", "link", "set", "lab0mon", "down"],
                          ["sudo", "iw", "dev", "lab0mon", "set", "type", "managed"],
                          ["sudo", "ip", "link", "set", "lab0mon", "up"],
                          ["sudo", "systemctl", "start", "NetworkManager"],
                          ["sudo", "nmcli", "device", "set", "lab0mon", "managed", "yes"]], privileged)
        self.assertFalse(any(c[0] in ("java", "mvn") for c in self.commands()))

    def test_failed_mode_change_attempts_to_bring_interface_back_up(self):
        self.env["FAIL_MANAGED"] = "1"
        result = self.run_launcher("restore", "lab0mon", input="restore\n")
        self.assertNotEqual(0, result.returncode)
        self.assertIn(["ip", "link", "set", "lab0mon", "up"], self.commands())
        self.assertFalse(any(c[0] == "systemctl" for c in self.commands()))

    def test_invalid_interface_is_rejected_before_commands(self):
        result = self.run_launcher("restore", "--help", input="restore\n")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(any(c[0] in ("sudo", "iw", "ip", "systemctl") for c in self.commands()))


if __name__ == "__main__":
    unittest.main()
