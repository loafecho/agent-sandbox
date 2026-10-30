import subprocess
import sys

from conftest import REPO, load_script

ps = load_script("boxes/coder/bin/placeholder-scan.py", "placeholder_scan")
P = ps.P  # built from parts in the script; never spelled out in this repo


def test_bare_prefix_kills():
    hits = ps.scan_text(f"say {P}\n", {"GITHUB_TOKEN"})
    assert [(h[0], h[1]) for h in hits] == [(1, "KILLS")]


def test_attached_provider_key_kills_and_versioned_form_too():
    known = {"GITHUB_TOKEN"}
    assert ps.scan_text(f"x {P}GITHUB_TOKEN y", known)[0][1] == "KILLS"
    assert ps.scan_text(f"x {P}v1_GITHUB_TOKEN y", known)[0][1] == "KILLS"


def test_unknown_key_is_a_risk_not_a_kill():
    hits = ps.scan_text(f"{P}SOMETHING_ELSE", {"GITHUB_TOKEN"})
    assert hits == [(1, "risk", "unknown key 'SOMETHING_ELSE' passes today")]


def test_percent_encoded_prefix_counts_case_insensitively():
    assert ps.scan_text(ps.P_PCT.upper(), set())[0][1] == "KILLS"


def test_alias_marker_is_a_risk():
    assert ps.scan_text(f"a {ps.A}b", set()) == [(1, "risk", "alias marker")]


def test_clean_text_has_no_hits():
    assert ps.scan_text("openshell resolve env, spelled out with spaces", {"GITHUB_TOKEN"}) == []


def test_cli_exit_code(tmp_path):
    bad = tmp_path / "bad.md"
    bad.write_text(f"{P}GITHUB_TOKEN\n")
    good = tmp_path / "good.md"
    good.write_text("nothing here\n")
    script = REPO / "boxes/coder/bin/placeholder-scan.py"
    assert subprocess.run([sys.executable, script, str(good)], capture_output=True).returncode == 0
    r = subprocess.run([sys.executable, script, str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 1 and "KILLS" in r.stdout
