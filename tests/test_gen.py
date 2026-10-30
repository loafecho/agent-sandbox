import copy
import subprocess
import sys

import pytest
import yaml

from conftest import REPO, load_script

gen = load_script("switchboard/gen.py", "sb_gen")


def spec():
    return gen.load()


def test_committed_files_match_tools_yaml():
    r = subprocess.run([sys.executable, REPO / "switchboard/gen.py", "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
    assert "stale=0" in r.stdout


def test_generation_is_deterministic():
    s = spec()
    assert gen.agents_json(s) == gen.agents_json(spec())
    assert gen.tools_md(s) == gen.tools_md(spec())


def test_power_allowlist_refuses_guests_that_hold_the_approval_path():
    s = spec()
    for never in sorted(gen.NEVER_POWER):
        bad = copy.deepcopy(s)
        bad["power_vmids"] = ["102", never]
        with pytest.raises(AssertionError):
            gen.power_vmids(bad)


def test_profile_allows_exactly_the_agents_tools():
    s = spec()
    prof = yaml.safe_load(gen.profile(s, "coder"))
    rules = prof["endpoints"][0]["rules"]
    called = sorted(r["allow"]["params"]["name"]["glob"] for r in rules if r["allow"]["method"] == "tools/call")
    assert called == gen.agent_tools(s, "coder")
    assert prof["binaries"] == ["/usr/local/bin/claude"]
    assert prof["endpoints"][0]["allowed_ips"] == [f"{s['switchboard']['host']}/32"]


def test_load_refuses_an_argument_without_a_pattern(tmp_path, monkeypatch):
    s = yaml.safe_load((REPO / "switchboard/tools.yaml").read_text())
    s["tools"]["host_health"]["args"]["host"].pop("pattern")
    (tmp_path / "tools.yaml").write_text(yaml.safe_dump(s))
    monkeypatch.setattr(gen, "HERE", tmp_path)
    with pytest.raises(AssertionError, match="host_health.host"):
        gen.load()


def test_load_refuses_an_unknown_tier(tmp_path, monkeypatch):
    s = yaml.safe_load((REPO / "switchboard/tools.yaml").read_text())
    s["tools"]["services_up"]["tier"] = "change"
    (tmp_path / "tools.yaml").write_text(yaml.safe_dump(s))
    monkeypatch.setattr(gen, "HERE", tmp_path)
    with pytest.raises(AssertionError, match="tier change"):
        gen.load()
