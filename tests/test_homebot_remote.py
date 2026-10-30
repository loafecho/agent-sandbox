from conftest import load_script

hr = load_script("boxes/homebot/bin/homebot-remote", "homebot_remote")


def test_scrub_removes_anthropic_keys_and_jwts():
    jwt = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 8
    out = hr.scrub(f"key sk-ant-abc_DEF-123 and token {jwt} end")
    assert "sk-ant-" not in out and "eyJ" not in out
    assert out == "key <scrubbed> and token <scrubbed-jwt> end"


def test_hosts_trailer_lists_allowed_and_denied_once_each():
    log = "\n".join([
        "NET:OPEN [L7] ALLOWED /usr/local/bin/claude -> api.anthropic.com:443",
        "NET:OPEN [L7] ALLOWED api.anthropic.com:443",
        "NET:OPEN [L4] DENIED /usr/bin/node -> example.com:443",
    ])
    assert hr.hosts(log) == "<<<NETWORK-HOSTS allowed=api.anthropic.com denied=example.com>>>\n"


def test_hosts_trailer_when_nothing_was_logged():
    assert hr.hosts("") == "<<<NETWORK-HOSTS allowed= denied=>>>\n"


def test_box_runs_with_no_builtin_tools_and_only_the_ha_server():
    assert '--tools ""' in hr.INNER
    assert "--strict-mcp-config" in hr.INNER
    assert '--allowedTools "mcp__home-assistant"' in hr.INNER
    assert hr.MAX_TASK == 4096
