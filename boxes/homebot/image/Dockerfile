# Homebot (Home Assistant agent) sandbox image. Runs inside an OpenShell microVM on the agent host.
# Pinned Claude Code, plus Homebot's skill and MCP config baked in
# read-only under /opt/homebot. No curl, no git: the only way out is /usr/local/bin/claude anyway.
FROM nvcr.io/nvidia/base/ubuntu:24.04
ARG CLAUDE_VERSION=2.1.283
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null \
 && curl -fsSL https://claude.ai/install.sh | bash -s "$CLAUDE_VERSION" \
 && cp -L /root/.local/bin/claude /usr/local/bin/claude && chmod 755 /usr/local/bin/claude \
 && apt-get purge -y -qq curl >/dev/null && apt-get autoremove -y -qq >/dev/null && apt-get clean
COPY skill/SKILL.md /opt/homebot/SKILL.md
COPY image/mcp.json /opt/homebot/mcp.json
RUN chmod 444 /opt/homebot/SKILL.md /opt/homebot/mcp.json
