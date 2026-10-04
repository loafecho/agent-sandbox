# coder-box image (step B2).
# The long-lived interactive OpenShell microVM on the agent host. Tools only: no secrets, no repos, no login.
# Programs are pinned by hash at first connection, so an update is a new image and a new box.
FROM nvcr.io/nvidia/base/ubuntu:24.04
ARG CLAUDE_VERSION=2.1.289
ARG BUN_VERSION=1.4.2
ARG UV_VERSION=0.12.21
# Must equal `id -u openshell` / `id -g openshell` on agent-host (gateway.toml sandbox_uid/gid).
ARG SANDBOX_UID=999
ARG SANDBOX_GID=988
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends ca-certificates curl gnupg git git-lfs jq ripgrep ffmpeg tmux \
      python3 python3-venv python3-pip unzip xz-utils less procps iproute2 file locales tzdata gh >/dev/null \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null \
 && apt-get install -y -qq --no-install-recommends nodejs >/dev/null \
 && curl -fsSL https://bun.sh/install | BUN_INSTALL=/usr/local bash -s "bun-v${BUN_VERSION}" >/dev/null \
 && curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" | env UV_UNMANAGED_INSTALL=/usr/local/bin sh >/dev/null \
 && curl -fsSL https://claude.ai/install.sh | bash -s "$CLAUDE_VERSION" >/dev/null \
 && cp -L /root/.local/bin/claude /usr/local/bin/claude && chmod 755 /usr/local/bin/claude \
 && find /root -mindepth 1 -maxdepth 1 \( -name .local -o -name .claude -o -name .claude.json -o -name .bun -o -name .cache \) -exec rm -r {} + \
 && python3 -m venv /opt/tts-venv && /opt/tts-venv/bin/pip install -q --no-cache-dir edge-tts \
 && locale-gen en_US.UTF-8 >/dev/null \
 && apt-get clean && find /var/lib/apt/lists -mindepth 1 -delete
# The box user. The VM driver runs the workload as sandbox_uid; the account is named `sandbox`,
# but its home is /home/coder so paths match the plain VM (memory folder, hooks, path fixes).
RUN groupadd -g "$SANDBOX_GID" sandbox \
 && useradd -u "$SANDBOX_UID" -g "$SANDBOX_GID" -d /home/coder -m -s /bin/bash sandbox \
 && install -d -o sandbox -g sandbox /sandbox \
 && printf '%s %s\n' "$SANDBOX_UID" "$SANDBOX_GID" > /opt/coder-ids
COPY image/boot.sh image/profile.sh bin/box-deny-check.sh /opt/coder/
RUN chmod 755 /opt/coder/boot.sh /opt/coder/box-deny-check.sh && chmod 644 /opt/coder/profile.sh \
 && ln -s /opt/coder/profile.sh /etc/profile.d/coder-box.sh
ENV LANG=en_US.UTF-8
WORKDIR /sandbox
