# sift-gateway container image — the Valhuntir forensic platform
# (forensic-mcp, sift-mcp, case-mcp, report-mcp) aggregated behind one HTTP MCP
# endpoint, for use as an agentcontainers container-type MCP tool
# (agent.tools.mcp.<name>: { type: container, transport: http, port: 4508 }).
#
# Built from THIS repo (jlgore/sift-mcp) — the build context is the monorepo
# itself, so the gateway runs this fork's sift-mcp (evidence graph, manifest,
# forensic-critic) rather than mainstream AppliedIR/sift-mcp.
#
# Base: Ubuntu 24.04 — matches the SIFT workstation host (glibc 2.39), so the
# baked toolset behaves identically to the host and host-specific extras can be
# bind-mounted at runtime without ABI mismatch. (The previous python:3.12-slim
# Debian base only shipped TSK, forcing the agent to hand-roll registry/SAM
# parsers; this image bakes the SIFT-class toolset instead.)
#
# Runtime note: agentcontainers runs MCP tool containers hardened — read-only
# rootfs, all caps dropped, only /run/secrets writable (tmpfs). Every mutable
# path below is funneled under /run/secrets and bytecode writes are disabled.
FROM ubuntu:24.04

LABEL org.opencontainers.image.source=https://github.com/jlgore/sift-mcp
LABEL org.opencontainers.image.description="Valhuntir SIFT forensic platform (forensic-mcp, sift-mcp, case-mcp, report-mcp) on an Ubuntu SIFT base, behind one HTTP MCP gateway"
LABEL org.opencontainers.image.licenses=MIT

ENV DEBIAN_FRONTEND=noninteractive

# Python runtime + build deps, and the SIFT-class forensic toolset:
#   sleuthkit/ewf-tools  — TSK CLI + EWF (Ubuntu's libewf reads .E01 directly,
#                          so no host-side ewfmount workaround is needed)
#   yara + libyara-dev   — IOC scanning (and the yara-python build dep)
#   bulk-extractor       — artifact/IOC carving
#   binutils             — strings
#   libesedb-utils       — ESE/SRUM (esedbexport); pff-tools — PST/OST
#   perl + libparse-win32registry-perl — RegRipper runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 python3-venv python3-pip python3-dev build-essential \
       git ca-certificates curl \
       sleuthkit ewf-tools \
       yara libyara-dev binutils \
       perl libparse-win32registry-perl \
    && for opt in bulk-extractor libesedb-utils pff-tools; do \
         apt-get install -y --no-install-recommends "$opt" \
           || echo "WARN: optional forensic package '$opt' not in base repos (GIFT-PPA only) — skipping; bind-mount from host if needed"; \
       done \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages uv

# RegRipper 3.0 (Perl; uses libparse-win32registry-perl). Provides registry
# parsing the backends can shell out to instead of a hand-rolled regf parser.
RUN git clone --depth 1 https://github.com/keydet89/RegRipper3.0.git /opt/regripper \
    && printf '#!/bin/sh\nexec perl /opt/regripper/rip.pl "$@"\n' > /usr/local/bin/rip.pl \
    && chmod 755 /usr/local/bin/rip.pl \
    && ln -sf /usr/local/bin/rip.pl /usr/local/bin/regripper

WORKDIR /app

# vhir-cli (required by case-mcp / report-mcp) lives in a separate public repo.
ARG VHIR_REF=main
RUN git clone --depth 1 --branch "$VHIR_REF" \
      https://github.com/AppliedIR/Valhuntir.git /app/vhir

# The sift-mcp monorepo (this build context — i.e. this fork).
COPY . /app/sift-mcp

# One system venv on PATH so the gateway's `python -m <backend>` subprocesses
# resolve to the installed packages.
ENV VIRTUAL_ENV=/app/venv
RUN uv venv "$VIRTUAL_ENV" --seed
ENV PATH="/app/venv/bin:$PATH"

# Install vhir-cli + the gateway and its core local backends (deps first), then
# the Python forensic libraries so backends parse artifacts natively:
#   regipy        — Windows registry hives (replaces hand-rolled regf parsing)
#   python-evtx   — Windows event logs (.evtx)
#   dfwinreg      — registry abstraction
#   yara-python   — programmatic YARA
#   volatility3   — memory analysis (for cases that include a memory image)
RUN uv pip install \
      -e /app/vhir \
      -e /app/sift-mcp/packages/sift-common \
      -e /app/sift-mcp/packages/forensic-knowledge \
      -e /app/sift-mcp/packages/sift-gateway \
      -e /app/sift-mcp/packages/forensic-mcp \
      -e /app/sift-mcp/packages/sift-mcp \
      -e /app/sift-mcp/packages/case-mcp \
      -e /app/sift-mcp/packages/report-mcp \
    && uv pip install regipy python-evtx dfwinreg yara-python volatility3

COPY docker/gateway.yaml /app/gateway.yaml
COPY docker/entrypoint.sh /usr/local/bin/sift-entrypoint
RUN chmod 755 /usr/local/bin/sift-entrypoint

# Funnel all mutable state under the single writable tmpfs (/run/secrets) and
# stop CPython writing .pyc into the read-only editable source trees.
# (agentcontainer.json overrides VHIR_AUDIT_DIR/VHIR_CASE_DIR at runtime to the
# bind-mounted case dir; these are defaults for a bare `docker run`.)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/run/secrets \
    TMPDIR=/run/secrets/tmp \
    VHIR_CASE_DIR=/run/secrets/case \
    VHIR_CASES_DIR=/run/secrets/cases \
    VHIR_AUDIT_DIR=/run/secrets/audit \
    VHIR_ACTIVE_CASE="" \
    VHIR_EXAMINER=agentcontainer

EXPOSE 4508
ENTRYPOINT ["/usr/local/bin/sift-entrypoint"]
