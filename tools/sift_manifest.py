#!/usr/bin/env python3
"""Seed a forensic-tool catalog from the authoritative SIFT install manifest.

This script is the *source of truth* bridge between what SIFT Workstation
actually installs (the teamdfir/sift-saltstack salt states) and what our
run_command catalog + forensic-knowledge (FK) package already cover.

It is READ-ONLY with respect to policy/enforcement/catalog code: it only reads
the salt states and our YAML data, and writes two artifacts next to itself.

Pipeline
--------
1. Resolve the SERVER image's state set by following ``include-server.sls``
   (repos + packages + python3-packages + scripts). The hackathon image is
   SIFT *server*, so we prefer that set and tag anything desktop-only.
2. Parse each leaf ``.sls`` for install actions:
     packages/*           -> apt   (pkg.installed / pkg.latest)
     python3-packages/*   -> pip   (pip.installed, console scripts symlinked)
     perl-packages/*      -> perl  (cpan / make install)
     scripts/*            -> manual (downloads, git, EZ Tools, wrappers)
   The strongest command signal is any ``/usr/local/bin/<name>`` file target:
   that is SIFT's convention for putting a command on $PATH, and it is read
   verbatim rather than guessed.
3. Resolve packages -> COMMAND names (argv[0] for run_command). We need command
   names, not apt package names, and one package may ship many commands. We
   ground-truth from ``dpkg -L`` (live ``--dpkg-host`` or the committed overlay
   ``sift_dpkg_groundtruth.json``); where neither knows a package we fall back
   to a curated RESOLUTION_MAP, and only as a last resort infer the command from
   the package name (``inferred: true`` -> needs_review).
4. Apply the noise filter (dev headers, runtime libs, build tooling, desktop
   apps) and scope tags (offline / network_offline / live_network).
5. Diff every resolved command against our catalog + FK:
     A  in our catalog AND FK-enriched
     B  FK knowledge exists but no catalog entry   (enrichment win)
     C  neither (long tail, runnable via run_command, just unenriched)
   The denylist is respected: a denied binary is never emitted as available.
6. Write ``sift_manifest.json`` and ``coverage.md``; print a console summary.

Usage
-----
    python tools/sift_manifest.py                 # uses committed ground truth
    python tools/sift_manifest.py --dpkg-host sansforensics@192.168.8.129
    python tools/sift_manifest.py --refresh-ground-truth --dpkg-host <host>

Re-runnable and idempotent: same inputs -> same outputs.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml (or run inside the repo venv)")

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CATALOG_DIR = REPO_ROOT / "packages/sift-mcp/data/catalog"
FK_TOOLS_DIR = REPO_ROOT / "packages/forensic-knowledge/data/tools"
SECURITY_YAML = CATALOG_DIR / "security.yaml"
GROUND_TRUTH = SCRIPT_DIR / "sift_dpkg_groundtruth.json"
# Runtime copy the MCP server loads (sift_mcp.manifest); keep in sync with the
# dev artifact in tools/. Same 8-field schema.
PACKAGE_MANIFEST = REPO_ROOT / "packages/sift-mcp/data/manifest/sift_manifest.json"
DEFAULT_SALTSTACK = Path("/tmp/sift-saltstack")
SALTSTACK_URL = "https://github.com/teamdfir/sift-saltstack.git"

# --------------------------------------------------------------------------- #
# Curated package -> command resolution (fallback when dpkg can't ground it).
# Read from the .sls header "Notes:" lines and upstream docs; libyal lib*-tools
# packages are KEPT because they ship CLI binaries. Only used when ground truth
# (dpkg -L) does not cover the package; entries resolved this way are marked
# inferred:true unless ground truth confirms them.
# --------------------------------------------------------------------------- #
RESOLUTION_MAP: dict[str, list[str]] = {
    # libyal CLI tool packages -------------------------------------------------
    "libesedb-tools": ["esedbexport", "esedbinfo"],
    "libregf-tools": ["regfexport", "regfinfo", "regfmount"],
    "libevtx-tools": ["evtxexport", "evtxinfo"],
    "libevt-tools": ["evtexport", "evtinfo"],
    "libvshadow-tools": ["vshadowinfo", "vshadowmount"],
    "libbde-tools": ["bdeinfo", "bdemount"],
    "libfvde-tools": ["fvdeinfo", "fvdemount"],
    "libfsapfs-tools": ["fsapfsinfo", "fsapfsmount"],
    "libewf-tools": ["ewfacquire", "ewfexport", "ewfinfo", "ewfverify", "ewfmount"],
    "ewf-tools": ["ewfacquire", "ewfexport", "ewfinfo", "ewfverify", "ewfmount"],
    "pff-tools": ["pffexport", "pffinfo"],
    "libplist-utils": ["plistutil"],
    # multi-binary forensic suites --------------------------------------------
    "sleuthkit": [
        "fls",
        "mmls",
        "icat",
        "istat",
        "blkls",
        "blkcat",
        "blkstat",
        "blkcalc",
        "fsstat",
        "ils",
        "ffind",
        "ifind",
        "fcat",
        "jcat",
        "jls",
        "img_stat",
        "img_cat",
        "mactime",
        "tsk_recover",
        "tsk_gettimes",
        "tsk_loaddb",
        "tsk_comparedir",
        "sigfind",
        "sorter",
        "hfind",
        "usnjls",
        "srch_strings",
    ],
    "plaso-tools": [
        "log2timeline.py",
        "psort.py",
        "pinfo.py",
        "psteal.py",
        "image_export.py",
    ],
    "python3-plaso": [
        "log2timeline.py",
        "psort.py",
        "pinfo.py",
        "psteal.py",
        "image_export.py",
    ],
    "bulk-extractor": ["bulk_extractor"],
    "afflib-tools": [
        "affcat",
        "affconvert",
        "affcopy",
        "affinfo",
        "affverify",
        "affuse",
    ],
    "pst-utils": ["readpst", "lspst", "pst2ldif", "pst2dii"],
    "hashdeep": ["hashdeep", "md5deep", "sha1deep", "sha256deep"],
    "ntfs-3g": [
        "ntfscat",
        "ntfsls",
        "ntfsinfo",
        "ntfscluster",
        "ntfsundelete",
        "ntfsfix",
    ],
    "qemu-utils": ["qemu-img", "qemu-nbd"],
    "nfdump": ["nfdump", "nfcapd", "nfanon"],
    "testdisk": ["testdisk", "photorec", "fidentify"],
    "radare2": ["r2", "rabin2", "radare2", "rafind2", "rahash2", "rax2"],
    "gddrescue": ["ddrescue", "ddrescuelog"],
    # single-command packages whose binary != package name --------------------
    "silversearcher-ag": ["ag"],
    "netcat-openbsd": ["nc"],
    "upx-ucl": ["upx"],
    "p7zip-full": ["7z", "7za"],
    "exif": ["exif"],
    "dos2unix": ["dos2unix", "unix2dos"],
    "wireshark": ["tshark", "dumpcap", "editcap", "mergecap", "capinfos"],
}

# Commands installed by an .sls but NOT via a /usr/local/bin symlink (e.g.
# exiftool's `make install` lands in the perl tree / /usr/bin). Keyed by leaf
# stem so they are still captured. Treated as ground-truth command names.
SLS_EXTRA_COMMANDS: dict[str, list[str]] = {
    "exiftool": ["exiftool"],
}

# --------------------------------------------------------------------------- #
# Noise filter: never forensic *commands*. Exact package names + name patterns.
# --------------------------------------------------------------------------- #
NOISE_PACKAGES = {
    # build tooling
    "build-essential",
    "gcc",
    "g++",
    "swig",
    "flex",
    "pkg-config",
    "patch",
    "cpanminus",
    "make",
    # python build/runtime deps
    "python3-pip",
    "python3-setuptools",
    "python3-setuptools-rust",
    "python3-wheel",
    "python3-virtualenv",
    "python3-dev",
    "python3-tk",
    "python3-pyqt5",
    "python3-wxgtk4.0",
    "python3-m2crypto",
    "python3-keyrings.alt",
    "python3-redis",
    "python3-xlsxwriter",
    "python3",
    "python-is-python3",
    "ipython3",
    "python3-keyring",
    # generic runtimes / JVM / .NET host
    "default-jre",
    "openjdk-8-jdk",
    "openjdk",
    "libbcprov-java",
    "libcommons-lang3-java",
    "dotnet-sdk-9.0",
    "dotnet",
    "powershell",
    "perl",
    "tcl",
    "blt",
    # desktop / system apps (not evidence analysis)
    "chromium-browser",
    "wine",
    "wine-stable",
    "unity-control-center",
    "onboard",
    "orca",
    "okular",
    "feh",
    "gthumb",
    "transmission",
    "samba",
    "winbind",
    "docker",
    "docker-ce",
    "qemu",
    "qemu-system",
    "lvm2",
    "mdadm",
    "apache2",
    "virtuoso-minimal",
    "phonon",
    "phonon4qt5",
    "zenity",
    "dbus-x11",
    "xdot",
    "magnus",
    "bless",
    "ghex",
    "kdiff3",
    "vim",
    "hexedit",
    "htop",
    "git",
    "curl",
    "vbindiff",
    "graphviz",
    "dconf-cli",
    "software-properties-common",
    "android-sdk-platform-tools",
    "aws-cli",
    "claude-code",
    "at",
    "net-tools",
    "open-iscsi",
    "nbd-client",
    "cifs-utils",
    "exfat-extras",
    "e2fsprogs",
    "xfsprogs",
    "squashfs-tools",
    "cryptsetup",
    "ntfs-3g",  # ntfs-3g: mount helpers; kept via map only for read tools
}
NOISE_PATTERNS = [
    re.compile(r"-dev$"),  # headers
    re.compile(r"-perl$"),  # perl library modules
    re.compile(r"^libgtk"),
    re.compile(r"^libcairo"),
    re.compile(r"^libgirepository"),
    re.compile(r"^libssl"),
    re.compile(r"^libbz2"),
    re.compile(r"^libffi"),
    re.compile(r"^libxml2"),
    re.compile(r"^libxslt"),
    re.compile(r"^libncurses"),
    re.compile(r"^libasound"),
    re.compile(r"^libpcap"),
    re.compile(r"^libnet1"),
    re.compile(r"^libglib"),
    re.compile(r"^libicu"),
    re.compile(r"^zlib"),
    re.compile(r"^libext2fs"),
    re.compile(r"^libfuse"),
]
# Pure library packages (no CLI we want) that don't match the patterns above.
NOISE_LIBS = {
    "libafflib",
    "libbde",
    "libesedb",
    "libevt",
    "libevtx",
    "libewf",
    "libewf2",
    "libewf-python3",
    "libfvde",
    "libmsiecf",
    "libolecf",
    "libpff",
    "libregf",
    "libregf-python3",
    "libvshadow",
    "libvshadow-python3",
    "libvmdk",
    "libvhdi",
    "liblightgrep",
    "libyara3",
    "python3-yara",
    "python3-pypff",
    "python3-pytsk3",
    "python3-tsk",
    "pytsk3",
    "python3-dfvfs",
    "python3-fuse",
    "python3-debian",
    "python3-magic",
    "python3-pefile",
    "libdatetime-perl",
    "libencode-perl",
    "libtext-csv-perl",
    "libparse-win32registry-perl",
}


def is_noise(pkg: str) -> bool:
    if pkg in NOISE_PACKAGES or pkg in NOISE_LIBS:
        return True
    return any(p.search(pkg) for p in NOISE_PATTERNS)


# --------------------------------------------------------------------------- #
# Scope tagging: default offline; these are the exceptions.
# --------------------------------------------------------------------------- #
NETWORK_OFFLINE = {  # parse captures from disk; safe under --unshare-net
    "tcpflow",
    "tcptrace",
    "ngrep",
    "nfdump",
    "nfcapd",
    "nfanon",
    "tcpxtract",
    "tcpick",
    "tcpstat",
    "tcpprof",
    "tcpslice",
    "tcptrack",
    "tcpreplay",
    "ssldump",
    "p0f",
}
LIVE_NETWORK = {  # need live network; out of scope for evidence analysis
    "hydra",
    "nikto",
    "aircrack-ng",
    "ettercap",
    "dsniff",
    "driftnet",
    "arp-scan",
    "nbtscan",
    "netwox",
    "sslsniff",
    "etherape",
    "netsed",
}


def scope_for(command: str, pkg: str) -> str:
    if command in LIVE_NETWORK or pkg in LIVE_NETWORK:
        return "live_network"
    if command in NETWORK_OFFLINE or pkg in NETWORK_OFFLINE:
        return "network_offline"
    return "offline"


# --------------------------------------------------------------------------- #
# salt-state parsing
# --------------------------------------------------------------------------- #
INSTALL_SOURCE = {
    "packages": "apt",
    "python3-packages": "pip",
    "perl-packages": "perl",
    "scripts": "manual",
}
JINJA_LIST_RE = re.compile(r"\{%\s*set\s+(\w+)\s*=\s*\[(.*?)\]\s*-?%\}", re.DOTALL)
JINJA_FOR_RE = re.compile(r"\{%-?\s*for\s+(\w+)\s+in\s+(\w+)\s*-?%\}")
USRBIN_LITERAL_RE = re.compile(r"/usr/local/bin/([A-Za-z0-9][A-Za-z0-9._+-]*)")
USRBIN_TMPL_RE = re.compile(r"/usr/local/bin/\{\{\s*(\w+)(\|lower)?\s*\}\}")
PKG_NAME_RE = re.compile(r"^\s*-\s*name:\s*([^\s#{].*?)\s*$")
PKG_STATE_RE = re.compile(r"pkg\.(installed|latest)")
TOP_ID_RE = re.compile(r"^([A-Za-z0-9][^:]*):\s*$")


def follow_includes(start: Path, sift_dir: Path, seen: set[Path]) -> set[Path]:
    """Recursively resolve ``include:`` lists to concrete .sls leaf files."""
    if start in seen or not start.exists():
        return seen
    seen.add(start)
    text = start.read_text(errors="replace")
    in_include = False
    for line in text.splitlines():
        if re.match(r"^include:\s*$", line):
            in_include = True
            continue
        if in_include:
            m = re.match(r"^\s*-\s*(sift[.\w-]+)\s*$", line)
            if m:
                dotted = m.group(1)
                # sift.packages.foo -> packages/foo.sls ; sift.packages -> packages/init.sls
                rel = dotted[len("sift.") :].replace(".", "/")
                cand = sift_dir / f"{rel}.sls"
                if not cand.exists():
                    cand = sift_dir / rel / "init.sls"
                follow_includes(cand, sift_dir, seen)
            elif line.strip() and not line.startswith(" "):
                in_include = False
    return seen


def parse_jinja_lists(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, body in JINJA_LIST_RE.findall(text):
        items = re.findall(r"'([^']+)'|\"([^\"]+)\"", body)
        flat = [a or b for a, b in items]
        # tuple-of-(folder, [files]) suites (e.g. 4n6) produce folder names too;
        # we only keep tokens that look like command/script files.
        out[name] = flat
    return out


def commands_from_usrbin(text: str, jinja: dict[str, list[str]]) -> set[str]:
    # literal targets; drop fragments left when a `{{ var }}` was truncated
    # (e.g. `/usr/local/bin/densityscout-build-{{ build }}` -> `densityscout-build-`)
    cmds: set[str] = {
        c
        for c in USRBIN_LITERAL_RE.findall(text)
        if "{" not in c and not c.endswith(("-", "_", "."))
    }
    # map Jinja loop variable -> the list it iterates (e.g. `for file in files`)
    loopvar = {var: lst for var, lst in JINJA_FOR_RE.findall(text)}
    for var, lower in USRBIN_TMPL_RE.findall(text):
        lst = jinja.get(loopvar.get(var, var), [])
        for item in lst:
            if "." in item and item.split(".")[-1] not in ("py", "pl", "sh"):
                continue  # skip non-script tokens (e.g. stray .txt/.def)
            cmds.add(item.lower() if lower else item)
            if lower:
                cmds.add(item)  # SIFT symlinks both original-case and lower
    return cmds


def parse_sls(path: Path):
    """Return (apt_packages, usrbin_commands) for one leaf .sls."""
    text = path.read_text(errors="replace")
    jinja = parse_jinja_lists(text)
    apt: set[str] = set()
    if path.parent.name == "packages":
        # Collect apt package names from pkg.installed / pkg.latest states.
        # A package name comes from an explicit `- name:` (or `pkgs:` list); if a
        # pkg state declares neither, salt uses the state ID as the name
        # (e.g. `testdisk:\n  pkg.installed`), so we fall back to that ID.
        current_id = None  # last top-level state declaration id
        pkg_blocks: list[list] = []  # [state_id, got_explicit_name]
        in_pkg_block = False
        in_list = None  # "pkgs" | "sources" | None
        for line in text.splitlines():
            top = TOP_ID_RE.match(line)
            if top:
                current_id = top.group(1).strip()
                in_pkg_block = False
                in_list = None
            if PKG_STATE_RE.search(line):
                in_pkg_block = True
                pkg_blocks.append([current_id, False])
                continue
            if not in_pkg_block:
                continue
            if re.search(r"\bpkgs:\s*$", line):
                in_list = "pkgs"
                continue
            if re.search(r"\bsources:\s*$", line):
                in_list = "sources"
                continue
            m = PKG_NAME_RE.match(line)
            if m and "{" not in m.group(1) and "/" not in m.group(1):
                val = m.group(1).strip().strip("'\"")
                if " " not in val:  # skip the CPAN one-liner etc.
                    apt.add(val)
                    pkg_blocks[-1][1] = True
                in_list = None
            elif in_list == "pkgs":
                mp = re.match(r"^\s*-\s*([A-Za-z0-9][A-Za-z0-9._+-]*)\s*$", line)
                if mp:
                    apt.add(mp.group(1))
                    pkg_blocks[-1][1] = True
                else:
                    in_list = None
            elif in_list == "sources":
                # `- pkgname: /path/to/file.deb` -> pkgname is the apt name
                ms = re.match(r"^\s*-\s*([A-Za-z0-9][A-Za-z0-9._+-]*):\s*\S", line)
                if ms:
                    apt.add(ms.group(1))
                    pkg_blocks[-1][1] = True
                else:
                    in_list = None
        # pkg states that named nothing -> the state ID is the package name,
        # but only for the bare `<pkg>:` form (SIFT prefixes real state decls
        # with `sift-`, which are never package names).
        for state_id, named in pkg_blocks:
            if (
                not named
                and state_id
                and "{" not in state_id
                and not state_id.startswith("sift-")
            ):
                apt.add(state_id)
    return apt, commands_from_usrbin(text, jinja)


# --------------------------------------------------------------------------- #
# ground truth (dpkg -L)
# --------------------------------------------------------------------------- #
def load_ground_truth(path: Path) -> dict[str, dict]:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def refresh_ground_truth(host: str, packages: list[str], out: Path) -> dict[str, dict]:
    """SSH to a live SIFT box and record dpkg -L binaries per package."""
    remote = (
        "python3 - <<'PY'\n"
        "import subprocess,json,os\n"
        f"pkgs={json.dumps(sorted(packages))}\n"
        "o={}\n"
        "for p in pkgs:\n"
        "    if subprocess.run(['dpkg','-s',p],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:\n"
        "        o[p]={'installed':False,'binaries':[]};continue\n"
        "    f=subprocess.run(['dpkg','-L',p],capture_output=True,text=True).stdout.splitlines()\n"
        "    b=sorted({os.path.basename(x) for x in f if ('/bin/' in x or '/sbin/' in x) and os.path.basename(x)})\n"
        "    o[p]={'installed':True,'binaries':b}\n"
        "print(json.dumps(o,indent=2))\nPY"
    )
    res = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, remote],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        sys.exit(f"ground-truth refresh failed: {res.stderr.strip()}")
    data = json.loads(res.stdout)
    out.write_text(json.dumps(data, indent=2) + "\n")
    print(f"  wrote ground truth for {len(data)} packages -> {out}")
    return data


# --------------------------------------------------------------------------- #
# our catalog + forensic-knowledge
# --------------------------------------------------------------------------- #
def load_catalog():
    """Return (binary->fk_tool_name|None, set_of_catalog_binaries)."""
    bin_to_fk: dict[str, str | None] = {}
    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        if yml.name == "security.yaml":
            continue
        data = yaml.safe_load(yml.read_text()) or {}
        for tool in data.get("tools", []):
            binary = tool.get("binary") or tool.get("name")
            if binary:
                bin_to_fk[binary] = tool.get("fk_tool_name")
    return bin_to_fk, set(bin_to_fk)


def load_fk_index():
    """Map normalized command keys -> FK tool name (for B-bucket detection)."""
    index: dict[str, str] = {}
    names: list[str] = []
    for yml in sorted(FK_TOOLS_DIR.rglob("*.yaml")):
        if "/mcp/" in yml.as_posix():
            continue  # internal MCP tools, not run_command binaries
        data = yaml.safe_load(yml.read_text()) or {}
        name = data.get("name")
        if not name:
            continue
        names.append(name)
        for key in _norm_keys(name):
            index.setdefault(key, name)
        index.setdefault(yml.stem.lower(), name)
    # curated aliases: FK tool <- the SIFT command that exercises it
    for cmd, fk in FK_ALIASES.items():
        index[_norm(cmd)] = fk
    return index, names


FK_ALIASES = {
    "rip.pl": "RegRipper",
    "log2timeline.py": "Plaso (log2timeline)",
    "psort.py": "psort",
    "vol": "Volatility 3",
    "hindsight.py": "hindsight",
    "photorec": "photorec",
    "densityscout": "densityscout",
    "exiftool": "ExifTool",
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _norm_keys(name: str) -> set[str]:
    base = name.lower()
    keys = {base, _norm(base)}
    keys.add(base.split("(")[0].strip())  # "plaso (log2timeline)" -> "plaso"
    keys.add(_norm(base.split("(")[0]))
    return {k for k in keys if k}


def fk_lookup(command: str, fk_index: dict[str, str]) -> str | None:
    for cand in (command, command.rsplit(".", 1)[0]):  # strip .py/.pl
        for key in (cand.lower(), _norm(cand)):
            if key in fk_index:
                return fk_index[key]
    return None


def load_denylist() -> set[str]:
    data = yaml.safe_load(SECURITY_YAML.read_text()) or {}
    return set(data.get("denied_binaries", []))


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def ensure_saltstack(path: Path) -> Path:
    sift = path / "sift"
    if sift.exists():
        return sift
    print(f"  cloning {SALTSTACK_URL} -> {path}")
    subprocess.run(
        ["git", "clone", "--depth", "1", SALTSTACK_URL, str(path)], check=True
    )
    return sift


def build_manifest(args) -> tuple[list[dict], dict]:
    sift = ensure_saltstack(args.saltstack_dir)

    # 1. server image state set
    server_set = follow_includes(sift / "include-server.sls", sift, set())
    leaves = sorted(
        p
        for p in server_set
        if p.parent.name in INSTALL_SOURCE and p.name != "init.sls"
    )

    # 2. parse states -> apt packages + /usr/local/bin commands (per source)
    apt_packages: set[str] = set()
    usrbin_cmds: dict[
        str, tuple[str, str]
    ] = {}  # command -> (install_source, sls stem)
    for leaf in leaves:
        src = INSTALL_SOURCE[leaf.parent.name]
        apt, cmds = parse_sls(leaf)
        apt_packages.update(apt)
        for c in list(cmds) + SLS_EXTRA_COMMANDS.get(leaf.stem, []):
            usrbin_cmds.setdefault(c, (src, leaf.stem))

    # 3. ground truth
    gt = load_ground_truth(args.ground_truth)
    if args.refresh_ground_truth or args.dpkg_host:
        gt = refresh_ground_truth(
            args.dpkg_host, sorted(apt_packages), args.ground_truth
        )

    denylist = load_denylist()
    bin_to_fk, catalog_bins = load_catalog()
    catalog_lower = {b.lower(): b for b in catalog_bins}
    fk_index, fk_names = load_fk_index()

    # 4. resolve apt packages -> commands
    records: list[dict] = []
    seen_lower: set[str] = set()
    needs_review: list[str] = []

    def emit(command, package, source, siblings, inferred):
        # case-insensitive dedup: SIFT symlinks EZ Tools as both `MFTECmd` and
        # `mftecmd`; keep one entry (the first, which matches catalog casing).
        if command in denylist or command.lower() in seen_lower:
            return
        seen_lower.add(command.lower())
        canon = catalog_lower.get(command.lower())
        in_catalog = canon is not None
        fk_name = None
        if in_catalog and bin_to_fk.get(canon):
            fk_name = bin_to_fk[canon]
        if fk_name is None:
            fk_name = fk_lookup(command, fk_index)
        fk_covered = fk_name is not None
        bucket = "A" if (in_catalog and fk_covered) else "B" if fk_covered else "C"
        rec = {
            "command": command,
            "package": package,
            "install_source": source,
            "source_category": _category(command, package, source),
            "analysis_scope": scope_for(command, package),
            "binaries": sorted(siblings),
            "inferred": inferred,
            "desktop_only": False,  # this repo's server set == full tool set
            "in_catalog": in_catalog,
            "fk_tool": fk_name,
            "bucket": bucket,
        }
        records.append(rec)
        if inferred:
            needs_review.append(command)

    for pkg in sorted(apt_packages):
        if is_noise(pkg):
            continue
        bins_gt = gt.get(pkg, {})
        if bins_gt.get("installed") and bins_gt.get("binaries"):
            cmds = [b for b in bins_gt["binaries"] if not _bin_is_noise(b)]
            inferred = False
        elif pkg in RESOLUTION_MAP:
            cmds = RESOLUTION_MAP[pkg]
            # ground-truth confirmation from a *sibling* lib package, if present
            inferred = not _confirmed_by_gt(cmds, gt)
        else:
            cmds = [pkg]  # last resort: assume command == package name
            inferred = True
        for c in cmds:
            emit(c, pkg, "apt", cmds, inferred)

    # 5. /usr/local/bin commands (pip / perl / manual) — these are ground-truth
    #    command names read straight from the salt file targets.
    for cmd, (src, stem) in sorted(usrbin_cmds.items()):
        emit(cmd, stem, src, [cmd], inferred=False)

    summary = {
        "leaves": len(leaves),
        "apt_packages": len(apt_packages),
        "fk_tools": len(fk_names),
        "catalog_binaries": len(catalog_bins),
        "needs_review": sorted(needs_review),
        "denylist": sorted(denylist),
    }
    return records, summary


# binaries that ship in -tools/suite packages but aren't analysis commands
_BIN_NOISE = re.compile(
    r"^(mkfs|mkntfs|mount\.|fsck|lowntfs|.*debug$|.*_test$|.*-config$|"
    r"r2agent|r2pm|r2r|rarun2|ravc2|ragg2|rasign2)"
)


def _bin_is_noise(b: str) -> bool:
    return bool(_BIN_NOISE.match(b))


def _confirmed_by_gt(cmds, gt) -> bool:
    allbins = {
        b for v in gt.values() if v.get("installed") for b in v.get("binaries", [])
    }
    return any(c in allbins for c in cmds)


def _category(command, package, source):
    return source if source in ("manual", "perl", "pip") else "apt"


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
def write_outputs(records, summary, out_dir: Path):
    records = sorted(records, key=lambda r: (r["bucket"], r["command"]))
    manifest = [
        {
            k: r[k]
            for k in (
                "command",
                "package",
                "install_source",
                "source_category",
                "analysis_scope",
                "binaries",
                "inferred",
                "desktop_only",
            )
        }
        for r in records
    ]
    manifest_json = json.dumps(manifest, indent=2) + "\n"
    (out_dir / "sift_manifest.json").write_text(manifest_json)
    # publish the runtime copy the MCP server loads
    PACKAGE_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    PACKAGE_MANIFEST.write_text(manifest_json)

    buckets = {"A": [], "B": [], "C": []}
    for r in records:
        buckets[r["bucket"]].append(r)
    total = len(records)
    fk_present = len(buckets["A"]) + len(buckets["B"])  # FK tools SIFT ships
    catalog_rate = 100 * len(buckets["A"]) // fk_present if fk_present else 0
    cataloged_unenriched = [r for r in buckets["C"] if r["in_catalog"]]

    lines = []
    lines.append("# SIFT manifest coverage\n")
    lines.append(
        "Generated by `tools/sift_manifest.py` from teamdfir/sift-saltstack "
        "(server image).\n"
    )
    lines.append(
        f"- **{total}** distinct forensic commands resolved from the SIFT server install.\n"
        f"- **{fk_present}** of them have forensic-knowledge (FK) enrichment available; "
        f"**{len(buckets['A'])}** are already wired into the run_command catalog "
        f"(**{catalog_rate}%** of FK-backed tools), **{len(buckets['B'])}** are not yet "
        f"(bucket B — the actionable enrichment wins).\n"
        f"- The remaining **{len(buckets['C'])}** are the long tail: runnable via "
        f"run_command today, just unenriched.\n"
    )
    lines.append("## Buckets\n")
    lines.append("| Bucket | Meaning | Count |")
    lines.append("|---|---|---|")
    lines.append(f"| A | in catalog **and** FK-enriched | {len(buckets['A'])} |")
    lines.append(
        f"| B | FK knowledge exists, **no catalog entry** (enrichment win) | {len(buckets['B'])} |"
    )
    lines.append(
        f"| C | neither — long tail, runnable via run_command | {len(buckets['C'])} |"
    )
    lines.append(
        f"|   | &nbsp;&nbsp;of which already in catalog but unenriched | {len(cataloged_unenriched)} |"
    )
    lines.append("")

    lines.append("## B — enrichment targets (FK exists, add a catalog entry)\n")
    if buckets["B"]:
        lines.append("| command | package | source | FK tool |")
        lines.append("|---|---|---|---|")
        for r in sorted(buckets["B"], key=lambda r: r["command"]):
            lines.append(
                f"| `{r['command']}` | {r['package']} | {r['install_source']} | {r['fk_tool']} |"
            )
    else:
        lines.append("_None — every FK tool present in SIFT is already cataloged._")
    lines.append("")

    lines.append("## A — covered (catalog + FK)\n")
    lines.append(
        ", ".join(
            f"`{r['command']}`"
            for r in sorted(buckets["A"], key=lambda r: r["command"])
        )
        or "_none_"
    )
    lines.append("")

    lines.append("## C — long tail (unenriched, runnable)\n")
    if cataloged_unenriched:
        lines.append(
            "Cataloged but no FK enrichment: "
            + ", ".join(
                f"`{r['command']}`"
                for r in sorted(cataloged_unenriched, key=lambda r: r["command"])
            )
        )
        lines.append("")
    lines.append("Not in catalog, no FK (sample of the long tail):")
    tail = [r for r in buckets["C"] if not r["in_catalog"]]
    lines.append(
        ", ".join(
            f"`{r['command']}`" for r in sorted(tail, key=lambda r: r["command"])[:80]
        )
    )
    lines.append("")

    if summary["needs_review"]:
        lines.append("## needs_review (inferred command names — not dpkg-confirmed)\n")
        lines.append(", ".join(f"`{c}`" for c in summary["needs_review"]))
        lines.append("")

    lines.append("## Notes\n")
    lines.append(
        "- The SIFT *server* image installs the full tool set; the desktop "
        "image adds only config, so `desktop_only` is `false` throughout."
    )
    lines.append(
        "- Command names are ground-truthed from `dpkg -L` on a live SIFT box "
        "where available; `inferred: true` marks names resolved from the "
        "curated map or package name and listed under needs_review."
    )
    lines.append(
        "- Denied binaries are never emitted: "
        + ", ".join(f"`{b}`" for b in summary["denylist"])
        + "."
    )
    (out_dir / "coverage.md").write_text("\n".join(lines) + "\n")
    return buckets, total, fk_present


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--saltstack-dir",
        type=Path,
        default=DEFAULT_SALTSTACK,
        help=f"sift-saltstack checkout (cloned if absent; default {DEFAULT_SALTSTACK})",
    )
    ap.add_argument(
        "--ground-truth",
        type=Path,
        default=GROUND_TRUTH,
        help="committed dpkg -L overlay JSON",
    )
    ap.add_argument(
        "--dpkg-host",
        default=None,
        help="ssh host (user@host) of a live SIFT box for dpkg grounding",
    )
    ap.add_argument(
        "--refresh-ground-truth",
        action="store_true",
        help="re-query --dpkg-host and overwrite the committed overlay",
    )
    ap.add_argument("--out-dir", type=Path, default=SCRIPT_DIR)
    args = ap.parse_args()

    print("Building SIFT manifest…")
    records, summary = build_manifest(args)
    buckets, total, _ = write_outputs(records, summary, args.out_dir)

    # console summary
    print(f"\n  leaf .sls parsed:    {summary['leaves']}")
    print(f"  apt packages seen:   {summary['apt_packages']}")
    print(f"  FK tools loaded:     {summary['fk_tools']}")
    print(f"  resolved commands:   {total}")
    fk_present = len(buckets["A"]) + len(buckets["B"])
    rate = 100 * len(buckets["A"]) // fk_present if fk_present else 0
    print(
        f"  FK tools in SIFT:    {fk_present}  ({len(buckets['A'])} cataloged = {rate}% FK-covered)"
    )
    print(
        f"  A / B / C:           {len(buckets['A'])} / {len(buckets['B'])} / {len(buckets['C'])}"
    )
    print(f"  needs_review:        {len(summary['needs_review'])}")
    top_b = sorted(buckets["B"], key=lambda r: r["command"])[:10]
    print("\n  Top B-bucket enrichment candidates (FK exists, not cataloged):")
    for r in top_b:
        print(f"    - {r['command']:<22} {r['fk_tool']}  [{r['package']}]")
    if not top_b:
        print("    (none)")
    print(
        f"\n  Wrote {args.out_dir / 'sift_manifest.json'} and {args.out_dir / 'coverage.md'}"
    )


if __name__ == "__main__":
    main()
