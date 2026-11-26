#!/usr/bin/env python3
"""VELFORT Phase 0.6 configuration guard for the Tauri spike (D-P4, D-P13, SR-UI-1/3/5/6, SR-IPC-1, SR-DIST-1).

Usage:
  check_config.py <src-tauri dir>              -> exit 0 if all rules pass, 1 otherwise
  check_config.py --selftest <src-tauri dir>   -> mutates temporary copies and requires every
                                                  mutation to be detected (guards the guard)
Standard library only.
"""
import copy
import json
import pathlib
import re
import shutil
import sys
import tempfile

ALLOWED_PERMISSIONS_PREFIX = "allow-spike-"


def load(d: pathlib.Path):
    conf = json.loads((d / "tauri.conf.json").read_text(encoding="utf-8"))
    caps = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted((d / "capabilities").glob("*.json"))}
    build_rs = (d / "build.rs").read_text(encoding="utf-8")
    cargo = (d / "Cargo.toml").read_text(encoding="utf-8")
    return conf, caps, build_rs, cargo


def check(d: pathlib.Path):
    errors = []
    conf, caps, build_rs, cargo = load(d)
    app = conf.get("app", {})
    sec = app.get("security", {})

    # D-P13 / SR-UI-6
    if app.get("withGlobalTauri", False) is not False:
        errors.append("app.withGlobalTauri must be false or absent")
    # D-P4 / SR-UI-5 (key name verified in tauri-utils 2.10.4 config.rs: general_autofill_enabled, camelCase)
    for w in app.get("windows", []):
        if w.get("generalAutofillEnabled", True) is not False:
            errors.append(f"window {w.get('label')!r}: generalAutofillEnabled must be false")
        url = w.get("url")
        if url and re.match(r"^[a-z]+://", url) and not url.startswith("tauri://"):
            errors.append(f"window {w.get('label')!r}: remote url {url!r}")
        if w.get("devtools") is True:
            errors.append(f"window {w.get('label')!r}: devtools enabled")
    # SR-UI-1 CSP
    csp = sec.get("csp")
    if not isinstance(csp, str) or not csp:
        errors.append("app.security.csp must be a non-empty string")
    else:
        if "unsafe-eval" in csp or "unsafe-inline" in csp:
            errors.append("CSP must not contain unsafe-eval / unsafe-inline")
        for tok in re.findall(r"https?://[^\s;]+", csp):
            if tok != "http://ipc.localhost":
                errors.append(f"CSP allows remote origin {tok}")
        if "default-src 'self'" not in csp:
            errors.append("CSP must have default-src 'self'")
    if sec.get("dangerousDisableAssetCspModification"):
        errors.append("dangerousDisableAssetCspModification must not be set")
    if sec.get("pattern", {}).get("use") != "isolation":
        errors.append("isolation pattern must be enabled")
    # SR-IPC-1 capabilities
    if set(caps) != {"main.json"}:
        errors.append(f"exactly one capability file expected, found {sorted(caps)}")
    granted = set()
    for name, c in caps.items():
        if c.get("windows") != ["main"]:
            errors.append(f"{name}: capability must target only window 'main'")
        if c.get("remote"):
            errors.append(f"{name}: remote capability not allowed")
        for p in c.get("permissions", []):
            pid = p if isinstance(p, str) else p.get("identifier", "")
            if not pid.startswith(ALLOWED_PERMISSIONS_PREFIX):
                errors.append(f"{name}: permission {pid!r} not allowed (core/plugin permissions are forbidden)")
            granted.add(pid)
    m = re.search(r"commands\(&\[(.*?)\]\)", build_rs, re.S)
    manifest = set(re.findall(r'"([a-z_]+)"', m.group(1))) if m else set()
    expected = {"allow-" + c.replace("_", "-") for c in manifest}
    if granted != expected:
        errors.append(f"capability permissions {sorted(granted)} != AppManifest commands {sorted(expected)}")
    # SR-UI-3 no plugins
    for line in cargo.splitlines():
        if re.match(r"^\s*tauri-plugin-[a-z0-9-]+\s*=", line):
            errors.append(f"Tauri plugin dependency not allowed: {line.strip()}")
    if re.search(r'tauri\s*=\s*\{[^}]*"devtools"', cargo):
        errors.append("tauri 'devtools' feature must not be enabled")
    # SR-DIST-1
    if conf.get("bundle", {}).get("windows", {}).get("nsis", {}).get("installMode") != "perMachine":
        errors.append("bundle.windows.nsis.installMode must be perMachine")
    return errors


MUTATIONS = [
    ("withGlobalTauri true", lambda c, caps: c["app"].__setitem__("withGlobalTauri", True)),
    ("autofill true", lambda c, caps: c["app"]["windows"][0].__setitem__("generalAutofillEnabled", True)),
    ("autofill key removed", lambda c, caps: c["app"]["windows"][0].pop("generalAutofillEnabled")),
    ("unsafe-eval in CSP", lambda c, caps: c["app"]["security"].__setitem__("csp", c["app"]["security"]["csp"] + "; script-src 'self' 'unsafe-eval'")),
    ("remote origin in CSP", lambda c, caps: c["app"]["security"].__setitem__("csp", c["app"]["security"]["csp"] + " https://cdn.example.com")),
    ("CSP removed", lambda c, caps: c["app"]["security"].pop("csp")),
    ("isolation removed", lambda c, caps: c["app"]["security"].pop("pattern")),
    ("core:default granted", lambda c, caps: caps["main.json"]["permissions"].append("core:default")),
    ("fs plugin permission", lambda c, caps: caps["main.json"]["permissions"].append("fs:default")),
    ("capability for all windows", lambda c, caps: caps["main.json"].__setitem__("windows", ["*"])),
    ("perUser install", lambda c, caps: c["bundle"]["windows"]["nsis"].__setitem__("installMode", "currentUser")),
    ("remote url window", lambda c, caps: c["app"]["windows"][0].__setitem__("url", "https://example.com")),
]


def selftest(d: pathlib.Path):
    base = check(d)
    if base:
        print("SELFTEST precondition failed, baseline has errors:", base)
        return 1
    failed = 0
    for name, mut in MUTATIONS + [("plugin dependency", None), ("permission without manifest entry", None)]:
        with tempfile.TemporaryDirectory() as t:
            td = pathlib.Path(t) / "src-tauri"
            (td / "capabilities").mkdir(parents=True)
            for f in ("tauri.conf.json", "build.rs", "Cargo.toml"):
                shutil.copy(d / f, td / f)
            for f in (d / "capabilities").glob("*.json"):
                shutil.copy(f, td / "capabilities" / f.name)
            conf, caps, _, _ = load(td)
            conf, caps = copy.deepcopy(conf), copy.deepcopy(caps)
            if mut:
                mut(conf, caps)
            elif name == "plugin dependency":
                (td / "Cargo.toml").write_text((td / "Cargo.toml").read_text() + '\n[dependencies.extra]\n', encoding="utf-8")
                with open(td / "Cargo.toml", "a", encoding="utf-8") as fh:
                    fh.write('tauri-plugin-shell = "2"\n')
            else:
                caps["main.json"]["permissions"].append("allow-spike-not-in-manifest")
            (td / "tauri.conf.json").write_text(json.dumps(conf), encoding="utf-8")
            for n, c in caps.items():
                (td / "capabilities" / n).write_text(json.dumps(c), encoding="utf-8")
            errs = check(td)
            ok = bool(errs)
            failed += 0 if ok else 1
            print(f"SELFTEST {'PASS' if ok else 'FAIL'} mutation detected: {name}" + ("" if ok else " (NOT detected)"))
    return 1 if failed else 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--selftest":
        sys.exit(selftest(pathlib.Path(sys.argv[2])))
    d = pathlib.Path(sys.argv[1])
    errs = check(d)
    for e in errs:
        print("CONFIG FAIL:", e)
    print("CONFIG", "PASS" if not errs else f"FAIL ({len(errs)} errors)")
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
