#!/usr/bin/env python3
"""
f3p - ADB-based triage for suspicious Android devices.

Copyright (C) 2026 Johnny Boero
Licensed under GNU GPL v3 or later.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Known malware signatures
#
# Sourced from public reports:
#   - Doctor Web (2025): Shibai campaign, pre-installed WhatsApp/Telegram trojans
#   - Malwarebytes (2020): Unimax U686CL Wireless Update / Settings trojans
#   - G DATA (2014-2019): Adups FOTA backdoor family
#   - Trustwave (2016): Adups OTA data exfiltration
#   - Palo Alto Networks (2014): Coolpad CoolReaper backdoor
#   - f3p case study 01 (2026): LUNA T10 / abfota / Redstone OTA rename
# ---------------------------------------------------------------------------

KNOWN_BAD_PACKAGES = {
    "com.wireless.update":          "Trojan.Dropper.Agent.UMX (Assurance Wireless UMX)",
    "com.adups.fota":               "Adups FOTA backdoor (data exfiltration, OTA hijack)",
    "com.adups.fota.sysoper":       "Adups FOTA sysoper backdoor",
    "com.rock.gota":                "Gota/Adups variant",
    "com.fw.upgrade.sysoper":       "Generic OTA backdoor variant",
    "com.android.cleanmaster":      "Cheetah Mobile adware (pre-installed variant)",
    "com.gmobi.trustpurchase":      "Gmobi trustpurchase tracker",
    "com.ckt.inst":                 "CKT installer (silent APK pusher)",
    "com.hawk.android":             "Hawk Adware SDK",
    "com.android.tservice":         "Known CN OEM silent service",
    "com.wps.xiaomi.abroad.lite":   "WPS bundled adware variant",
    "com.coolpad.deepsleep":        "Coolpad CoolReaper backdoor (Palo Alto 2014)",
    "com.redstone.ota.ui":          "Redstone OTA backdoor",
    "com.abfota.systemUpdate":      "Redstone OTA rebrand ('abfota', seen on LUNA T10 / WWT 26 Ultra)",
}

SUSPICIOUS_FRAGMENTS = [
    "adups", "gmobi", "yehua", "rockchip.ota",
    "silentinstaller", "superapk", "appstore.cn",
]

FOTA_BRAND_WHITELIST = {"google", "samsung", "motorola", "nothing",
                        "sony", "fairphone", "oneplus", "nokia"}

# Messengers pre-installed in system partition = Shibai pattern
SHIBAI_MESSENGER_TARGETS = {
    "com.whatsapp", "org.telegram.messenger", "org.telegram.messenger.web",
    "org.thoughtcrime.securesms", "com.tencent.mm",
    "com.discord", "com.viber.voip",
}

# Third-party apps knockoffs frequently bake into /vendor/app/
SHIBAI_BLOATWARE_TARGETS = {
    "com.facebook.katana", "com.facebook.orca", "com.instagram.android",
    "com.twitter.android",
    "com.zhiliaoapp.musically", "com.ss.android.ugc.aweme",
    "com.netflix.mediaclient",
    "com.amazon.mShop.android.shopping",
    "com.spotify.music",
}

SOC_MAP = {
    # --- MediaTek budget (commonly spoofed chips on knockoffs) ---
    "mt6580":  "MediaTek MT6580 (2015, 4x Cortex-A7 @ 1.3GHz, 28nm)",
    "mt6735":  "MediaTek MT6735 (2015, 4x Cortex-A53 @ 1.3GHz, 28nm)",
    "mt6737":  "MediaTek MT6737 (2016, 4x Cortex-A53 @ 1.25GHz, 28nm)",
    "mt6753":  "MediaTek MT6753 (2015, 8x Cortex-A53 @ 1.3GHz, 28nm)",
    "mt6761":  "MediaTek Helio A22 (2018, 4x Cortex-A53)",
    "mt6762":  "MediaTek Helio P22/A25 (2018, 8x Cortex-A53)",
    "mt6765":  "MediaTek Helio P35/G35 (2019, 8x Cortex-A53)",
    "mt6768":  "MediaTek Helio P65/G70 (2019)",
    "mt6769":  "MediaTek Helio G80/G85 (2020)",
    # --- MediaTek Dimensity (legitimate mid/high) ---
    "mt6833":  "MediaTek Dimensity 700 (2020)",
    "mt6853":  "MediaTek Dimensity 720/800U",
    "mt6855":  "MediaTek Dimensity 930/7050",
    "mt6877":  "MediaTek Dimensity 900/920",
    "mt6893":  "MediaTek Dimensity 1200",
    "mt6895":  "MediaTek Dimensity 8100",
    "mt6896":  "MediaTek Dimensity 8200",
    "mt6983":  "MediaTek Dimensity 9000",
    "mt6985":  "MediaTek Dimensity 9200",
    "mt6989":  "MediaTek Dimensity 9300 / 9400",
    # --- Unisoc ---
    "ums312":  "Unisoc T310 (2020, 1+3 A75/A55)",
    "ums512":  "Unisoc T618/T610 (2020, 8x A75/A55)",
    "ums9230": "Unisoc T606/T612 (2021)",
    "ums9620": "Unisoc T760/T820 (2023, 5G mid-range)",
    # --- Qualcomm Snapdragon (entry) ---
    "sm4250":  "Qualcomm Snapdragon 4-series",
    "sm4350":  "Qualcomm Snapdragon 480 (2021)",
    "sm4450":  "Qualcomm Snapdragon 4 Gen 2",
    # --- Qualcomm Snapdragon 6/7-series (mid) ---
    "sm6115":  "Qualcomm Snapdragon 662 (2020)",
    "sm6150":  "Qualcomm Snapdragon 675/730 (2019)",
    "sm6225":  "Qualcomm Snapdragon 680 (2021)",
    "sm6375":  "Qualcomm Snapdragon 695 5G (2022)",
    "sm6450":  "Qualcomm Snapdragon 6 Gen 1",
    "sm7125":  "Qualcomm Snapdragon 720G/730G",
    "sm7150":  "Qualcomm Snapdragon 730/730G",
    "sm7225":  "Qualcomm Snapdragon 750G",
    "sm7325":  "Qualcomm Snapdragon 778G",
    "sm7435":  "Qualcomm Snapdragon 7 Gen 1",
    "sm7550":  "Qualcomm Snapdragon 7 Gen 3",
    # --- Qualcomm Snapdragon 8-series flagship ---
    "sm8150":  "Qualcomm Snapdragon 855 (2019 flagship)",
    "sm8250":  "Qualcomm Snapdragon 865 (2020 flagship)",
    "sm8350":  "Qualcomm Snapdragon 888 (2021 flagship)",
    "sm8450":  "Qualcomm Snapdragon 8 Gen 1 (2022)",
    "sm8475":  "Qualcomm Snapdragon 8+ Gen 1",
    "sm8550":  "Qualcomm Snapdragon 8 Gen 2 (2023)",
    "sm8650":  "Qualcomm Snapdragon 8 Gen 3 (2024)",
    "sm8735":  "Qualcomm Snapdragon 8s Gen 4 (2025)",
    "sm8750":  "Qualcomm Snapdragon 8 Gen 4 / Elite",
    # --- Samsung Exynos ---
    "exynos850":  "Samsung Exynos 850",
    "exynos880":  "Samsung Exynos 880",
    "exynos980":  "Samsung Exynos 980",
    "exynos990":  "Samsung Exynos 990",
    "exynos1080": "Samsung Exynos 1080",
    "exynos1280": "Samsung Exynos 1280",
    "exynos1330": "Samsung Exynos 1330",
    "exynos1380": "Samsung Exynos 1380",
    "exynos1480": "Samsung Exynos 1480",
    "exynos2100": "Samsung Exynos 2100 (flagship)",
    "exynos2200": "Samsung Exynos 2200 (flagship)",
    "exynos2400": "Samsung Exynos 2400 (flagship)",
    # --- Samsung internal aliases ---
    "universal9820":  "Samsung Exynos 9820 (S10 family)",
    "universal9825":  "Samsung Exynos 9825 (Note 10)",
    "universal2100":  "Samsung Exynos 2100",
    "universal2200":  "Samsung Exynos 2200",
    "universal2400":  "Samsung Exynos 2400",
    # --- Google Tensor ---
    "gs101":   "Google Tensor G1 (Pixel 6)",
    "gs201":   "Google Tensor G2 (Pixel 7)",
    "zuma":    "Google Tensor G3 (Pixel 8)",
    "zumapro": "Google Tensor G4 (Pixel 9)",
    # --- HiSilicon Kirin (Huawei) ---
    "kirin710":  "HiSilicon Kirin 710",
    "kirin810":  "HiSilicon Kirin 810",
    "kirin820":  "HiSilicon Kirin 820 5G",
    "kirin970":  "HiSilicon Kirin 970",
    "kirin980":  "HiSilicon Kirin 980",
    "kirin985":  "HiSilicon Kirin 985 5G",
    "kirin990":  "HiSilicon Kirin 990",
    "kirin9000": "HiSilicon Kirin 9000",
    "kirin9010": "HiSilicon Kirin 9010",
    # --- Rockchip / Allwinner (tablets) ---
    "rk3326":  "Rockchip RK3326 (tablet SoC)",
    "rk3399":  "Rockchip RK3399 (tablet/SBC)",
    "rk3566":  "Rockchip RK3566",
    "rk3588":  "Rockchip RK3588",
    "a133":    "Allwinner A133 (budget tablet)",
    "a523":    "Allwinner A523",
}

PREMIUM_MARKETING = [
    "snapdragon 8", "dimensity 9", "exynos 2", "tensor g",
]

BUDGET_SOC_PREFIXES = ("mt6580", "mt6735", "mt6737", "mt6753",
                       "mt6761", "mt6762", "mt6765",
                       "ums312", "ums512", "ums9230",
                       "rk3326", "a133")

# Internal/marketing codenames used in ro.board.platform by various OEMs.
# Qualcomm in particular uses codenames (kalama=SM8550, taro=SM8450) instead
# of the chip ID. Map them back so legitimate flagships don't trigger
# "Could not identify SoC" false positives.
SOC_CODENAME_ALIASES = {
    # Qualcomm Snapdragon internal codenames
    "kona":       "sm8250",   # Snapdragon 865
    "lahaina":    "sm8350",   # Snapdragon 888
    "taro":       "sm8450",   # Snapdragon 8 Gen 1
    "ukee":       "sm8475",   # Snapdragon 8+ Gen 1
    "kalama":     "sm8550",   # Snapdragon 8 Gen 2
    "pineapple":  "sm8650",   # Snapdragon 8 Gen 3
    "sun":        "sm8750",   # Snapdragon 8 Gen 4
    "holi":       "sm7325",   # Snapdragon 778G
    "yupik":      "sm7325",   # Snapdragon 778G+
    "parrot":     "sm7450",   # Snapdragon 7 Gen 1
    "divar":      "sm7550",   # Snapdragon 7 Gen 3
    "lito":       "sm7150",   # Snapdragon 730/730G
    "bengal":     "sm6115",   # Snapdragon 662
    "khaje":      "sm6225",   # Snapdragon 680
    "blair":      "sm6375",   # Snapdragon 695
    # Samsung Exynos aliases
    "exynos9820": "exynos990",
    # Google Tensor (pixel board codenames vs soc codenames are different;
    # zuma and gs201 already in SOC_MAP directly)
}


# ---------------------------------------------------------------------------
# ADB wrapper
# ---------------------------------------------------------------------------

class ADBError(Exception):
    pass


class ADB:
    def __init__(self, serial=None):
        self.serial = serial
        if not shutil.which("adb"):
            raise ADBError("adb not found in PATH. Install android-tools.")

    def _args(self):
        a = ["adb"]
        if self.serial:
            a += ["-s", self.serial]
        return a

    def devices(self):
        out = subprocess.run(["adb", "devices"], capture_output=True,
                             text=True, timeout=10)
        devs = []
        for line in out.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                devs.append((parts[0], parts[1]))
        return devs

    def shell(self, cmd, timeout=30):
        try:
            r = subprocess.run(self._args() + ["shell", cmd],
                               capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            return r.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""

    def pull(self, remote, local, timeout=120):
        try:
            r = subprocess.run(self._args() + ["pull", remote, local],
                               capture_output=True, text=True, timeout=timeout)
            return r.returncode == 0, r.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "timeout"


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def getprop_all(adb):
    raw = adb.shell("getprop", timeout=15)
    props = {}
    for line in raw.splitlines():
        m = re.match(r"\[([^\]]+)\]:\s*\[(.*)\]$", line)
        if m:
            props[m.group(1)] = m.group(2)
    return props


def get_meminfo(adb):
    raw = adb.shell("cat /proc/meminfo", timeout=10)
    info = {}
    for line in raw.splitlines():
        parts = line.split(":", 1)
        if len(parts) == 2:
            info[parts[0].strip()] = parts[1].strip()
    return info


def get_cpuinfo(adb):
    return adb.shell("cat /proc/cpuinfo", timeout=10)


def get_storage(adb):
    return adb.shell("df -h", timeout=10)


def list_packages(adb):
    sys_raw = adb.shell("pm list packages -s -f", timeout=30)
    usr_raw = adb.shell("pm list packages -3 -f", timeout=30)

    def parse(raw):
        pkgs = []
        for line in raw.splitlines():
            m = re.match(r"package:(.+)=(.+)$", line.strip())
            if m:
                pkgs.append((m.group(2), m.group(1)))
        return pkgs
    return parse(sys_raw), parse(usr_raw)


def check_socket_stats(adb):
    for cmd in ["ss -tunap", "netstat -tunap", "cat /proc/net/tcp"]:
        out = adb.shell(cmd, timeout=10)
        if out and "not found" not in out.lower() and "no such" not in out.lower():
            return cmd, out
    return None, ""


def hash_system_apks(adb, outdir, limit=0, progress_cb=None):
    apks_dir = outdir / "system_apks"
    apks_dir.mkdir(exist_ok=True)
    sys_pkgs, _ = list_packages(adb)
    results = []
    total = len(sys_pkgs)
    for i, (pkg, path) in enumerate(sys_pkgs, 1):
        if limit and len(results) >= limit:
            break
        local = apks_dir / f"{pkg}.apk"
        ok, err = adb.pull(path, str(local), timeout=60)
        if ok and local.exists():
            h = hashlib.sha256(local.read_bytes()).hexdigest()
            results.append({
                "package": pkg, "path": path,
                "sha256": h, "size": local.stat().st_size,
            })
        else:
            results.append({"package": pkg, "path": path, "error": err})
        if progress_cb:
            progress_cb(i, total, pkg)
    return results


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _detect_soc(hw, board, platform_, boot_hw, cpuinfo):
    """Return (soc_id, real_name, mismatch_bool).

    Tries direct SOC_MAP matches first, then falls back to OEM codename
    aliases in SOC_CODENAME_ALIASES (e.g. 'kalama' -> 'sm8550').
    """
    from collections import Counter
    fields = [(f, v.lower()) for f, v in (
        ("ro.hardware", hw),
        ("ro.board.platform", platform_),
        ("ro.product.board", board),
        ("ro.boot.hardware", boot_hw),
    )]
    found = {}
    # Pass 1: direct SoC ID match
    for fname, fval in fields:
        for k in SOC_MAP:
            if k in fval:
                found[fname] = k
                break
    # Pass 2: codename alias resolution (only for fields that didn't match)
    for fname, fval in fields:
        if fname in found:
            continue
        for codename, soc_id in SOC_CODENAME_ALIASES.items():
            # Use word-boundary-ish match for codenames - they can be short
            # like "sun" or "taro" and we don't want to match in the middle
            # of longer strings
            if fval == codename or fval.startswith(codename + "_") or \
               fval.endswith("_" + codename) or ("_" + codename + "_") in fval:
                found[fname] = soc_id
                break
    if not found and cpuinfo:
        ci = cpuinfo.lower()
        for k in SOC_MAP:
            if k in ci:
                found["cpuinfo"] = k
                break
    if not found:
        return None, None, False
    counter = Counter(found.values())
    primary, _ = counter.most_common(1)[0]
    return primary, SOC_MAP[primary], len(set(found.values())) > 1


def analyze(props, meminfo, cpuinfo, packages_sys, packages_usr):
    findings = []

    hw         = props.get("ro.hardware", "")
    board      = props.get("ro.product.board", "")
    platform   = props.get("ro.board.platform", "")
    boot_hw    = props.get("ro.boot.hardware", "")
    model      = props.get("ro.product.model", "")
    brand      = props.get("ro.product.brand", "")
    manuf      = props.get("ro.product.manufacturer", "")
    name       = props.get("ro.product.name", "")
    marketname = (props.get("ro.product.marketname", "") or
                  props.get("ro.product.odm.marketname", "") or
                  props.get("ro.vendor.product.marketname", ""))

    # Android version mismatch
    sdk_int = props.get("ro.build.version.sdk", "0")
    rel     = props.get("ro.build.version.release", "?")
    try:
        sdk_num = int(sdk_int)
    except ValueError:
        sdk_num = 0
    sdk_release_map = {28: "9", 29: "10", 30: "11", 31: "12", 32: "12",
                       33: "13", 34: "14", 35: "15", 36: "16"}
    expected_rel = sdk_release_map.get(sdk_num)
    if expected_rel and rel != expected_rel and not rel.startswith(expected_rel + "."):
        findings.append(("HIGH",
            f"Android version mismatch: claims {rel} but SDK level is {sdk_int} "
            f"(expected Android {expected_rel}). Classic spoof pattern."))

    # Security patch age
    patch = props.get("ro.build.version.security_patch", "")
    if patch and len(patch) >= 7:
        try:
            py, pm = int(patch[:4]), int(patch[5:7])
            now = datetime.now()
            months_old = (now.year - py) * 12 + (now.month - pm)
            if months_old >= 24:
                findings.append(("HIGH",
                    f"Security patch level is {patch} ({months_old} months stale). "
                    f"Device is not receiving security updates."))
            elif months_old >= 12:
                findings.append(("WARN",
                    f"Security patch level is {patch} ({months_old} months stale)."))
        except ValueError:
            pass

    # Build-date vs security-patch (detects shipping-time build.date touch-ups)
    bd = props.get("ro.build.date", "")
    if bd and patch:
        ydm = re.search(r"\b(20\d{2})\b", bd)
        if ydm:
            by = int(ydm.group(1))
            try:
                py = int(patch[:4])
                if by - py >= 2:
                    findings.append(("WARN",
                        f"ro.build.date ({bd}) claims build year {by}, but "
                        f"security patch is from {py}. Build metadata was "
                        f"likely touched at shipping time, not a real rebuild."))
            except ValueError:
                pass

    # SoC detection with internal consistency check
    soc_id, real_soc, soc_mismatch = _detect_soc(hw, board, platform, boot_hw, cpuinfo)

    name_field = (marketname + " " + model + " " + name).lower()
    premium_claimed = (any(p in name_field or p in brand.lower()
                           for p in PREMIUM_MARKETING)
                       or "ultra" in name_field
                       or "pro max" in name_field)

    if soc_id:
        findings.append(("INFO", f"Detected SoC: {real_soc}"))
        if soc_mismatch:
            findings.append(("HIGH",
                f"Internal SoC identity is inconsistent across props: "
                f"ro.hardware='{hw}', ro.board.platform='{platform}', "
                f"ro.boot.hardware='{boot_hw}'. Different fields name different "
                f"chips - copy-paste ODM firmware, misidentified hardware, or "
                f"both."))
        if any(soc_id.startswith(pfx) for pfx in BUDGET_SOC_PREFIXES) and premium_claimed:
            findings.append(("CRITICAL",
                f"Budget SoC ({real_soc}) marketed as premium device "
                f"(model='{model}'). Hardware is spoofed."))
    else:
        findings.append(("WARN",
            f"Could not identify SoC from ro.hardware='{hw}' "
            f"ro.board.platform='{platform}'. Inspect cpuinfo manually."))

    fp = props.get("ro.build.fingerprint", "")

    # Product identity cross-field check
    # NOTE: legitimate OEMs (Google, Samsung) routinely have different
    # marketing models vs codenames (e.g. "Pixel 8" vs "shiba", "SM-S918U"
    # vs "dm3qsqw"). Only flag when the fingerprint also doesn't reference
    # either one - that's when it looks like an ODM-rebrand pattern.
    if model and name and fp:
        nm = name.lower()
        ml = model.lower()
        fpl = fp.lower()
        if (nm not in ml and ml not in nm and
                ml.replace(" ", "_") != nm and
                nm not in fpl and ml.replace(" ", "_") not in fpl and
                ml.replace(" ", "") not in fpl):
            findings.append(("WARN",
                f"Product identity inconsistent across props: "
                f"model='{model}', name='{name}', and fingerprint does not "
                f"reference either. Possible rebranding of an ODM reference "
                f"board."))

    # RAM
    mem_total_kb = 0
    mt = meminfo.get("MemTotal", "")
    m = re.match(r"(\d+)\s*kB", mt)
    if m:
        mem_total_kb = int(m.group(1))
    actual_ram_gb = mem_total_kb / 1024 / 1024
    findings.append(("INFO", f"Actual RAM (MemTotal): {actual_ram_gb:.2f} GB"))
    if actual_ram_gb and actual_ram_gb < 3.5 and any(
            tok in name_field for tok in ("12+", "16+", "12gb", "16gb",
                                          "8+256", "12+512", "16+1")):
        findings.append(("CRITICAL",
            f"RAM mismatch: device reports only {actual_ram_gb:.2f} GB "
            f"but marketing suggests much more."))

    heap = props.get("dalvik.vm.heapsize", "")
    if heap:
        findings.append(("INFO",
            f"dalvik.vm.heapsize = {heap} (scales with real RAM tier)"))

    # Fingerprint info + brand mismatch check
    if fp:
        findings.append(("INFO", f"Fingerprint: {fp}"))
        if (brand and manuf and
                brand.lower() not in fp.lower() and
                manuf.lower() not in fp.lower()):
            findings.append(("WARN",
                "Build fingerprint brand/manuf mismatch - repackaged firmware."))

    # SELinux
    selinux = (props.get("ro.boot.selinux", "") or
               props.get("ro.build.selinux", ""))
    if selinux.lower() in ("permissive", "disabled"):
        findings.append(("HIGH",
            f"SELinux is {selinux} - reduced sandboxing, often a sign of "
            f"lazy OEM builds."))

    # Verified boot
    vb = props.get("ro.boot.verifiedbootstate", "")
    if vb and vb.lower() != "green":
        findings.append(("WARN", f"Verified boot state: {vb}"))

    # Bootloader unlock reality check
    unlock_supp = props.get("ro.oem_unlock_supported", "")
    if unlock_supp == "0":
        findings.append(("INFO",
            "ro.oem_unlock_supported=0 - bootloader unlock is permanently "
            "disabled at build time. The Developer Options toggle, if present, "
            "is cosmetic."))
    elif unlock_supp == "1":
        findings.append(("INFO",
            "ro.oem_unlock_supported=1 - bootloader unlock is theoretically "
            "supported via fastboot flashing unlock (assuming a working USB "
            "data connection)."))
    else:
        findings.append(("INFO",
            "ro.oem_unlock_supported unset - unlock support unknown. The "
            "Developer Options toggle is probably cosmetic AOSP UI."))

    # Treble / GSI feasibility
    treble = props.get("ro.treble.enabled", "")
    if treble:
        findings.append(("INFO",
            f"ro.treble.enabled={treble} - GSI (Generic System Image) is "
            f"{'theoretically feasible' if treble == 'true' else 'not available'}."))

    # Known bad packages
    pkgnames = {p for p, _ in packages_sys} | {p for p, _ in packages_usr}
    for bad, desc in KNOWN_BAD_PACKAGES.items():
        if bad in pkgnames:
            findings.append(("CRITICAL",
                f"Known malicious/suspicious package: {bad} -- {desc}"))

    # Fuzzy fragments
    brand_l = brand.lower()
    placeholder_pkgs = []
    for pkg in pkgnames:
        pl = pkg.lower()
        if pkg in KNOWN_BAD_PACKAGES:
            continue
        # Generic Android Studio placeholder packages in production firmware
        # is an amateur-hour ROM build tell (seen e.g. on LUNA T10 with
        # com.example.switchbootanim). Catches any com.example.*.
        if pl.startswith("com.example."):
            placeholder_pkgs.append(pkg)
            continue
        for frag in SUSPICIOUS_FRAGMENTS:
            if frag in pl:
                findings.append(("WARN",
                    f"Suspicious package name contains '{frag}': {pkg}"))
                break
        if "fota" in pl and brand_l not in FOTA_BRAND_WHITELIST:
            findings.append(("WARN",
                f"FOTA package from non-whitelisted brand: {pkg}"))

    if placeholder_pkgs:
        findings.append(("WARN",
            f"{len(placeholder_pkgs)} Android Studio placeholder package(s) "
            f"(com.example.*) in system firmware: "
            f"{', '.join(placeholder_pkgs)}. Production ROMs should not ship "
            f"with default sample package names - indicates unprofessional "
            f"ROM engineering."))

    # Shibai pattern: messengers in /system or /vendor
    for pkg, path in packages_sys:
        if pkg in SHIBAI_MESSENGER_TARGETS:
            findings.append(("CRITICAL",
                f"{pkg} installed as a system-partition app ({path}). "
                f"This is the Shibai trojan pattern - messenger baked into "
                f"the system partition by the OEM/reseller. Compare APK "
                f"sha256 against official release hash before trusting."))

    # Third-party bloatware in vendor partition
    bloat_in_vendor = [(p, pa) for p, pa in packages_sys
                       if p in SHIBAI_BLOATWARE_TARGETS]
    if bloat_in_vendor:
        findings.append(("HIGH",
            f"{len(bloat_in_vendor)} third-party app(s) pre-installed in "
            f"system/vendor partition: " +
            ", ".join(p for p, _ in bloat_in_vendor) +
            ". These cannot be uninstalled without root and may be "
            f"modified/trojanized versions."))

    return findings


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "WARN": 2, "INFO": 3}
SEV_COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[0;31m",
             "WARN": "\033[0;33m", "INFO": "\033[0;36m"}


def extract_specs(props, meminfo, storage):
    """Return a dict of headline device specs for display.

    Pulls from getprop / /proc/meminfo / `df` output and groups by category.
    Values are always strings (never None) so the GUI can render directly.
    Unknown values are the literal string "—".
    """
    def _g(*keys):
        """First non-empty prop value from keys."""
        for k in keys:
            v = props.get(k, "")
            if v:
                return v
        return "—"

    # SoC
    soc_mfr = _g("ro.soc.manufacturer", "ro.hardware.chipname",
                 "ro.vendor.mediatek.platform")
    soc_model = _g("ro.soc.model", "ro.board.platform", "ro.hardware")
    soc_detected = None
    hw = props.get("ro.hardware", "")
    plat = props.get("ro.board.platform", "")
    board = props.get("ro.product.board", "")
    boot_hw = props.get("ro.boot.hardware", "")
    try:
        soc_id, soc_name, _ = _detect_soc(hw, board, plat, boot_hw, "")
        if soc_name:
            soc_detected = soc_name
    except Exception:
        pass

    # CPU
    cpu_abi = _g("ro.product.cpu.abi")
    cpu_abilist = _g("ro.product.cpu.abilist")

    # RAM
    ram_gb = "—"
    mt = meminfo.get("MemTotal", "")
    m = re.match(r"(\d+)\s*kB", mt)
    if m:
        ram_gb = f"{int(m.group(1)) / 1024 / 1024:.2f} GB"

    # Storage (userdata)
    data_size = "—"
    data_avail = "—"
    for line in (storage or "").splitlines():
        if "/data" in line and "fuse" not in line:
            parts = line.split()
            if len(parts) >= 4:
                data_size = parts[1]
                data_avail = parts[3]
                break

    # Display
    res = _g("persist.sys.sellcdresolution", "ro.sf.lcd_resolution")
    density = _g("ro.sf.lcd_density")
    hdr = _g("ro.surface_flinger.has_HDR_display")

    # GPU
    egl = _g("ro.hardware.egl", "ro.hardware.vulkan")
    gles_raw = props.get("ro.opengles.version", "")
    gles_ver = "—"
    if gles_raw.isdigit():
        v = int(gles_raw)
        gles_ver = f"{v >> 16}.{v & 0xffff}"
    vulkan_ver = _g("ro.hardware.vulkan.level",
                    "ro.hardware.vulkan.version")

    # Modem / baseband
    baseband = _g("gsm.version.baseband", "ro.boot.baseband")
    if baseband != "—" and "," in baseband:
        # e.g. "MOLY...,MOLY..." -> just one
        baseband = baseband.split(",")[0]
    max_modems = _g("telephony.active_modems.max_count",
                    "ro.telephony.default_network")
    default_net = _g("ro.telephony.default_network")

    # Wi-Fi / Bluetooth
    wifi_fw = _g("persist.vendor.connsys.wifi_fw_ver",
                 "persist.vendor.wifi.fw.ver",
                 "vendor.wifi.fw.version")
    wifi_iface = _g("ro.vendor.wifi.sap.interface", "wifi.interface")
    bt_name = _g("net.bt.name", "ro.boot.bt.name")

    # Identity / firmware
    model = _g("ro.product.model")
    brand = _g("ro.product.brand")
    manuf = _g("ro.product.manufacturer")
    prod_name = _g("ro.product.name")
    prod_device = _g("ro.product.device")
    board_code = _g("ro.product.board")
    android_rel = _g("ro.build.version.release")
    sdk = _g("ro.build.version.sdk")
    patch = _g("ro.build.version.security_patch")
    fp = _g("ro.build.fingerprint")
    build_date = _g("ro.build.date")
    locale = _g("ro.product.locale", "persist.sys.locale")
    tz = _g("persist.sys.timezone")
    serialno = _g("ro.serialno", "ro.boot.serialno")

    # Security
    vb = _g("ro.boot.verifiedbootstate")
    flash_locked = _g("ro.boot.flash.locked")
    unlock_supp = _g("ro.oem_unlock_supported")
    treble = _g("ro.treble.enabled")

    return {
        "identity": [
            ("Model", model),
            ("Brand", brand),
            ("Manufacturer", manuf),
            ("Product name", prod_name),
            ("Device codename", prod_device),
            ("Board code", board_code),
            ("Serial number", serialno),
        ],
        "soc_cpu": [
            ("SoC manufacturer", soc_mfr),
            ("SoC model", soc_model),
            ("SoC (detected)", soc_detected or "—"),
            ("CPU ABI", cpu_abi),
            ("CPU ABI list", cpu_abilist),
        ],
        "memory": [
            ("RAM (actual)", ram_gb),
            ("Storage /data", f"{data_size} total, {data_avail} free"),
            ("Dalvik heap size", _g("dalvik.vm.heapsize")),
        ],
        "display_gpu": [
            ("Resolution", res),
            ("LCD density", density),
            ("HDR display", hdr),
            ("OpenGL ES", gles_ver),
            ("Vulkan level", vulkan_ver),
            ("GPU driver tag", egl),
        ],
        "radio": [
            ("Baseband", baseband),
            ("Max active modems", max_modems),
            ("Default network", default_net),
            ("Wi-Fi firmware", wifi_fw),
            ("Wi-Fi SAP interface", wifi_iface),
            ("Bluetooth name", bt_name),
        ],
        "os": [
            ("Android release", android_rel),
            ("SDK level", sdk),
            ("Security patch", patch),
            ("Build date", build_date),
            ("Locale", locale),
            ("Timezone", tz),
            ("Fingerprint", fp),
        ],
        "security": [
            ("Verified boot", vb),
            ("Flash locked", flash_locked),
            ("OEM unlock supported", unlock_supp),
            ("Treble enabled", treble),
        ],
    }


def verdict_from_findings(findings):
    crit = sum(1 for s, _ in findings if s == "CRITICAL")
    high = sum(1 for s, _ in findings if s == "HIGH")
    warn = sum(1 for s, _ in findings if s == "WARN")
    if crit > 0:
        label, tier = "LIKELY COUNTERFEIT / COMPROMISED", "critical"
    elif high > 0:
        label, tier = "SUSPICIOUS - review findings", "high"
    elif warn > 0:
        label, tier = "MINOR FLAGS - probably OK", "warn"
    else:
        label, tier = "No critical findings", "ok"
    return label, tier, crit, high, warn


def write_report(outdir, props, meminfo, cpuinfo, storage,
                 pkg_sys, pkg_usr, net_cmd, net_out, findings, apk_hashes):
    ts = datetime.now().isoformat(timespec="seconds")
    report = {
        "tool_version": __version__,
        "scan_timestamp": ts,
        "props_count": len(props),
        "props": props,
        "meminfo": meminfo,
        "storage": storage,
        "cpuinfo": cpuinfo,
        "packages_system": [{"pkg": p, "path": pa} for p, pa in pkg_sys],
        "packages_user":   [{"pkg": p, "path": pa} for p, pa in pkg_usr],
        "network_cmd": net_cmd,
        "network_out": net_out,
        "findings": [{"severity": s, "message": m} for s, m in findings],
        "apk_hashes": apk_hashes,
    }
    json_path = outdir / "report.json"
    json_path.write_text(json.dumps(report, indent=2))

    findings_sorted = sorted(findings, key=lambda f: SEV_ORDER.get(f[0], 9))
    verdict, _, crit, high, warn = verdict_from_findings(findings)

    md = [
        f"# f3p report",
        "",
        f"**Tool version:** {__version__}  ",
        f"**Scan time:** {ts}  ",
        f"**Device:** {props.get('ro.product.manufacturer','?')} "
        f"{props.get('ro.product.model','?')}  ",
        f"**Advertised:** Android {props.get('ro.build.version.release','?')} "
        f"(SDK {props.get('ro.build.version.sdk','?')})  ",
        f"**Fingerprint:** `{props.get('ro.build.fingerprint','?')}`  ",
        "",
        f"## Verdict: {verdict}",
        "",
        f"- {crit} CRITICAL",
        f"- {high} HIGH",
        f"- {warn} WARN",
        "",
        "## Findings",
        "",
    ]
    for sev, msg in findings_sorted:
        md.append(f"- **[{sev}]** {msg}")
    md += [
        "",
        "## Packages",
        "",
        f"- System packages: {len(pkg_sys)}",
        f"- User packages:   {len(pkg_usr)}",
        "",
        "Full JSON in `report.json`. System APKs in `system_apks/` -- "
        "upload to VirusTotal, MobSF, or inspect with `apktool`.",
    ]
    md_path = outdir / "report.md"
    md_path.write_text("\n".join(md))
    return json_path, md_path


# ---------------------------------------------------------------------------
# Scan orchestrator (usable from CLI and GUI)
# ---------------------------------------------------------------------------

def run_scan(adb, outdir, skip_apks=False, apk_limit=0, progress_cb=None):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    def step(name, extra=None):
        if progress_cb:
            progress_cb(name, extra)

    step("getprop")
    props = getprop_all(adb)
    step("proc")
    meminfo = get_meminfo(adb)
    cpuinfo = get_cpuinfo(adb)
    step("storage")
    storage = get_storage(adb)
    step("packages")
    pkg_sys, pkg_usr = list_packages(adb)
    step("network")
    net_cmd, net_out = check_socket_stats(adb)

    apk_hashes = []
    if not skip_apks:
        def apk_cb(i, total, pkg):
            if progress_cb:
                progress_cb("apks", (i, total, pkg))
        apk_hashes = hash_system_apks(adb, outdir, limit=apk_limit,
                                       progress_cb=apk_cb)

    step("analyze")
    findings = analyze(props, meminfo, cpuinfo, pkg_sys, pkg_usr)

    step("report")
    jp, mp = write_report(outdir, props, meminfo, cpuinfo, storage,
                          pkg_sys, pkg_usr, net_cmd, net_out,
                          findings, apk_hashes)

    return {
        "outdir": str(outdir),
        "report_md": str(mp),
        "report_json": str(jp),
        "findings": findings,
        "props": props,
        "meminfo": meminfo,
        "storage": storage,
        "packages_system": pkg_sys,
        "packages_user": pkg_usr,
        "apk_hashes": apk_hashes,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_doctor(args):
    print("f3p doctor - checking prerequisites")
    print("-" * 50)
    ok = True

    adb_path = shutil.which("adb")
    if adb_path:
        r = subprocess.run(["adb", "--version"], capture_output=True, text=True)
        ver = r.stdout.splitlines()[0] if r.stdout else "?"
        print(f"  [OK]   adb: {adb_path} ({ver})")
    else:
        print("  [FAIL] adb not found. Install:")
        print("           Fedora/RHEL: sudo dnf install android-tools")
        print("           Debian/Ubuntu: sudo apt install android-tools-adb")
        ok = False

    if adb_path:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            lines = [l for l in r.stdout.splitlines()[1:] if l.strip()]
            if lines:
                print(f"  [OK]   adb server running, {len(lines)} device(s):")
                for l in lines:
                    print(f"           {l}")
            else:
                print("  [WARN] adb server running but no device attached.")
        else:
            print("  [FAIL] adb server failed to start.")
            ok = False

    pv = sys.version_info
    if pv >= (3, 6):
        print(f"  [OK]   Python: {sys.version.split()[0]}")
    else:
        print(f"  [FAIL] Python >= 3.6 required, found {sys.version}")
        ok = False

    if sys.platform.startswith("linux"):
        udev = Path("/etc/udev/rules.d/51-android.rules")
        if udev.exists():
            print(f"  [OK]   udev rules present: {udev}")
        else:
            print(f"  [INFO] No {udev} - install contrib/51-android.rules if needed.")

    try:
        import PyQt6  # noqa: F401
        print(f"  [OK]   PyQt6 available (for GUI)")
    except ImportError:
        print(f"  [INFO] PyQt6 not installed - GUI unavailable.")
        print(f"           Fedora: sudo dnf install python3-pyqt6")

    print("-" * 50)
    print("READY" if ok else "NOT READY - fix the failures above")
    sys.exit(0 if ok else 2)


def cmd_scan(args):
    adb = ADB(serial=args.serial)
    devs = adb.devices()
    if not devs:
        print("No ADB devices found. Run 'f3p doctor' first.", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Devices: {devs}")

    for serial, state in devs:
        if state == "unauthorized":
            print(f"    {serial}: UNAUTHORIZED - accept RSA prompt", file=sys.stderr)
            sys.exit(1)
        if state == "offline":
            print(f"    {serial}: OFFLINE", file=sys.stderr)
            sys.exit(1)

    def cb(stage, extra):
        if stage == "getprop":   print("[*] Dumping getprop...")
        elif stage == "proc":    print("[*] Reading /proc/meminfo and /proc/cpuinfo...")
        elif stage == "storage": print("[*] Storage...")
        elif stage == "packages":print("[*] Listing packages...")
        elif stage == "network": print("[*] Network sockets...")
        elif stage == "analyze": print("[*] Analyzing...")
        elif stage == "apks":
            i, total, _ = extra
            if i == 1:
                print(f"[*] Pulling system APKs (total={total})...")
            if i % 10 == 0:
                print(f"    {i}/{total}...")

    result = run_scan(adb, args.outdir, skip_apks=args.skip_apks,
                      apk_limit=args.apk_limit, progress_cb=cb)

    print(f"\n[+] Report: {result['report_md']}")
    print(f"[+] JSON:   {result['report_json']}")
    print("\n=== FINDINGS ===")
    for sev, msg in sorted(result['findings'], key=lambda f: SEV_ORDER.get(f[0], 9)):
        color = SEV_COLOR.get(sev, "") if sys.stdout.isatty() else ""
        reset = "\033[0m" if color else ""
        print(f"  {color}[{sev:<8}]{reset} {msg}")


def cmd_watch_net(args):
    adb = ADB(serial=args.serial)
    print("[*] Watching network activity. Ctrl+C to stop.")
    try:
        while True:
            print(f"\n--- {datetime.now().isoformat(timespec='seconds')} ---")
            cmd, out = check_socket_stats(adb)
            if out:
                print(out)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] stopped")


def cmd_gui(args):
    try:
        from f3p_gui import run_gui
    except ImportError as e:
        print(f"GUI unavailable: {e}", file=sys.stderr)
        print("Install PyQt6: sudo dnf install python3-pyqt6", file=sys.stderr)
        sys.exit(2)
    run_gui()


def main():
    p = argparse.ArgumentParser(prog="f3p",
        description="Triage suspicious Android devices via ADB.")
    p.add_argument("--version", action="version",
                   version=f"f3p {__version__}")
    p.add_argument("-s", "--serial",
                   help="ADB device serial (if multiple attached)")
    sub = p.add_subparsers(dest="cmd", required=True)

    dp = sub.add_parser("doctor", help="Sanity-check the environment")
    dp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("scan", help="Full offline triage scan")
    sp.add_argument("-o", "--outdir",
                    default=f"./scan-{datetime.now():%Y%m%d-%H%M%S}")
    sp.add_argument("--skip-apks", action="store_true")
    sp.add_argument("--apk-limit", type=int, default=0)
    sp.set_defaults(func=cmd_scan)

    wp = sub.add_parser("watch-net", help="Live socket monitor")
    wp.add_argument("--interval", type=int, default=3)
    wp.set_defaults(func=cmd_watch_net)

    gp = sub.add_parser("gui", help="Launch Qt6 GUI")
    gp.set_defaults(func=cmd_gui)

    args = p.parse_args()
    try:
        args.func(args)
    except ADBError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
