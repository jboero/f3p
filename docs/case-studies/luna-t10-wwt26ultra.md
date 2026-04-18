# Case study: "WWT 26 Ultra" is a LUNA T10 is an Alldocube-family tablet with Keenadu

**Scan date:** 2026-04-17
**Retail label:** "WWT 26 Ultra" phone, purchased on Amazon
**Firmware identity:** LUNA T10 tablet
**Outcome:** Firmware-level backdoor (Keenadu) all but confirmed; device returned

## The three-layer identity mismatch

```
Retail box / Amazon listing:   WWT 26 Ultra
                               Snapdragon 8s Gen 4, Adreno 750, 12+512 GB
                               "phone" form factor

Android firmware thinks:       LUNA T10 tablet
                               ro.product.device = LUNA_T10
                               ro.product.name   = LUNA_T10

ODM reference board:           g662v3_pmz_w3_3d
                               MediaTek Helio P22/A25 (mt6762 / mt6765)
                               ~3.7 GB RAM, ~50 GB userdata
```

Three independent layers, none of them agreeing. The retail branding is a
sticker on a box. The firmware identity is a tablet ROM. The underlying board
is an anonymous Shenzhen ODM tablet reference design.

## The smoking gun: com.abfota.systemUpdate

Our scan flagged `com.abfota.systemUpdate` as a non-whitelisted FOTA package.
Digging into it:

- **Alldocube tablets** (iPlay 50 mini Pro in particular) ship with this exact
  package. Alldocube's OTA server was compromised in **March 2024** and the
  company publicly acknowledged "a virus attack through OTA software."
- **Kaspersky (Feb 2026)** linked those compromised firmwares to **Keenadu**
  — a firmware-level backdoor embedded in `libandroid_runtime.so`. Keenadu
  injects into the Zygote process and ends up in the address space of every
  app on the device.
- Firmware IOC: `libVndxUtils.a` (MD5: `ca98ae7ab25ce144927a46b7fee6bd21`),
  masquerading as legitimate MediaTek code.
- C2 infrastructure: `keepgo123[.]com`, `gsonx[.]com`, `zcnewy[.]com`.
- **All firmware versions for the compromised model remained infected**,
  including updates released after Alldocube's public statement.

The `abfota` package we observed is either the same compromised Redstone OTA
variant, or a rebranded version of it. Either way: this package is a known
vector for Keenadu delivery.

## Why the LUNA T10 matters (not an Alldocube model, but shares the supply chain)

LUNA T10 is not an Alldocube device per se — it's another reseller using the
same ODM board (`g662v3_pmz_w3_3d`). The `abfota` package and the tablet class
(not phone) strongly suggest this firmware branch descends from the same
Redstone-based OTA ecosystem that was compromised.

Sophos (March 2026) reported Keenadu detections across ~50 models from
Allview, BLU, Dcode, DOOGEE, Gigaset, Gionee, Lava, and Ulefone — **not just
Alldocube**. The supply-chain root is shared across brands. "LUNA" is the
latest discovered label.

## Other findings on this specific unit

Beyond the Keenadu vector:

**Internal SoC inconsistency:**
- `ro.hardware = mt6762` (Helio P22/A25)
- `ro.board.platform = mt6765` (Helio P35/G35)

These are different chips. Someone assembled this firmware from a different
device's vendor tree without fixing the board platform prop. Classic
copy-paste ROM engineering.

**Build date anomaly:**
- `ro.build.date = Sat Jan 17 09:44:47 CST 2026`
- `ro.build.version.security_patch = 2023-03-01`
- Fingerprint internal date: `20230412`

ROM was built in April 2023 with March 2023 patches (3+ years stale), then
re-stamped Jan 17 2026. This is the refresh-before-ship pattern: reflash the
stock image right before packaging to reset timestamps and defeat age-based
warranty checks.

**Pre-installed consumer apps in /vendor/app/:**

| Package | Path |
|---|---|
| com.whatsapp | /vendor/app/WhatsApp/WhatsApp.apk |
| com.facebook.katana | /vendor/operator/app/Facebook/Facebook.apk |
| com.twitter.android | /vendor/app/X/X.apk |
| com.zhiliaoapp.musically (TikTok) | /vendor/app/TikTok/TikTok.apk |
| com.netflix.mediaclient | /vendor/app/Netflix/Netflix.apk |

These are the Shibai pattern (Doctor Web, April 2025). Consumer apps should
NEVER live in the system/vendor partition on clean AOSP. When they do, it's
because the OEM/reseller wanted them there — and in prior campaigns, it's
been because they were trojanized variants the user can't uninstall.

**Amateur-hour tell:**

- `com.example.switchbootanim` at `/system/app/SwitchBootAnim/SwitchBootAnim.apk`

Somebody built a boot animation switcher, left the Android Studio default
`com.example.*` package name in, and shipped it to production. This doesn't
prove malice — just that the people assembling this ROM aren't professionals.
Which is exactly who you'd expect to hand over signing keys to a supply-chain
attacker.

**USB port is intentionally crippled:**

The device refuses to charge with non-proprietary USB-C cables and exposes no
USB data lines to any cable we tested. This prevents `fastboot` access
entirely, which means even though `ro.treble.enabled = true`, a LineageOS GSI
via DSU loader is not reachable. Together with the firmware-level Keenadu
vector, this device has no clean path forward.

## Bottom line

This device is sold as a "phone," is actually a re-shelled tablet mainboard,
runs a firmware descended from an OTA ecosystem that was provably compromised
with a firmware-level backdoor, and has no hardware path to escape that
firmware. The scan's CRITICAL verdict is correct.

**Action taken:** Returned to Amazon under "item not as described." Packet
captures from the brief period it was powered on a quarantined VLAN are
available in `wwt26-phonehome.pcap` (redacted for local network details).

## f3p output summary

```
Verdict: LIKELY COUNTERFEIT / COMPROMISED
- 7 CRITICAL
- 2 HIGH
- 2 WARN
```

Full findings:

- **[CRITICAL]** Board code `g662v3_pmz_w3_3d` is a known counterfeit ODM reference
- **[CRITICAL]** Known malicious package present: `com.abfota.systemUpdate` — Redstone OTA variant (Keenadu vector, March 2024)
- **[CRITICAL]** WhatsApp is a SYSTEM app at `/vendor/app/WhatsApp/WhatsApp.apk` (Shibai pattern)
- **[CRITICAL]** X (Twitter) is a SYSTEM app at `/vendor/app/X/X.apk` (Shibai pattern)
- **[CRITICAL]** Netflix is a SYSTEM app at `/vendor/app/Netflix/Netflix.apk` (Shibai pattern)
- **[CRITICAL]** TikTok is a SYSTEM app at `/vendor/app/TikTok/TikTok.apk` (Shibai pattern)
- **[CRITICAL]** Facebook is a SYSTEM app at `/vendor/operator/app/Facebook/Facebook.apk` (Shibai pattern)
- **[HIGH]** Security patches are 3+ years stale (2023-03-01) despite build date Jan 17 2026 — reflash-before-shipping
- **[HIGH]** Internal SoC inconsistency: `mt6762` + `mt6765` referenced — copy-paste ODM vendor tree
- **[WARN]** Firmware identity suggests TABLET class (`LUNA_T10`) in phone shell
- **[WARN]** Placeholder package in production: `com.example.switchbootanim`

## References

- Kaspersky Securelist, ["Keenadu the tablet conqueror and the links between major Android botnets"](https://securelist.com/keenadu-android-backdoor/118913/) (Feb 18 2026)
- Sophos Labs, ["Android devices ship with firmware-level malware"](https://www.sophos.com/en-us/blog/android-devices-ship-with-firmware-level-malware) (Feb 2026)
- BleepingComputer, ["New Keenadu backdoor found in Android firmware"](https://www.bleepingcomputer.com/news/security/new-keenadu-backdoor-found-in-android-firmware-google-play-apps/) (Feb 18 2026)
- NotebookCheck, ["Alldocube confirms critical security flaws in several tablets"](https://www.notebookcheck.net/Alldocube-confirms-critical-security-flaws-in-several-tablets-promising-OTA-updates-early-next-month.1235943.0.html) (Feb 26 2026)
- XDA Forums, ["Alldocube OTA Malware (iPlay 50 Mini Pro)"](https://xdaforums.com/t/alldocube-ota-malware-iplay-50-mini-pro.4682746/) (Jul 2024)
- Doctor Web, ["Chinese Android phones shipped with malware-laced WhatsApp, Telegram apps"](https://securityaffairs.com/176600/malware/chinese-android-phones-shipped-with-malware-laced-whatsapp-telegram-apps.html) (April 2025)
