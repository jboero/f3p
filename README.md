# f3p — Fight Phone Fraud

Triage suspicious Android devices via ADB. Detects spoofed specs and known
pre-installed malware.

Named in the style of [f3 (Fight Flash Fraud)](https://github.com/AltraMayor/f3),
which catches counterfeit USB sticks. `f3p` does the same for counterfeit
Android phones and tablets: instead of trusting `getprop` or the "About phone"
screen (which knockoff OEMs spoof freely), it pulls what the Linux kernel
actually sees — `/proc/meminfo`, `/proc/cpuinfo`, the full package manifest,
system APK hashes, live socket table — and cross-references reality against
the marketing.

No root required. No APK installed on the device. Everything runs on your
host over ADB (USB or Android 11+ Wireless Debugging).

## Install

From source (Fedora / RHEL / Amazon Linux):

```fish
sudo dnf install android-tools python3-pyqt6
make install       # installs to /usr/local by default
```

Or build an RPM:

```fish
make srpm          # produces f3p-0.1.0-1.fc*.src.rpm
# rebuild in mock:
mock -r fedora-43-x86_64 rebuild f3p-*.src.rpm
```

Dependencies: `python3 >= 3.6`, `android-tools`. `python3-pyqt6` only if you
want the GUI.

## Usage

```fish
f3p doctor              # sanity-check the environment
f3p scan                # USB or Wireless Debugging device, outputs ./scan-TIMESTAMP/
f3p gui                 # Qt6 window (uses your system theme)
f3p watch-net           # live socket monitor
```

## What it checks

- Android version spoofing: `ro.build.version.sdk` vs `ro.build.version.release`
- SoC spoofing: `ro.hardware` / `ro.board.platform` / `/proc/cpuinfo` vs the
  marketed name. Includes a codename alias map (kalama → SM8550, taro → SM8450,
  zuma → Tensor G3, etc.) so legitimate flagships don't false-positive.
- SoC internal consistency: `ro.hardware` differing from `ro.board.platform`
  is the copy-paste-vendor-tree tell.
- RAM spoofing: `/proc/meminfo` MemTotal vs the model's marketing claim.
- Security patch staleness (≥24 months = HIGH, ≥12 = WARN).
- Build-date vs patch-date discrepancy (catches firmware that was touched up
  at shipping time to reset timestamps).
- Verified boot state, SELinux mode, bootloader unlock support, Treble.
- Known malicious packages: Adups, UMX dropper, Redstone OTA family
  (including the `com.abfota.systemUpdate` rebrand from the Alldocube/Keenadu
  supply-chain compromise), Coolpad CoolReaper, and more.
- Shibai pattern: WhatsApp / Telegram / Signal / Facebook / Netflix / TikTok
  pre-installed in `/system/` or `/vendor/app/` (they shouldn't be).
- Generic placeholder-package check (any `com.example.*` in production ROM
  is an amateur-hour signal).
- Fuzzy fragment match for less-known OTA/FOTA/tracker families.

## Is this generic, or is it for one specific phone?

Generic. The kernel-level reads work on any Android device. Clean flagships
(Pixel 8, Galaxy S23, OnePlus 11) and legitimate budget devices (Lenovo Tab
K11) produce zero findings at WARN or above. The knockoff-specific findings
only fire when the knockoff-specific conditions are met. If you run this on
a phone you trust, you'll get a clean report. If you run it on a phone you
don't trust, you'll get the real story.

See [`docs/case-studies/luna-t10-wwt26ultra.md`](docs/case-studies/luna-t10-wwt26ultra.md)
for a full writeup of the device that motivated this tool.

## What this is NOT

A detection tool, not an attestation bypass. The Android ecosystem has plenty
of tools going the other direction (PixelSpoof, XPL-EX, Tricky-Addon) which
help users fool apps about the device they're on. That's not what this does.
`f3p` reads without modifying and helps you decide whether to return a
suspicious device.

## License

GPLv3, same as f3. See `LICENSE`.
