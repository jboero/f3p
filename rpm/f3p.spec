Name:           f3p
Version:        0.1.0
Release:        1%{?dist}
Summary:        Fight Phone Fraud - ADB-based triage for counterfeit Android devices

License:        GPL-3.0-or-later
URL:            https://github.com/jboero/f3p
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  make
Requires:       python3 >= 3.6
Requires:       android-tools
Recommends:     python3-pyqt6

%description
f3p (Fight Phone Fraud) inspects a USB- or Wi-Fi-connected Android device
via adb and cross-references advertised specs (model, RAM, SoC, Android
version) against reality read from /proc/meminfo, /proc/cpuinfo, and getprop.
Flags known pre-installed malware (Keenadu / Shibai / Adups / Redstone OTA
families) and pulls system APKs for offline analysis.

Runs entirely over ADB - no root required on the target device, no APK
installed, no modifications.

Named after f3 (Fight Flash Fraud), which inspired the approach.

%prep
%setup -q

%build

%install
%make_install PREFIX=%{_prefix}

%files
%doc README.md docs/case-studies docs/LICENSE
%{_bindir}/%{name}
%{_prefix}/lib/%{name}/f3p.py
%{_prefix}/lib/%{name}/f3p_gui.py
%{_prefix}/lib/udev/rules.d/51-android.rules
%{_datadir}/applications/f3p.desktop

%post
if [ -x /usr/bin/udevadm ]; then
    /usr/bin/udevadm control --reload-rules >/dev/null 2>&1 || :
    /usr/bin/udevadm trigger >/dev/null 2>&1 || :
fi

%postun
if [ -x /usr/bin/udevadm ]; then
    /usr/bin/udevadm control --reload-rules >/dev/null 2>&1 || :
fi

%changelog
* Fri Apr 17 2026 Johnny Boero <boeroboy@gmail.com> - 0.1.0-1
- Initial f3p release (was dodgyscan internally during development)
- CLI engine with generic analyzer covering MTK, Unisoc, Qualcomm, Exynos,
  Tensor, Kirin, Rockchip, Allwinner SoCs
- SoC codename alias map (kalama, taro, zuma, pineapple, etc.)
- Minimal Qt6 GUI using system default theme, severity-colored findings
- Known-bad package list seeded from public reports (Adups, UMX, Shibai,
  Redstone/abfota, Coolpad CoolReaper)
- First case study: LUNA T10 / WWT 26 Ultra
