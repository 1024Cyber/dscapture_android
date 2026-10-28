<div align="center">

# 🦈 DSCapture

**No-root packet capture for Android — real `.pcap` files, straight into Wireshark.**

[![Platform](https://img.shields.io/badge/platform-Android%2011%2B-3DDC84?style=flat-square)]()
[![Build](https://img.shields.io/badge/build-GitHub%20Actions-2088FF?style=flat-square)]()

</div>

---

## What it is

DSCapture uses Android's built-in `VpnService` to capture real device traffic locally — no root, no proxy certs, no rooted emulator. Every packet is written to a standard libpcap file you can pull off the device and open directly in Wireshark.

It runs as a standalone app (Start/Stop from its own UI) and doubles as the packet-capture helper for **[DroidSentinel](https://github.com/1024Cyber)**, which can trigger it over `adb`.

## Features

- Real `.pcap` output — no proprietary format, opens natively in Wireshark
- Zero root required
- TCP/UDP/DNS traffic relayed locally so the device stays online while capturing
- Scope a capture to a single app or the whole device
- Saves to a user-visible folder (`/storage/emulated/0/dscapture`), not app-private storage
- Captured packets show the device's real local IP, not an internal placeholder address

## Install

Grab the latest APK from this repo's Releases), then install it on your device. Android 11+ needs one extra step: open the app and tap **Grant Storage Access**.

## Usage

1. Open DSCapture
2. Tap **Start capturing** — accept the one-time "Allow DSCapture to set up a VPN connection?" prompt (first run only)
3. Tap **Stop capturing & export** when done
4. Pull the `.pcap` from `/storage/emulated/0/dscapture` and open it in Wireshark

## Building

Built via GitHub Actions on every push — no local Android SDK setup needed. See [`.github/workflows/build-dscapture.yml`](.github/workflows/build-dscapture.yml).

## Scope

This is a focused capture tool, not a full user-space network stack — TCP, UDP, and DNS are relayed so the device keeps working during capture; other protocols are captured to the pcap but not relayed.

---

<div align="center">
<sub>Built by <a href="https://x.com/1024Cyber">1024Cyber</a> — companion capture engine for DroidSentinel.</sub>
</div>
