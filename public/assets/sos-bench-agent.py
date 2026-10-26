#!/usr/bin/env python3
"""
SOS Tools — Workstation USB Bench Agent
Listens locally on http://127.0.0.1:7890 to bridge physical USB-connected
phones (ADB and Apple MobileDevice) directly to SOS Tools in your browser.

Requirements:
  - Python 3.7+ (zero external dependencies, standard library only)
  - For Android: ADB in PATH (e.g. from Android SDK platform-tools)
  - For Apple: iTunes installed or libimobiledevice (ideviceinfo) in PATH
"""

import sys
import json
import subprocess
import re
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 7890

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
        return res.stdout.strip()
    except Exception:
        return ""

def scan_android():
    out = run_cmd(["adb", "devices", "-l"])
    if not out:
        return None
    lines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("*") and not l.startswith("List of devices")]
    if not lines:
        return None
    
    line = lines[0]
    parts = line.split()
    if len(parts) < 2:
        return None
    serial = parts[0]
    status = parts[1]

    if status == "unauthorized":
        return {
            "platform": "android",
            "brand": "Android",
            "model": "Handset (Unauthorized)",
            "serial": serial,
            "authState": "unauthorized"
        }
    if status == "offline":
        return {
            "platform": "android",
            "brand": "Android",
            "model": "Handset (Offline)",
            "serial": serial,
            "authState": "offline"
        }
    if status != "device":
        return None

    # Authorized Android device
    brand = run_cmd(["adb", "-s", serial, "shell", "getprop", "ro.product.brand"]).capitalize() or "Android"
    model = run_cmd(["adb", "-s", serial, "shell", "getprop", "ro.product.model"]) or "Phone"
    storage_kb = run_cmd(["adb", "-s", serial, "shell", "df", "/data"])
    storage = "128GB"
    if storage_kb:
        try:
            m = re.findall(r"\s+(\d+)\s+", storage_kb)
            if m:
                total_gb = int(m[0]) / (1024 * 1024)
                if total_gb > 350: storage = "512GB"
                elif total_gb > 180: storage = "256GB"
                elif total_gb > 90: storage = "128GB"
                elif total_gb > 40: storage = "64GB"
        except Exception:
            pass

    # Battery
    batt_out = run_cmd(["adb", "-s", serial, "shell", "dumpsys", "battery"])
    battery_level = 90
    battery_cycles = 150
    if batt_out:
        level_m = re.search(r"level:\s*(\d+)", batt_out)
        if level_m:
            battery_level = int(level_m.group(1))

    # IMEI
    imei = ""
    imei_prop = run_cmd(["adb", "-s", serial, "shell", "getprop", "gsm.baseband.imei"])
    if re.match(r"^\d{15}$", imei_prop):
        imei = imei_prop
    if not imei:
        subinfo = run_cmd(["adb", "-s", serial, "shell", "service", "call", "iphonesubinfo", "1"])
        imei_match = re.findall(r"\'([0-9\.\s]+)\'", subinfo)
        if imei_match:
            digits = "".join(imei_match).replace(".", "").replace(" ", "").strip()
            if len(digits) >= 15:
                imei = digits[:15]

    return {
        "platform": "android",
        "brand": brand,
        "model": model,
        "storage": storage,
        "serial": serial,
        "imei": imei,
        "battery": battery_level,
        "cycles": battery_cycles,
        "os": "Android",
        "authState": "authorized"
    }

def scan_apple():
    out = run_cmd(["ideviceinfo"])
    if not out:
        return None
    if "PasswordProtected" in out or "PairingDialogResponsePending" in out:
        return {
            "platform": "apple",
            "brand": "Apple",
            "model": "iPhone (Screen Locked / Trust Prompt Pending)",
            "serial": "Apple-Device",
            "authState": "awaiting_trust"
        }
    
    props = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            props[k.strip()] = v.strip()

    model_name = props.get("ProductType", "iPhone")
    serial = props.get("SerialNumber", "")
    imei = props.get("InternationalMobileEquipmentIdentity", "")
    os_ver = "iOS " + props.get("ProductVersion", "")
    
    return {
        "platform": "apple",
        "brand": "Apple",
        "model": props.get("DeviceName", model_name),
        "storage": "128GB",
        "serial": serial,
        "imei": imei,
        "battery": 95,
        "cycles": 120,
        "os": os_ver,
        "authState": "authorized"
    }

def scan_windows_pnp():
    if sys.platform != "win32":
        return None
    try:
        ps_cmd = "$d = Get-CimInstance Win32_PnPEntity | Where-Object { $_.DeviceID -match 'VID_05AC|VID_04E8|VID_18D1|VID_2717|VID_22B8|VID_2A70|VID_12D1|VID_0FCE' } | Select-Object -First 1; if ($d) { @{ id = $d.DeviceID; name = $d.Name } | ConvertTo-Json -Compress }"
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], stdout=subprocess.PIPE, text=True, timeout=3)
        out = res.stdout.strip()
        if out:
            data = json.loads(out)
            dev_id = data.get("id", "")
            name = data.get("name", "USB Handset")
            is_apple = "VID_05AC" in dev_id
            brand = "Apple" if is_apple else ("Samsung" if "VID_04E8" in dev_id else ("Google" if "VID_18D1" in dev_id else "Android"))
            model = name
            if is_apple and "iPhone" not in model: model = "Apple iPhone"
            serial = "USB-DEVICE"
            m = re.search(r"VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}\\([^\&]+)", dev_id)
            if m: serial = m.group(1)
            return {
                "platform": "apple" if is_apple else "android",
                "brand": brand,
                "model": model,
                "storage": "128GB",
                "serial": serial,
                "battery": 94,
                "cycles": 140,
                "os": "Apple iOS" if is_apple else "Android OS",
                "authState": "authorized"
            }
    except Exception:
        pass
    return None

class BenchHandler(BaseHTTPRequestHandler):
    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_GET(self):
        if self.path == "/api/status":
            self._set_headers(200)
            self.wfile.write(json.dumps({"ok": True, "agentOnline": True, "version": "1.3.0"}).encode())
            return

        if self.path in ("/api/device", "/api/scan"):
            self._set_headers(200)
            dev = scan_android() or scan_apple() or scan_windows_pnp()
            self.wfile.write(json.dumps({"ok": True, "device": dev}).encode())
            return

        self._set_headers(404)
        self.wfile.write(b'{"error": "not found"}')

    def log_message(self, format, *args):
        pass # Quiet mode

def main():
    print("=" * 60)
    print("  SOS TOOLS — Workstation USB Bench Agent")
    print(f"  Listening on http://127.0.0.1:{PORT}")
    print("  Ready for Android (ADB) and Apple (ideviceinfo)")
    print("=" * 60)
    httpd = HTTPServer(("127.0.0.1", PORT), BenchHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nAgent stopped.")

if __name__ == "__main__":
    main()
