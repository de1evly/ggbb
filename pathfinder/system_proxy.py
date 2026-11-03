"""Opt-in, reversible per-user Windows PAC settings. No administrator access."""
import ctypes
import json
import os
from pathlib import Path
from .config import atomic_json, DEFAULT_DIRECT_DOMAINS
from . import __version__

REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
SETTING_NAMES = ("AutoConfigURL", "ProxyEnable")


def pac_script(config):
    patterns = [p for s in config["services"] for p in s["domains"]]
    return """function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/[.]$/, "");
  if (url.substring(0, 6) !== "https:") return "DIRECT";
  if (host.indexOf(".") < 0 || host.indexOf(":") >= 0 || /^[0-9.]+$/.test(host)) return "DIRECT";
  var local = [".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid", ".onion"];
  for (var i=0; i<local.length; i++) if (dnsDomainIs(host, local[i])) return "DIRECT";
  var direct = %s;
  for (var d=0; d<direct.length; d++) {
    if (host === direct[d] || (direct[d].substring(0,2) === "*." && dnsDomainIs(host, direct[d].substring(1)))) return "DIRECT";
  }
  var patterns = %s;
  var managed = %s;
  for (var j=0; j<patterns.length; j++) {
    if (host === patterns[j] || (patterns[j].substring(0,2) === "*." && dnsDomainIs(host, patterns[j].substring(1)))) managed = true;
  }
  return managed ? "PROXY 127.0.0.1:%d" : "DIRECT";
}
""" % (json.dumps(config.get("direct_domains", DEFAULT_DIRECT_DOMAINS)), json.dumps(patterns), "true" if config["auto_manage"] else "false", config["proxy_port"])


def require_windows():
    if os.name != "nt":
        raise RuntimeError("Настройка системного прокси доступна только в Windows")


def notify_windows():
    wininet = ctypes.windll.Wininet
    for option in (39, 37):
        wininet.InternetSetOptionW(None, option, None, 0)


def read_values(key):
    import winreg
    result = {}
    for name in SETTING_NAMES:
        try:
            value, kind = winreg.QueryValueEx(key, name)
            result[name] = {"value": value, "type": kind}
        except FileNotFoundError:
            result[name] = None
    return result


def enable(directory, port):
    require_windows()
    import winreg
    backup = Path(directory) / "proxy-backup.json"
    desired = {"AutoConfigURL": {"value": f"http://127.0.0.1:{port}/proxy.pac?v={__version__}", "type": winreg.REG_SZ},
               "ProxyEnable": {"value": 0, "type": winreg.REG_DWORD}}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
        current = read_values(key)
        if backup.exists():
            saved = json.loads(backup.read_text(encoding="utf-8"))
            old_url = saved["installed"]["AutoConfigURL"]["value"].split("?", 1)[0]
            new_url = desired["AutoConfigURL"]["value"].split("?", 1)[0]
            if current != saved["installed"] or old_url != new_url:
                raise RuntimeError("Настройки прокси изменены извне. Сначала восстановите их через меню или разберите proxy-backup.json")
            if desired != saved["installed"]:
                saved["installed"] = desired
                atomic_json(backup, saved)
        else:
            atomic_json(backup, {"before": current, "installed": desired})
        try:
            for name, item in desired.items():
                winreg.SetValueEx(key, name, 0, item["type"], item["value"])
        except OSError:
            saved = json.loads(backup.read_text(encoding="utf-8"))
            for name in SETTING_NAMES:
                item = saved["before"][name]
                try:
                    if item is None:
                        winreg.DeleteValue(key, name)
                    else:
                        winreg.SetValueEx(key, name, 0, item["type"], item["value"])
                except OSError:
                    pass  # Durable backup remains for explicit restoration.
            raise
    notify_windows()


def disable(directory):
    require_windows()
    import winreg
    backup = Path(directory) / "proxy-backup.json"
    if not backup.exists():
        return False
    saved = json.loads(backup.read_text(encoding="utf-8"))
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
        current = read_values(key)
        # Restore each value only if still ours; never overwrite another tool's edit.
        for name in SETTING_NAMES:
            if current[name] != saved["installed"][name]:
                continue
            item = saved["before"][name]
            if item is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, item["type"], item["value"])
    backup.unlink()
    notify_windows()
    return True
