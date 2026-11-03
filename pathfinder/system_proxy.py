"""Opt-in, reversible per-user Windows PAC settings. No administrator access."""
import ctypes
import json
import os
from pathlib import Path
from .config import atomic_json, DEFAULT_DIRECT_DOMAINS, TLS_PORTS
from . import __version__

REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
SETTING_NAMES = ("AutoConfigURL", "ProxyEnable", "ProxyServer", "ProxyOverride")


def pac_script(config):
    patterns = [p for s in config["services"] for p in s["domains"]]
    return """function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/[.]$/, "");
  if (!/^(https|wss):[/][/]/.test(url)) return "DIRECT";
  if (host.indexOf(".") < 0 || host.indexOf(":") >= 0 || /^[0-9.]+$/.test(host)) return "DIRECT";
  var authority = url.split("/")[2];
  var portMatch = /:([0-9]+)$/.exec(authority);
  var port = portMatch ? Number(portMatch[1]) : 443;
  var ports = %s;
  if (ports.indexOf(port) < 0) return "DIRECT";
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
""" % (json.dumps(TLS_PORTS), json.dumps(config.get("direct_domains", DEFAULT_DIRECT_DOMAINS)), json.dumps(patterns), "true" if config["auto_manage"] else "false", config["proxy_port"])


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


def write_value(key, name, item):
    import winreg
    if item is None:
        try:
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
    else:
        winreg.SetValueEx(key, name, 0, item["type"], item["value"])


def enable(directory, port, proxy_port=None, direct_domains=None):
    require_windows()
    import winreg
    backup = Path(directory) / "proxy-backup.json"
    desired = {"AutoConfigURL": {"value": f"http://127.0.0.1:{port}/proxy.pac?v={__version__}", "type": winreg.REG_SZ},
               "ProxyEnable": {"value": int(proxy_port is not None), "type": winreg.REG_DWORD}}
    if proxy_port is not None:
        if type(proxy_port) is not int or not 1024 <= proxy_port <= 65535:
            raise ValueError("Некорректный порт прокси")
        bypass = ["<local>", "localhost", "127.*", "[::1]", "10.*", "192.168.*"]
        bypass += [f"172.{n}.*" for n in range(16, 32)]
        bypass += list(direct_domains if direct_domains is not None else DEFAULT_DIRECT_DOMAINS)
        desired.update({"ProxyServer": {"value": f"https=127.0.0.1:{proxy_port}", "type": winreg.REG_SZ},
                        "ProxyOverride": {"value": ";".join(bypass), "type": winreg.REG_SZ}})
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
        current = read_values(key)
        if backup.exists():
            saved = json.loads(backup.read_text(encoding="utf-8"))
            old_url = saved["installed"]["AutoConfigURL"]["value"].split("?", 1)[0]
            new_url = desired["AutoConfigURL"]["value"].split("?", 1)[0]
            if any(current[name] != item for name, item in saved["installed"].items()) or old_url != new_url:
                raise RuntimeError("Настройки прокси изменены извне. Сначала восстановите их через меню или разберите proxy-backup.json")
            for name in desired:
                if name not in saved["installed"]:
                    saved["before"][name] = current[name]
            # Keep ownership of values written by an earlier activation so exit
            # restores them even if the user changes scope back to PAC-only.
            for name, item in saved["installed"].items():
                desired.setdefault(name, item)
            if desired != saved["installed"]:
                saved["installed"] = desired
                atomic_json(backup, saved)
        else:
            atomic_json(backup, {"before": current, "installed": desired})
        try:
            for name, item in desired.items():
                write_value(key, name, item)
        except OSError:
            saved = json.loads(backup.read_text(encoding="utf-8"))
            for name in saved["installed"]:
                item = saved["before"].get(name)
                try:
                    write_value(key, name, item)
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
        for name in saved["installed"]:
            if current[name] != saved["installed"][name]:
                continue
            write_value(key, name, saved["before"].get(name))
    backup.unlink()
    notify_windows()
    return True
