#!/usr/bin/env python3
# PROJECT EDGE - Logitech read-only discovery bridge
# Version 2.9.2 - faster dashboard refresh with serialized HID++ polling.
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import json, socket, time, threading

HOST = "0.0.0.0"
PORT = 8765

# HID++ is a shared USB transport: serialize diagnostics and reuse a short-lived snapshot.
_DIAGNOSTIC_LOCK = threading.Lock()
_DIAGNOSTIC_CACHE = {"created": 0.0, "data": None}
_DIAGNOSTIC_CACHE_TTL = 1.0

def cached_diagnostic():
    now = time.monotonic()
    cached = _DIAGNOSTIC_CACHE.get("data")
    if cached is not None and now - _DIAGNOSTIC_CACHE["created"] < _DIAGNOSTIC_CACHE_TTL:
        result = dict(cached)
        result["cache"] = {"hit": True, "age_seconds": round(now - _DIAGNOSTIC_CACHE["created"], 1)}
        return result
    with _DIAGNOSTIC_LOCK:
        now = time.monotonic()
        cached = _DIAGNOSTIC_CACHE.get("data")
        if cached is not None and now - _DIAGNOSTIC_CACHE["created"] < _DIAGNOSTIC_CACHE_TTL:
            result = dict(cached)
            result["cache"] = {"hit": True, "age_seconds": round(now - _DIAGNOSTIC_CACHE["created"], 1)}
            return result
        result = hidpp_readonly_probe()
        if result.get("ok"):
            _DIAGNOSTIC_CACHE["data"] = result
            _DIAGNOSTIC_CACHE["created"] = time.monotonic()
            result = dict(result)
            result["cache"] = {"hit": False, "age_seconds": 0}
            return result
        # On a transient HID failure, keep the last successful snapshot available.
        if cached is not None:
            result = dict(cached)
            result["cache"] = {"hit": True, "stale": True, "age_seconds": round(time.monotonic() - _DIAGNOSTIC_CACHE["created"], 1)}
            result["warning"] = "Lecture HID temporairement indisponible; dernière mesure valide conservée."
            return result
        return result

def local_ips():
    found = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        found.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return list(dict.fromkeys(found))

def enumerate_logitech():
    rows = []
    try:
        import hid
        devices = hid.enumerate(0x046D, 0)
        for d in devices:
            rows.append({
                "vendor_id": "046D",
                "product_id": f'{int(d.get("product_id", 0)):04X}',
                "manufacturer": d.get("manufacturer_string") or "Logitech",
                "product": d.get("product_string") or "Périphérique Logitech",
                "serial": None,  # deliberately do not expose serial numbers
                "interface_number": d.get("interface_number"),
                "usage_page": d.get("usage_page"),
                "usage": d.get("usage"),
                "transport": d.get("bus_type"),
                "path_available": bool(d.get("path")),
            })
    except ImportError:
        return {"available": False, "error": "Module hidapi absent. Lancez INSTALLER.bat.", "devices": []}
    except Exception as e:
        return {"available": False, "error": f"Erreur HID : {type(e).__name__}: {e}", "devices": []}
    return {"available": True, "devices": rows}



def hidpp_readonly_probe():
    try:
        import hid
    except ImportError:
        return {"ok": False, "error": "hidapi absent"}
    ds = hid.enumerate(0x046D, 0xC547)
    def report_caps(d):
        return {
            "interface_number": d.get("interface_number"),
            "usage_page": d.get("usage_page"),
            "usage": d.get("usage"),
            "max_input_report_length": d.get("max_input_report_length"),
            "max_output_report_length": d.get("max_output_report_length"),
            "max_feature_report_length": d.get("max_feature_report_length"),
        }
    # Keep short-report and long-report HID collections separate.
    # Usage 0x0001 carries normal 7-byte HID++ requests/replies.
    # Usage 0x0002 is opened independently for 20-byte long reports.
    short_tx_candidates = [d for d in ds if int(d.get("interface_number",-1)) == 2
                           and int(d.get("usage_page",0)) == 0xFF00 and int(d.get("usage",0)) == 1]
    short_rx_candidates = [d for d in ds if int(d.get("interface_number",-1)) == 2
                           and int(d.get("usage_page",0)) == 0xFF00 and int(d.get("usage",0)) == 2]
    long_tx_candidates = [d for d in ds if int(d.get("interface_number",-1)) == 2
                          and int(d.get("usage_page",0)) == 0xFF00 and int(d.get("usage",0)) == 2]
    long_rx_candidates = [d for d in ds if int(d.get("interface_number",-1)) == 2
                          and int(d.get("usage_page",0)) == 0xFF00 and int(d.get("usage",0)) == 2]
    short_txi = short_tx_candidates[0] if short_tx_candidates else None
    short_rxi = short_rx_candidates[0] if short_rx_candidates else None
    long_txi = long_tx_candidates[0] if long_tx_candidates else None
    long_rxi = long_rx_candidates[0] if long_rx_candidates else None
    if not short_txi or not short_rxi:
        return {"ok": False, "error": "Interfaces HID++ courts du C547 introuvables",
                "hid_interfaces": [report_caps(d) for d in ds]}
    tx = rx = long_tx = long_rx = None
    def read_reply(timeout=600):
        try:
            b = rx.read(64, timeout)
            return bytes(b) if b else b""
        except Exception:
            return b""
    def request(dev, feat, fn, params=b""):
        packet = bytes([0x10, dev, feat, ((fn & 15) << 4) | 1]) + bytes(params[:3]).ljust(3,b"\0")
        tx.write(list(packet))
        raw = read_reply()
        good = len(raw) >= 7 and raw[0] in (0x10,0x11) and raw[1] == dev and raw[2] == feat
        return raw, good
    def request_dpi(dev, feat, fn, params=b""):
        """Read-only 0x2201 exchange: short TX request, long RX response."""
        packet = bytes([0x10, dev, feat, ((fn & 15) << 4) | 1]) + bytes(params[:3]).ljust(3, b"\0")
        result = {"request_hex": packet.hex(" ").upper(), "request_length": len(packet)}
        raw = b""
        skipped = []
        try:
            for _ in range(64):
                stale = long_rx.read(64, 1)
                if not stale:
                    break
                skipped.append(bytes(stale).hex(" ").upper())
            result["preflush_report_count"] = len(skipped)
            result["write_result"] = tx.write(list(packet))
            result["write_error"] = None
            if result["write_result"] == 7:
                deadline = time.monotonic() + 2.5
                expected_function = ((fn & 15) << 4) | 1
                while time.monotonic() < deadline:
                    candidate = long_rx.read(64, 200)
                    candidate = bytes(candidate) if candidate else b""
                    if not candidate:
                        continue
                    if (len(candidate) >= 20 and candidate[0] == 0x11
                            and candidate[1] == dev and candidate[2] == feat
                            and candidate[3] == expected_function):
                        raw = candidate
                        break
                    skipped.append(candidate.hex(" ").upper())
            result["skipped_reports"] = skipped
            result["read_length"] = len(raw)
            result["read_raw_hex"] = raw.hex(" ").upper() if raw else None
            result["response_valid"] = bool(len(raw) >= 20)
            result["read_error"] = None
        except Exception as exc:
            result.update({
                "write_error": f"{type(exc).__name__}: {exc}",
                "read_length": len(raw),
                "read_raw_hex": raw.hex(" ").upper() if raw else None,
                "response_valid": False
            })
        return raw, bool(result.get("response_valid")), result

    def request_long(dev, feat, fn, params=b""):
        # HID++ long report (20 bytes), read-only memoryRead diagnostic.
        address = bytes(params[:4]).ljust(4, b"\0")
        payload = address + bytes(12)
        packet = bytes([0x11, dev, feat, ((fn & 15) << 4) | 1]) + payload
        result = {"request_hex": packet.hex(" ").upper(), "request_length": len(packet)}
        try:
            import time
            raw = b""
            skipped = []
            preflush = 0
            # IMPORTANT: drain stale reports BEFORE sending the new request.
            for _ in range(64):
                stale = long_rx.read(64, 1)
                if not stale:
                    break
                preflush += 1
                skipped.append({"phase": "before_request",
                                "hex": bytes(stale).hex(" ").upper()})
            result["preflush_report_count"] = preflush
            # Send only after the input queue has been drained.
            try:
                result["write_result"] = long_tx.write(list(packet))
                result["write_error"] = None
            except Exception as exc:
                result["write_result"] = None
                result["write_error"] = f"{type(exc).__name__}: {exc}"
            if result["write_result"] == 20:
                deadline = time.monotonic() + 4.0
                while time.monotonic() < deadline:
                    b = long_rx.read(64, 250)
                    candidate = bytes(b) if b else b""
                    if not candidate:
                        continue
                    matches = (len(candidate) >= 20 and candidate[0] == 0x11
                               and candidate[1] == dev and candidate[2] == feat
                               and candidate[3] == (((fn & 15) << 4) | 1))
                    if matches:
                        raw = candidate
                        break
                    skipped.append({"phase": "after_request",
                                    "hex": candidate.hex(" ").upper()})
            result["skipped_unmatched_reports"] = skipped
            result["read_length"] = len(raw)
            result["read_raw_hex"] = raw.hex(" ").upper() if raw else None
            result["read_error"] = None
        except Exception as exc:
            raw = b""
            result["read_length"] = 0
            result["read_raw_hex"] = None
            result["read_error"] = f"{type(exc).__name__}: {exc}"
        good = len(raw) >= 20 and raw[0] == 0x11 and raw[1] == dev and raw[2] == feat
        result["response_valid"] = bool(good)
        return raw, good, result
    try:
        tx=hid.device(); tx.open_path(short_txi["path"]); tx.set_nonblocking(False)
        rx=hid.device(); rx.open_path(short_rxi["path"]); rx.set_nonblocking(False)
        if long_txi and long_rxi:
            long_tx=hid.device(); long_tx.open_path(long_txi["path"]); long_tx.set_nonblocking(False)
            long_rx=hid.device(); long_rx.open_path(long_rxi["path"]); long_rx.set_nonblocking(False)
        try:
            while rx.read(64,10): pass
        except Exception: pass
        results=[]
        for dev in (1,2):
            entry={"receiver_device_index":dev,"features":{}}
            indexes={}
            for fid in (0x1000,0x1001,0x1004):
                raw,good=request(dev,0,0,bytes([fid>>8,fid&255,0]))
                # Preserve the actual receiver response so feature errors are distinguishable
                # from timeouts. HID++ error replies must never be treated as feature indexes.
                response = {
                    "present": False,
                    "response_received": bool(raw),
                    "response_raw_hex": raw.hex(" ").upper() if raw else None,
                    "response_report_id": raw[0] if raw else None,
                    "response_device_index": raw[1] if len(raw) > 1 else None,
                    "response_feature_index": raw[2] if len(raw) > 2 else None,
                    "response_function": raw[3] if len(raw) > 3 else None,
                    "response_payload_hex": raw[4:].hex(" ").upper() if len(raw) > 4 else None,
                }
                # A successful getFeature response has function 0 and a non-zero index.
                # Error responses are commonly reported with function 8 and are not indexes.
                if (good and len(raw) >= 7 and raw[3] == 0x01 and raw[4] not in (0, 0xFF)):
                    indexes[fid]=raw[4]
                    response.update({"present":True,"index":raw[4],"response_kind":"feature_index"})
                elif raw and len(raw) >= 4 and (raw[3] >> 4) == 8:
                    response["response_kind"]="hidpp_error"
                    response["error_code"]=raw[4] if len(raw)>4 else None
                elif raw:
                    response["response_kind"]="unexpected_response"
                else:
                    response["response_kind"]="timeout"
                entry["features"][f"0x{fid:04X}"]=response
            # Unified Battery 0x1004: fn0 capabilities, fn1 current status.
            if 0x1004 in indexes:
                bidx=indexes[0x1004]
                caps,cok=request(dev,bidx,0,b"\\0\\0\\0")
                status,sok=request(dev,bidx,1,b"\\0\\0\\0")
                batt={"feature":"0x1004","capabilities_read":bool(cok),"status_read":bool(sok)}
                if cok and len(caps)>=6:
                    cap=caps[4:6]
                    batt["percentage_supported"]=bool(cap[1]&0x02)
                    batt["rechargeable"]=bool(cap[1]&0x01)
                    batt["reported_levels_mask"]=cap[0]
                if sok and len(status)>=7:
                    payload=status[4:]
                    batt["level_code"]=payload[1]
                    batt["charging_status_code"]=payload[2]
                    batt["charging_status"]={0:"décharge",1:"charge",2:"charge presque terminée",3:"charge complète",4:"charge lente",5:"batterie invalide",6:"erreur thermique",7:"erreur de charge"}.get(payload[2],"inconnu")
                    batt["percentage"]=payload[0] if batt.get("percentage_supported") and payload[0]<=100 else None
                    batt["coarse_level"]={1:"critique",2:"faible",4:"bon",8:"plein"}.get(payload[1],"inconnu")
                    batt["note"]="Pourcentage affiché uniquement si la capacité SoC est annoncée."
                entry["battery"]=batt
            elif 0x1001 in indexes:
                raw,good=request(dev,indexes[0x1001],0,b"\\0\\0\\0")
                entry["battery"]={"feature":"0x1001","read":bool(good),
                                  "raw_voltage_payload":raw[4:7].hex(" ").upper() if good else None,
                                  "note":"Tension brute uniquement, aucun pourcentage estimé."}
            results.append(entry)
        headset=[]
        try:
            hds=hid.enumerate(0x046D,0x0ABA)
            # PRO X Wireless uses a dedicated HID++ 2.0 collection.
            target=next((d for d in hds if int(d.get("usage_page",0))==0xFF43
                         and int(d.get("usage",0))==0x0202 and d.get("path")), None)
            for d in hds:
                row={"product_id":"0ABA","product":d.get("product_string") or "PRO X Wireless",
                     "interface_number":d.get("interface_number"),
                     "usage_page":d.get("usage_page"),"usage":d.get("usage"),
                     "battery_protocol":"inventaire"}
                if d is target:
                    row["battery_protocol"]="HID++ 2.0 direct / FF43:0202"
                headset.append(row)
            if target:
                hh=None
                try:
                    hh=hid.device()
                    hh.open_path(target["path"])
                    hh.set_nonblocking(False)

                    def hread(timeout=1800):
                        try:
                            b=hh.read(64, timeout)
                            return bytes(b) if b else b""
                        except Exception:
                            return b""

                    def hrequest(feat, fn, params=b"", timeout=1800):
                        packet=bytes([0x11,0xFF,feat,((fn & 15)<<4)|0x0B])+bytes(params[:16]).ljust(16,b"\0")
                        diag={"request_hex":packet[:min(20,len(packet))].hex(" ").upper(),
                              "request_length":20,"preflush_report_count":0}
                        stale=[]
                        try:
                            for _ in range(64):
                                old=hh.read(64,1)
                                if not old:
                                    break
                                stale.append(bytes(old).hex(" ").upper())
                        except Exception:
                            pass
                        diag["preflush_report_count"]=len(stale)
                        diag["preflush_reports"]=stale
                        try:
                            diag["write_result"]=hh.write(list(packet))
                            diag["write_error"]=None
                        except Exception as exc:
                            diag["write_result"]=None
                            diag["write_error"]=f"{type(exc).__name__}: {exc}"
                            diag["read_length"]=0
                            diag["read_raw_hex"]=None
                            diag["response_valid"]=False
                            return b"",False,diag
                        raw=b""
                        skipped=[]
                        expected=((fn & 15)<<4)|0x0B
                        deadline=time.monotonic()+timeout/1000.0
                        while time.monotonic()<deadline:
                            candidate=hread(200)
                            if not candidate:
                                continue
                            # Some firmware returns device index 0x00 on the
                            # direct collection; accept it as well as 0xFF.
                            if (len(candidate)>=20 and candidate[0]==0x11
                                    and candidate[1] in (0x00,0xFF)
                                    and candidate[2]==feat and candidate[3]==expected):
                                raw=candidate
                                break
                            skipped.append(candidate.hex(" ").upper())
                        diag.update({"skipped_reports":skipped,
                                     "read_length":len(raw),
                                     "read_raw_hex":raw.hex(" ").upper() if raw else None,
                                     "response_valid":len(raw)>=20})
                        return raw,len(raw)>=20,diag

                    # Root ping is read-only. Do not require a magic-byte echo:
                    # the transport already matches report/device/function/SWID.
                    ping,ping_ok,ping_diag=hrequest(0,1,b"\0\0\x5A")
                    hb={"read_only":True,"device_index":"0xFF",
                        "transport":"HID++ 2.0 / report 0x11 / usage FF43:0202",
                        "ping_read":bool(ping_ok),"ping_transport":ping_diag,
                        "features":{}}
                    feature_ids=(0x1004,0x1000,0x1001,0x1F20)
                    feature_probes={}
                    hfeatures={}
                    if ping_ok:
                        for fid in feature_ids:
                            raw,good,diag=hrequest(0,0,bytes([fid>>8,fid&255]))
                            feature_probes[f"0x{fid:04X}"]=diag
                            if good and raw[4] not in (0,0xFF):
                                hfeatures[fid]=raw[4]
                    hb["feature_lookup"]=feature_probes
                    for fid,idx in hfeatures.items():
                        hb["features"][f"0x{fid:04X}"]={"present":True,"index":idx}

                    battery=None
                    # Prefer a device-supplied percentage where supported.
                    if 0x1004 in hfeatures:
                        idx=hfeatures[0x1004]
                        raw,good,diag=hrequest(idx,1,b"")
                        if good:
                            payload=raw[4:8]
                            battery={"feature":"0x1004","feature_index":idx,
                                     "read":True,"percentage":payload[0] if payload[0]<=100 else None,
                                     "level_flags":payload[1],"charging_status_code":payload[2],
                                     "charging_status":{0:"décharge",1:"charge",2:"charge lente",
                                                        3:"charge complète",4:"erreur"}.get(payload[2],"inconnu"),
                                     "transport":diag,"percentage_type":"fourni par le périphérique"}
                    # PRO X Wireless is documented to use ADC_MEASUREMENT 0x1F20.
                    if battery is None and 0x1F20 in hfeatures:
                        idx=hfeatures[0x1F20]
                        raw,good,diag=hrequest(idx,0,b"")
                        if good:
                            payload=raw[4:7]
                            voltage=int.from_bytes(payload[0:2],"big")
                            flags=payload[2]
                            status={0x01:"décharge",0x03:"charge",0x07:"charge complète",
                                    0x0F:"inconnu"}.get(flags,"inconnu")
                            adc_curve=[4030,4024,4018,4011,4003,3994,3985,3975,3963,3951,
                                3937,3922,3907,3893,3880,3868,3857,3846,3837,3828,
                                3820,3812,3805,3798,3791,3785,3779,3773,3768,3762,
                                3757,3752,3747,3742,3738,3733,3729,3724,3720,3716,
                                3712,3708,3704,3700,3696,3692,3688,3685,3681,3677,
                                3674,3670,3667,3663,3660,3657,3653,3650,3646,3643,
                                3640,3637,3633,3630,3627,3624,3620,3617,3614,3611,
                                3608,3604,3601,3598,3595,3592,3589,3585,3582,3579,
                                3576,3573,3569,3566,3563,3560,3556,3553,3550,3546,
                                3543,3539,3536,3532,3529,3525,3499,3466,3433,3399]
                            percent=0
                            for i,v in enumerate(adc_curve):
                                if voltage>=v:
                                    percent=100-i
                                    break
                            battery={"feature":"0x1F20","feature_index":idx,"read":True,
                                     "voltage_mV":voltage,"charging_status_code":flags,
                                     "charging_status":status,"percentage_estimate":percent,
                                     "percentage_is_estimate":True,
                                     "percentage_curve":"Linux HID Logitech ADC 1F20 (HeadsetControl-derived)",
                                     "transport":diag,
                                     "note":"Pourcentage estimé depuis la tension; le casque ne fournit pas directement un pourcentage."}
                    if battery is None:
                        battery={"read":False,
                                 "note":"Aucune fonction batterie compatible n'a répondu. Diagnostic HID++ conservé.",
                                 "features_found":list(hb["features"].keys())}
                    hb["battery"]=battery
                    hb["connected"]=bool(ping_ok and battery.get("read"))
                    hb["note"]="Lecture HID++ directe en lecture seule. Aucun profil, réglage audio ou appairage modifié."
                    headset.append({"device":"PRO X Wireless","battery_diagnostic":hb})
                except Exception as e:
                    headset.append({"device":"PRO X Wireless","battery_diagnostic":{
                        "read":False,"error":f"{type(e).__name__}: {e}","read_only":True}})
                finally:
                    try:
                        if hh: hh.close()
                    except Exception: pass
        except Exception as e:
            headset.append({"device":"PRO X Wireless","battery_diagnostic":{
                "read":False,"error":f"{type(e).__name__}: {e}","read_only":True}})
        return {"ok":True,"receiver":"Logitech LIGHTSPEED C547","devices":results,
                "headset_usb_interfaces":headset,
                "read_only":True,
                "note":"Index 1 et 2 sondés en lecture seule. Profils embarqués détectés sans lecture/écriture. Casque PRO X Wireless sondé sur sa collection HID++ dédiée avec lecture batterie 0x1F20. Aucune modification des périphériques, de G HUB ou de l’appairage."}
    except Exception as e:
        return {"ok":False,"error":f"{type(e).__name__}: {e}"}
    finally:
        for h in (tx,rx):
            try:
                if h: h.close()
            except Exception: pass


PAGE = """<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PROJECT EDGE V2.9</title>
<style>
*{box-sizing:border-box}body{margin:0;padding:24px;background:radial-gradient(ellipse at top,#17334b,#080d16 65%);color:#eaf5ff;font:15px Segoe UI,Arial}main{max-width:1050px;margin:auto}h1{color:#38c5ff;letter-spacing:.12em}.muted{color:#91a9bd;font-size:12px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px;margin:20px 0}.card,.panel{background:#111e2d;border:1px solid #29485e;border-radius:15px;padding:19px}.card{min-height:180px}.big{font-size:36px;font-weight:bold;margin:16px 0 5px}.detail{font-size:13px;line-height:1.7;color:#b8cada}.track{height:8px;background:#293b4c;border-radius:8px;margin:10px 0;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,#20a9df,#66e0b2)}button{background:#087db2;color:white;border:0;border-radius:8px;padding:11px 16px;font-weight:bold;cursor:pointer}.secondary{background:#203246}.ok{color:#6fe0a2}.warn{color:#ffc078}pre{white-space:pre-wrap;word-break:break-word;color:#9ee6ff;font-size:12px;max-height:350px;overflow:auto}.hidden{display:none}
</style><main><h1>PROJECT EDGE</h1><p class="muted">LOGITECH BRIDGE · V2.9 · Lecture seule</p><b>ÉTAT DES PÉRIPHÉRIQUES</b><span class="muted" id="updated" style="float:right">Initialisation…</span>
<section class="cards" id="cards"><article class="card">Lecture en cours…</article></section><p id="state" class="muted">Connexion au service…</p>
<p><button onclick="refresh()">ACTUALISER</button> <button class="secondary" onclick="document.getElementById('rawbox').classList.toggle('hidden')">DÉTAILS TECHNIQUES</button></p>
<div class="panel hidden" id="rawbox"><b>Diagnostic HID++ brut</b><pre id="raw"></pre></div><div class="panel"><b>Connexion depuis PROJECT EDGE sur iPhone</b><pre id="ips">Chargement…</pre></div>
<p class="muted">Actualisation automatique toutes les 5 secondes. Aucune modification des périphériques ou de G HUB.</p>
<script>
let data=null,busy=false;function esc(x){return String(x??"—").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function tile(n,sub,b,extra=""){if(!b||!(b.read||b.status_read||b.percentage!==undefined||b.level_code!==undefined||b.raw_voltage_payload))return `<article class="card"><b>${n}</b><div class="muted">${sub}</div><div class="big">—</div><span class="warn">Lecture indisponible</span>${extra}</article>`;let p=Number.isFinite(b.percentage)?b.percentage:(Number.isFinite(b.percentage_estimate)?b.percentage_estimate:null);let coarse=({critique:"Critique",faible:"Faible",bon:"Bon",plein:"Plein"})[b.coarse_level]||b.coarse_level||"Lecture effectuée";return `<article class="card"><b>${n}</b><div class="muted">${sub}</div><div class="big">${p===null?esc(coarse):p+"%"}</div>${p===null?"":`<div class="track"><div class="fill" style="width:${Math.max(0,Math.min(100,p))}%"></div></div>`}<div class="detail">${esc(b.charging_status||"État inconnu")}${b.voltage_mV?" · "+b.voltage_mV+" mV":""}</div>${b.percentage_is_estimate?'<div class="muted warn">Pourcentage estimé depuis la tension</div>':""}${extra}</article>`;}
function render(d){let a=d.devices||[],k=a.find(x=>x.device_index===1||x.receiver_device_index===1)||a[0],m=a.find(x=>x.device_index===2||x.receiver_device_index===2)||a[1],h=(d.headset_usb_interfaces||[]).find(x=>x.device==="PRO X Wireless"),hb=h?.battery_diagnostic?.battery;let sensor=m?.dpi?.sensors?.[0]||{},dpi=sensor.current_dpi??m?.dpi?.current_dpi??m?.current_dpi??"—",def=sensor.default_dpi??m?.dpi?.default_dpi??m?.default_dpi??"—",st=m?.onboard_profiles?.configured_dpi?.stages??m?.dpi?.configured_stages;document.getElementById("cards").innerHTML=tile("G915 X LIGHTSPEED","Clavier · récepteur C547",k?.battery)+tile("G502 X LIGHTSPEED","Souris · récepteur C547",m?.battery,`<div class="detail">DPI actuel : <b>${esc(dpi)}</b> · Défaut : <b>${esc(def)}</b><br>Paliers : ${esc(Array.isArray(st)?st.join(" · "):"—")}</div>`)+tile("PRO X Wireless","Casque · USB dédié",hb,`<div class="detail ${h?.battery_diagnostic?.connected?"ok":"warn"}">${h?.battery_diagnostic?.connected?"Casque connecté":"Casque non détecté"}</div>`);document.getElementById("updated").textContent="Mis à jour à "+new Date().toLocaleTimeString();document.getElementById("state").innerHTML=d.ok?'<span class="ok">● Service actif · lecture terminée</span>':'<span class="warn">Diagnostic incomplet</span>';document.getElementById("raw").textContent=JSON.stringify(d,null,2);}
async function refresh(){if(busy)return;busy=true;try{let r=await fetch("/api/diagnostic",{cache:"no-store"});if(!r.ok)throw Error("HTTP "+r.status);data=await r.json();render(data);}catch(e){document.getElementById("state").textContent="Erreur : "+e.message;}finally{busy=false;}}
fetch("/api/info").then(r=>r.json()).then(d=>document.getElementById("ips").textContent=(d.addresses||[]).map(x=>"http://"+x+":8765").join("\\n")||"Adresse non détectée");refresh();setInterval(refresh,5000);
</script></main></html>"""

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload, content_type="application/json; charset=utf-8"):
        raw = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self._send(204, "")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if path == "/api/info":
            return self._send(200, {"service": "PROJECT EDGE Logitech Bridge", "version": "2.9.2", "read_only": True, "addresses": local_ips()})
        if path == "/api/inventory":
            result = enumerate_logitech()
            return self._send(200, {"service":"PROJECT EDGE Logitech Bridge","version":"2.9.2",
                                    "read_only":True,"inventory":result})
        if path == "/api/status":
            result = enumerate_logitech()
            result.update({"service": "PROJECT EDGE Logitech Bridge", "version": "2.9.2", "read_only": True, "timestamp": int(time.time()), "hidapi_available": result.get("available", False)})
            return self._send(200, result)
        if path == "/api/diagnostic":
            result = cached_diagnostic()
            result.update({"service": "PROJECT EDGE Logitech Bridge", "version": "2.9.2", "timestamp": int(time.time()), "read_only": True})
            return self._send(200, result)
        return self._send(404, {"error": "Not found"})

    def log_message(self, fmt, *args):
        print("[HTTP]", fmt % args)

if __name__ == "__main__":
    print("=" * 60)
    print(" PROJECT EDGE - LOGITECH BRIDGE V2.9.2 (LECTURE SEULE)")
    print(" Aucune écriture aucun changement G HUB")
    print("=" * 60)
    print("PC local : http://127.0.0.1:%d" % PORT)
    for ip in local_ips():
        print("iPhone / réseau local : http://%s:%d" % (ip, PORT))
    print("Arrêt : CTRL+C")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
