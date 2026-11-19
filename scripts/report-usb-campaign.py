#!/usr/bin/env python3
"""Create byte-level TXT/HTML/JSON reports for a whole USB fuzz campaign.

Compares descriptor bytes expected from each case JSON profile against the
USBPcap/tshark observations assigned to that case by capture time. A single
PCAPNG may contain the whole campaign. PCAP is a host-stack observation, not
an electrical USB analyzer; timestamps must be reasonably synchronized.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "frame_number": ("frame.number",),
    "time_epoch": ("frame.time_epoch",),
    "bus_id": ("usb.bus_id",),
    "device_address": ("usb.device_address",),
    "urb_id": ("usb.urb_id",),
    "irp_id": ("usb.irp_id",),
    "urb_type": ("usb.urb_type",),
    "urb_function": ("usb.urb_function",),
    "control_stage": ("usb.control_stage",),
    "endpoint_address": ("usb.endpoint_address",),
    "transfer_type": ("usb.transfer_type",),
    "urb_status": ("usb.usbd_status", "usb.irp_usbd_status", "usb.urb_status"),
    "request_type": ("usb.bmRequestType", "usb.setup.bmRequestType"),
    "bRequest": ("usb.setup.bRequest",),
    "wValue": ("usb.setup.wValue",),
    "wIndex": ("usb.setup.wIndex",),
    "wLength": ("usb.setup.wLength",),
    "data_len": ("usb.data_len",),
    "capdata": ("usb.capdata",),
    "data_fragment": ("usb.data_fragment",),
    "control_response": ("usb.control.Response",),
    "get_descriptor_response": ("usb.getDescriptor.Response",),
    "idVendor": ("usb.idVendor",),
    "idProduct": ("usb.idProduct",),
}
DESC_NAMES = {
    1: "Device", 2: "Configuration", 3: "String", 4: "Interface",
    5: "Endpoint", 6: "Device Qualifier", 7: "Other-speed Configuration",
    15: "BOS", 16: "Device Capability", 0x21: "HID", 0x22: "HID Report",
    0x23: "Physical", 0x30: "SuperSpeed Endpoint Companion",
}
REQ_NAMES = {0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE", 5: "SET_ADDRESS",
             6: "GET_DESCRIPTOR", 8: "GET_CONFIGURATION", 9: "SET_CONFIGURATION",
             10: "GET_INTERFACE", 11: "SET_INTERFACE"}


def import_verifier():
    path = ROOT / "scripts" / "verify-usb-case.py"
    if not path.is_file():
        raise RuntimeError(f"не найден компилятор ожидаемых дескрипторов: {path}")
    spec = importlib.util.spec_from_file_location("usb_case_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"не удалось загрузить {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        m = re.search(r"\(\s*(-?0x[0-9a-fA-F]+|-?\d+)\s*\)", text)
        if m:
            try:
                return int(m.group(1), 0)
            except ValueError:
                pass
        try:
            return int(text, 10)
        except ValueError:
            # A tshark enum may look like "GET DESCRIPTOR (6)".
            m = re.search(r"\((-?\d+)\)\s*$", text)
            return int(m.group(1)) if m else None


def parse_hex_field(value: Any) -> bytes | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s in ("<MISSING>", "N/A", "No data"):
        return None
    # tshark fields for USB byte arrays are usually colon-separated hex.
    if not re.fullmatch(r"[0-9a-fA-F\s:.,-]+", s):
        return None
    compact = re.sub(r"[\s:.,-]", "", s)
    if not compact or len(compact) % 2:
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def load_campaign_rows(campaign_dir: Path) -> list[dict[str, Any]]:
    p = campaign_dir / "campaign.jsonl"
    rows = []
    if p.is_file():
        for line_no, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{p}:{line_no}: некорректный JSON: {exc}") from exc
            if isinstance(row, dict) and row.get("case") is not None:
                rows.append(row)
    return rows


def merge_manifest_cases(campaign_dir: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Include generated-but-not-run profiles, so interrupted campaigns remain complete in reports."""
    existing = {int(r.get("case", -1)) for r in rows if r.get("case") is not None}
    manifest_path = campaign_dir / "manifest.json"
    if not manifest_path.is_file():
        return rows
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return rows
    for item in manifest.get("cases", []) if isinstance(manifest, dict) else []:
        try:
            number = int(item.get("case"))
        except (TypeError, ValueError):
            continue
        if number in existing:
            # Trace/run rows carry authoritative final status and timestamps; retain manifest changes if missing.
            prior = next(r for r in rows if int(r.get("case", -1)) == number)
            if not prior.get("changes") and item.get("changes"):
                prior["changes"] = item.get("changes")
            if not prior.get("profile") and item.get("profile"):
                prior["profile"] = item.get("profile")
            for identity_field in ("campaign_id", "device_id", "serial_number"):
                if not prior.get(identity_field) and item.get(identity_field):
                    prior[identity_field] = item.get(identity_field)
            continue
        rows.append({**item, "case": number, "status": "NOT_RUN", "started_epoch": None,
                     "ended_epoch": None, "profile": item.get("profile"), "trace": None,
                     "note": "Профиль сгенерирован, но в campaign.jsonl нет записи о запуске."})
    return rows


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events = []
    if not path.is_file():
        return events
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: некорректный JSON: {exc}") from exc
        if isinstance(item, dict):
            events.append(item)
    return events


def available_tshark_fields(tshark: str) -> set[str]:
    result = subprocess.run([tshark, "-G", "fields"], text=True, capture_output=True, errors="replace", timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"tshark -G fields завершился с кодом {result.returncode}: {(result.stderr or '')[-2000:]}")
    fields = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            fields.add(parts[2].strip())
    return fields


def select_field_map(available: set[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for logical, candidates in FIELD_CANDIDATES.items():
        match = next((f for f in candidates if f in available), None)
        if match:
            mapping[logical] = match
    for required in ("frame_number", "time_epoch"):
        if required not in mapping:
            raise RuntimeError(f"tshark не предоставляет обязательное поле {FIELD_CANDIDATES[required][0]}")
    for required in ("request_type", "bRequest", "wValue", "wIndex", "wLength"):
        if required not in mapping:
            rendered = ", ".join(FIELD_CANDIDATES[x][0] for x in ("request_type", "bRequest", "wValue", "wIndex", "wLength"))
            raise RuntimeError(f"tshark не предоставляет одно или несколько обязательных полей setup: {rendered}; проверь версию Wireshark и декодирование USBPcap")
    return mapping


def parse_request_code(value: Any) -> int | None:
    number = parse_int(value)
    if number is not None:
        return number
    names = {"GET STATUS": 0, "CLEAR FEATURE": 1, "SET FEATURE": 3, "SET ADDRESS": 5,
             "GET DESCRIPTOR": 6, "SET DESCRIPTOR": 7, "GET CONFIGURATION": 8,
             "SET CONFIGURATION": 9, "GET INTERFACE": 10, "SET INTERFACE": 11}
    text = re.sub(r"\s+", " ", str(value or "").strip().upper().replace("_", " "))
    return next((code for name, code in names.items() if text == name or text.startswith(name + " ")), None)


def normalize_field_row(raw: dict[str, str], mapping: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for logical, field in mapping.items():
        value = (raw.get(field) or "").strip()
        if logical in ("capdata", "data_fragment", "control_response", "get_descriptor_response"):
            out[logical] = value or None
        elif logical == "time_epoch":
            try:
                out[logical] = float(value) if value else None
            except ValueError:
                out[logical] = None
        elif logical in ("urb_id", "irp_id"):
            out[logical] = value or None
        elif logical in ("urb_type", "urb_function", "control_stage", "transfer_type", "urb_status"):
            out[logical] = value or None
        elif logical == "bRequest":
            out[logical] = parse_request_code(value)
        else:
            out[logical] = parse_int(value)
    out["request"] = None
    if out.get("bRequest") is not None and out.get("wValue") is not None:
        out["request"] = {
            "bmRequestType": out.get("request_type") if out.get("request_type") is not None else 0,
            "bRequest": out.get("bRequest"),
            "wValue": out.get("wValue", 0),
            "wIndex": out.get("wIndex") or 0,
            "wLength": out.get("wLength") or 0,
        }
    return out


def read_tshark_rows(pcap: Path, tshark: str) -> tuple[list[dict[str, Any]], list[str]]:
    exe = shutil.which(tshark) or (tshark if Path(tshark).is_file() else None)
    if not exe:
        raise RuntimeError(f"tshark не найден: {tshark}. На Raspberry Pi установи: sudo apt install tshark")
    available = available_tshark_fields(exe)
    mapping = select_field_map(available)
    fields = list(mapping.values())
    cmd = [exe, "-r", str(pcap), "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in fields:
        cmd.extend(["-e", field])
    result = subprocess.run(cmd, text=True, capture_output=True, errors="replace", timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"tshark не смог прочитать PCAPNG: {(result.stderr or result.stdout)[-4000:]}")
    reader = csv.DictReader(result.stdout.splitlines(), delimiter="\t", quotechar='"')
    rows = [normalize_field_row(row, mapping) for row in reader]
    rows.sort(key=lambda r: (r.get("frame_number") if r.get("frame_number") is not None else 0))
    return rows, fields


def _pcapng_blocks(path: Path):
    """Yield (block_type, endian, block_start, block_length) for a PCAPNG file."""
    data = path.read_bytes()
    offset = 0
    endian = "<"
    while offset + 12 <= len(data):
        raw_type = data[offset:offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError(f"PCAPNG: неизвестный byte-order magic на offset {offset}: {bom.hex()}")
        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or block_len % 4 or offset + block_len > len(data):
            raise ValueError(f"PCAPNG: некорректная длина блока {block_len} на offset {offset}")
        trailer = struct.unpack_from(endian + "I", data, offset + block_len - 4)[0]
        if trailer != block_len:
            raise ValueError(f"PCAPNG: длина в конце блока не совпадает на offset {offset}")
        yield data, block_type, endian, offset, block_len
        offset += block_len
    if offset != len(data):
        raise ValueError(f"PCAPNG: {len(data) - offset} лишних байт в конце файла")


def pcapng_linktypes(path: Path) -> list[int]:
    """Return link types for interfaces in a PCAPNG capture."""
    result: list[int] = []
    for data, block_type, endian, offset, block_len in _pcapng_blocks(path):
        if block_type == 1:  # Interface Description Block
            if block_len < 20:
                raise ValueError(f"PCAPNG: слишком короткий Interface Description Block на offset {offset}")
            result.append(struct.unpack_from(endian + "H", data, offset + 8)[0])
    return result


def read_usbpcap_pcapng_rows(path: Path, skip_packets: int = 6) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Decode USBPcap linktype 249 directly; does not depend on TShark field names.

    Frame numbers stay one-based and refer to the original capture. The skip count
    is applied to packet records before USBPcap decoding, exactly as requested.
    """
    if skip_packets < 0:
        raise ValueError("skip_packets must be >= 0")
    interfaces: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    packet_number = 0
    packet_count = 0
    skipped = 0
    saw_pcapng = False

    for data, block_type, endian, offset, block_len in _pcapng_blocks(path):
        if block_type == 0x0A0D0D0A:
            saw_pcapng = True
            interfaces = []
            continue
        if block_type == 1:  # IDB
            linktype = struct.unpack_from(endian + "H", data, offset + 8)[0]
            snaplen = struct.unpack_from(endian + "I", data, offset + 12)[0]
            ts_resolution = 1e-6  # PCAPNG default
            option_offset = offset + 16
            option_end = offset + block_len - 4
            while option_offset + 4 <= option_end:
                code, length = struct.unpack_from(endian + "HH", data, option_offset)
                option_offset += 4
                if code == 0:
                    break
                value = data[option_offset:option_offset + length]
                if code == 9 and length == 1:  # if_tsresol
                    raw = value[0]
                    if raw & 0x80:
                        ts_resolution = 2.0 ** -(raw & 0x7f)
                    else:
                        ts_resolution = 10.0 ** -raw
                option_offset += (length + 3) & ~3
            interfaces.append({"linktype": linktype, "snaplen": snaplen, "ts_resolution": ts_resolution})
            continue

        packet = None
        interface_id = 0
        timestamp = None
        if block_type == 6:  # Enhanced Packet Block
            if block_len < 32:
                warnings.append(f"EPB at {offset} is too short")
                continue
            interface_id, ts_high, ts_low, caplen, origlen = struct.unpack_from(endian + "IIIII", data, offset + 8)
            packet_start = offset + 28
            packet = data[packet_start:packet_start + caplen]
            if interface_id < len(interfaces):
                timestamp = ((ts_high << 32) | ts_low) * interfaces[interface_id]["ts_resolution"]
        elif block_type == 2:  # obsolete Packet Block
            if block_len < 32:
                warnings.append(f"Packet Block at {offset} is too short")
                continue
            interface_id = struct.unpack_from(endian + "H", data, offset + 8)[0]
            ts_high, ts_low, caplen, origlen = struct.unpack_from(endian + "IIII", data, offset + 12)
            packet_start = offset + 28
            packet = data[packet_start:packet_start + caplen]
            if interface_id < len(interfaces):
                timestamp = ((ts_high << 32) | ts_low) * interfaces[interface_id]["ts_resolution"]
        elif block_type == 3:  # Simple Packet Block (no timestamp)
            if block_len < 16:
                warnings.append(f"Simple Packet Block at {offset} is too short")
                continue
            origlen = struct.unpack_from(endian + "I", data, offset + 8)[0]
            interface = interfaces[0] if interfaces else {"snaplen": origlen, "linktype": None}
            caplen = min(origlen, interface.get("snaplen") or origlen)
            packet = data[offset + 12:offset + 12 + caplen]
            interface_id = 0
        else:
            continue

        if packet is None:
            continue
        packet_number += 1
        packet_count += 1
        if packet_number <= skip_packets:
            skipped += 1
            continue
        if interface_id >= len(interfaces):
            warnings.append(f"frame {packet_number}: interface_id {interface_id} is not defined")
            continue
        interface = interfaces[interface_id]
        if interface["linktype"] != 249:
            warnings.append(f"frame {packet_number}: skipped non-USBPcap linktype {interface['linktype']}")
            continue
        if len(packet) < 27:
            warnings.append(f"frame {packet_number}: USBPcap header is shorter than 27 bytes")
            continue

        header_len = struct.unpack_from("<H", packet, 0)[0]
        irp_id = struct.unpack_from("<Q", packet, 2)[0]
        usbd_status = struct.unpack_from("<I", packet, 10)[0]
        function = struct.unpack_from("<H", packet, 14)[0]
        info = packet[16]
        bus_id = struct.unpack_from("<H", packet, 17)[0]
        device_address = struct.unpack_from("<H", packet, 19)[0]
        endpoint_address = packet[21]
        transfer_type = packet[22]
        data_length = struct.unpack_from("<I", packet, 23)[0]
        if header_len < 27 or header_len > len(packet):
            warnings.append(f"frame {packet_number}: invalid USBPcap headerLen={header_len}, packet={len(packet)}")
            continue
        stage = packet[27] if transfer_type == 2 and header_len >= 28 and len(packet) >= 28 else None
        available_len = max(0, len(packet) - header_len)
        payload = packet[header_len:header_len + min(data_length, available_len)]
        truncated = data_length > available_len

        request = None
        if transfer_type == 2 and stage == 0 and len(payload) >= 8:
            bm, br, wv, wi, wl = struct.unpack_from("<BBHHH", payload, 0)
            request = {"bmRequestType": bm, "bRequest": br, "wValue": wv, "wIndex": wi, "wLength": wl}

        # USBPcap info bit 0 means the record travels PDO -> FDO (completion side).
        # For control transfers the explicit stage byte is authoritative.
        if transfer_type == 2:
            urb_type = "S" if stage == 0 else ("C" if stage == 3 else "?")
        else:
            urb_type = "C" if (info & 1) else "S"

        fn_name = {0x0008: "URB_FUNCTION_CONTROL_TRANSFER",
                   0x000B: "URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE"}.get(function, f"URB_FUNCTION_0x{function:04x}")
        irp_text = f"0x{irp_id:016x}" if irp_id else None
        hex_colon = ":".join(f"{byte:02x}" for byte in payload) if payload else None
        row: dict[str, Any] = {
            "frame_number": packet_number,
            "time_epoch": timestamp,
            "bus_id": bus_id,
            "device_address": device_address,
            "irp_id": irp_text,
            "urb_id": irp_text,
            "urb_type": urb_type,
            "urb_function": fn_name,
            "control_stage": stage,
            "urb_status": usbd_status,
            "endpoint_address": endpoint_address,
            "transfer_type": transfer_type,
            "request": request,
            "data_len": data_length,
            "usbpcap_info": info,
            "usbpcap_function": function,
            "usbpcap_header_len": header_len,
            "usbpcap_stage": stage,
            "payload_truncated": truncated,
        }
        if transfer_type == 2 and stage == 3:
            row["control_response"] = hex_colon
            row["get_descriptor_response"] = hex_colon if request is not None and request.get("bRequest") == 6 else None
        elif transfer_type == 2 and stage in (1, 2):
            row["data_fragment"] = hex_colon
        elif transfer_type != 2:
            row["capdata"] = hex_colon
        rows.append(row)

    if not saw_pcapng:
        raise ValueError("Файл не является PCAPNG; native USBPcap parser не применим")
    if not interfaces:
        raise ValueError("PCAPNG не содержит Interface Description Block")
    if not any(x["linktype"] == 249 for x in interfaces):
        raise ValueError(f"В PCAPNG нет USBPcap linktype 249; linktypes={pcapng_linktypes(path)}")
    if not rows:
        raise ValueError(f"После пропуска первых {skip_packets} пакетов не осталось корректных USBPcap-пакетов")
    meta = {"parser": "native_usbpcap_pcapng", "linktypes": [x["linktype"] for x in interfaces],
            "packet_count": packet_count, "skipped_packets": skipped,
            "first_included_frame": skip_packets + 1, "decoded_packet_rows": len(rows),
            "parse_warnings": warnings}
    return rows, meta


def read_host_capture_rows(pcap: Path, tshark: str, skip_packets: int = 6) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Prefer exact native USBPcap decoding; retain TShark fallback for other link types."""
    try:
        linktypes = pcapng_linktypes(pcap)
    except Exception:
        linktypes = []
    if 249 in linktypes:
        rows, meta = read_usbpcap_pcapng_rows(pcap, skip_packets=skip_packets)
        return rows, ["USBPcap native fields (linktype 249)"], meta
    rows, fields = read_tshark_rows(pcap, tshark)
    # The six-record exclusion is a capture-specific USBPcap rule, not a generic
    # TShark rule. JSON/fake-tshark fixtures and unrelated link types must not
    # silently lose their first six rows.
    classic_linktype = None
    try:
        with pcap.open("rb") as stream:
            header = stream.read(24)
        if len(header) >= 24:
            magic = header[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                classic_linktype = struct.unpack_from("<I", header, 20)[0]
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                classic_linktype = struct.unpack_from(">I", header, 20)[0]
    except OSError:
        pass
    should_skip = skip_packets if classic_linktype == 249 else 0
    packet_count = len(rows)
    skipped = min(should_skip, packet_count)
    rows = rows[skipped:]
    return rows, fields, {"parser": "tshark", "linktypes": [classic_linktype] if classic_linktype is not None else [],
                          "packet_count": packet_count, "skipped_packets": skipped,
                          "first_included_frame": skipped + 1, "decoded_packet_rows": len(rows),
                          "skip_policy": "USBPcap-only" if classic_linktype == 249 else "not-applied-non-USBPcap",
                          "parse_warnings": []}


def urb_class(value: Any) -> str:
    s = str(value or "").strip().upper()
    if s in {"S", "SUBMIT"} or s.startswith("SUBMIT"):
        return "S"
    if s in {"C", "COMPLETE", "COMPLETED"} or s.startswith("COMPLETE"):
        return "C"
    if s in {"E", "ERROR"} or s.startswith("ERROR"):
        return "E"
    return "?"


URB_FUNCTION_NAMES = {
    0x0000: "SELECT_CONFIGURATION", 0x0001: "SELECT_INTERFACE",
    0x0002: "ABORT_PIPE", 0x0008: "CONTROL_TRANSFER",
    0x0009: "BULK_OR_INTERRUPT_TRANSFER", 0x000A: "ISOCH_TRANSFER",
    0x000B: "GET_DESCRIPTOR_FROM_DEVICE", 0x001E: "SYNC_RESET_PIPE_AND_CLEAR_STALL",
    0x0030: "SYNC_RESET_PIPE", 0x0031: "SYNC_CLEAR_STALL",
}
USBD_STATUS_NAMES = {
    0x00000000: "USBD_STATUS_SUCCESS",
    0x40000000: "USBD_STATUS_PENDING",
    0x80000200: "USBD_STATUS_INVALID_URB_FUNCTION",
    0x80000300: "USBD_STATUS_INVALID_PARAMETER",
    0x80000400: "USBD_STATUS_ERROR_BUSY",
    0x80000600: "USBD_STATUS_INVALID_PIPE_HANDLE",
    0x80000700: "USBD_STATUS_NO_BANDWIDTH",
    0x80000800: "USBD_STATUS_INTERNAL_HC_ERROR",
    0x80000900: "USBD_STATUS_ERROR_SHORT_TRANSFER",
    0xC0000001: "USBD_STATUS_CRC",
    0xC0000002: "USBD_STATUS_BTSTUFF",
    0xC0000003: "USBD_STATUS_DATA_TOGGLE_MISMATCH",
    0xC0000004: "USBD_STATUS_STALL_PID",
    0xC0000005: "USBD_STATUS_DEV_NOT_RESPONDING",
    0xC0000006: "USBD_STATUS_PID_CHECK_FAILURE",
    0xC0000007: "USBD_STATUS_UNEXPECTED_PID",
    0xC0000008: "USBD_STATUS_DATA_OVERRUN",
    0xC0000009: "USBD_STATUS_DATA_UNDERRUN",
    0xC0010000: "USBD_STATUS_CANCELED",
}


def urb_function_code(row: dict[str, Any]) -> int | None:
    value = parse_int(row.get("usbpcap_function"))
    if value is not None:
        return value
    text = str(row.get("urb_function") or "")
    match = re.search(r"0x([0-9a-fA-F]{1,4})", text)
    if match:
        return int(match.group(1), 16)
    for code, name in URB_FUNCTION_NAMES.items():
        if name in text.upper():
            return code
    return None


def usbd_status_name(value: Any) -> str:
    code = parse_int(value)
    if code is None:
        return str(value or "UNKNOWN")
    return USBD_STATUS_NAMES.get(code, f"USBD_STATUS_0x{code:08X}")


def build_transfer_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pair USBPcap submit/complete records by IRP ID for control and data URBs."""
    groups: list[dict[str, Any]] = []
    pending: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)

    def make_group(row: dict[str, Any]) -> dict[str, Any]:
        endpoint = parse_int(row.get("endpoint_address"))
        transfer_type = parse_int(row.get("transfer_type"))
        g = {"rows": [row], "request": row.get("request"), "first_time": row.get("time_epoch"),
             "last_time": row.get("time_epoch"), "frame_numbers": [row.get("frame_number")],
             "bus_id": row.get("bus_id"), "device_address": row.get("device_address"),
             "endpoint_address": endpoint, "transfer_type": transfer_type,
             "direction": ("device_to_host" if endpoint is not None and endpoint & 0x80 else "host_to_device") if endpoint else None,
             "urb_id": row.get("irp_id") or row.get("urb_id"), "irp_id": row.get("irp_id"),
             "urb_types": [urb_class(row.get("urb_type"))],
             "urb_functions": [row.get("urb_function")],
             "urb_function_codes": [urb_function_code(row)],
             "is_abort_pipe": urb_function_code(row) == 0x0002,
             "is_irp_info": transfer_type == 0xFE,
             "control_stages": [row.get("control_stage")],
             "control_request_seen": row.get("request") is not None,
             "complete_seen": urb_class(row.get("urb_type")) in {"C", "E"} or parse_int(row.get("control_stage")) == 3}
        groups.append(g)
        return g

    def append_to_group(g: dict[str, Any], row: dict[str, Any]) -> None:
        g["rows"].append(row)
        if row.get("time_epoch") is not None:
            g["last_time"] = row.get("time_epoch")
        if row.get("frame_number") is not None:
            g["frame_numbers"].append(row.get("frame_number"))
        g["urb_types"].append(urb_class(row.get("urb_type")))
        g["urb_functions"].append(row.get("urb_function"))
        fn_code = urb_function_code(row)
        g.setdefault("urb_function_codes", []).append(fn_code)
        g["is_abort_pipe"] = bool(g.get("is_abort_pipe")) or fn_code == 0x0002
        g["is_irp_info"] = bool(g.get("is_irp_info")) or parse_int(row.get("transfer_type")) == 0xFE
        g["control_stages"].append(row.get("control_stage"))
        if row.get("request") is not None:
            g["request"] = row.get("request")
            g["control_request_seen"] = True
        if g.get("endpoint_address") is None:
            g["endpoint_address"] = parse_int(row.get("endpoint_address"))
        if g.get("transfer_type") is None:
            g["transfer_type"] = parse_int(row.get("transfer_type"))
        if g.get("direction") is None and g.get("endpoint_address") is not None:
            g["direction"] = "device_to_host" if int(g["endpoint_address"]) & 0x80 else "host_to_device"
        if urb_class(row.get("urb_type")) in {"C", "E"} or parse_int(row.get("control_stage")) == 3:
            g["complete_seen"] = True

    for row in sorted(rows, key=lambda r: parse_int(r.get("frame_number")) or 0):
        irp = row.get("irp_id") or row.get("urb_id")
        stage = parse_int(row.get("control_stage"))
        transfer_type = parse_int(row.get("transfer_type"))
        fn = str(row.get("urb_function") or "").upper()
        typ = urb_class(row.get("urb_type"))
        is_control = transfer_type == 2 or stage is not None or "CONTROL_TRANSFER" in fn or "GET_DESCRIPTOR_FROM_DEVICE" in fn
        is_setup = (row.get("request") is not None and (stage == 0 or "GET_DESCRIPTOR_FROM_DEVICE" in fn))
        is_control_complete = is_control and (stage == 3 or ("CONTROL_TRANSFER" in fn and row.get("request") is None))
        if irp:
            key = (str(row.get("bus_id") or "?"), str(irp))
            if is_setup:
                pending[key].append(make_group(row))
                continue
            if is_control_complete:
                queue = pending.get(key)
                if queue:
                    g = queue.popleft()
                    if not queue:
                        pending.pop(key, None)
                    append_to_group(g, row)
                else:
                    make_group(row)
                continue
            if is_control and pending.get(key):
                append_to_group(pending[key][-1], row)
                continue
            if not is_control:
                if typ == "S":
                    pending[key].append(make_group(row))
                    continue
                if typ in {"C", "E"}:
                    queue = pending.get(key)
                    if queue:
                        g = queue.popleft()
                        if not queue:
                            pending.pop(key, None)
                        append_to_group(g, row)
                    else:
                        make_group(row)
                    continue
                if pending.get(key):
                    append_to_group(pending[key][-1], row)
                    continue
            make_group(row)
            continue

        # TShark/legacy fallback when no IRP identifier is available.
        bus = str(row.get("bus_id") if row.get("bus_id") is not None else "?")
        key = (bus, str(irp)) if irp else None
        if key and typ == "S":
            pending[key].append(make_group(row))
        elif key and typ in {"C", "E"}:
            queue = pending.get(key)
            if queue:
                g = queue.popleft()
                if not queue:
                    pending.pop(key, None)
                append_to_group(g, row)
            else:
                make_group(row)
        else:
            make_group(row)

    for g in groups:
        if g.get("request") is None:
            g["request"] = next((x.get("request") for x in g["rows"] if x.get("request") is not None), None)
        g["time_epoch"] = next((x.get("time_epoch") for x in g["rows"] if x.get("request") is not None and x.get("time_epoch") is not None), g.get("first_time"))
        g["payload"] = choose_payload(g["rows"])
        # USBPcap transfer_type=0xFE is an IRP-info record. In this capture it
        # carries URB_FUNCTION_ABORT_PIPE, not an endpoint payload transfer.
        # Keep it visible as teardown metadata, but never count it as device I/O.
        g["status"] = "TEARDOWN_ABORT_PIPE" if g.get("is_abort_pipe") else transfer_status(g["rows"])
        g["complete_seen"] = bool(g.get("complete_seen")) or any(
            urb_class(x.get("urb_type")) in {"C", "E"} or parse_int(x.get("control_stage")) == 3
            for x in g["rows"])
        g["is_urb_error"] = (not g.get("is_abort_pipe")) and (("E" in g.get("urb_types", [])) or any(
            "ERROR" in str(x.get("urb_function") or "").upper() for x in g["rows"]))
        g["status_details"] = [
            {"frame": x.get("frame_number"), "code": parse_int(x.get("urb_status")),
             "name": usbd_status_name(x.get("urb_status"))}
            for x in g["rows"] if x.get("urb_status") not in (None, "", 0, "0")
        ]
        g["frame_numbers"] = sorted({n for n in g.get("frame_numbers", []) if n is not None})
    groups.sort(key=lambda g: (g.get("frame_numbers", [10**18])[0] if g.get("frame_numbers") else 10**18))
    return groups


def assign_usb_enumeration_sessions(host_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Split sequential USB device enumerations without relying on host/Pi clocks."""
    sessions: list[dict[str, Any]] = []
    active_by_bus: dict[str, dict[str, Any]] = {}
    counters: Counter[str] = Counter()
    ordered = sorted(host_groups, key=lambda g: (g.get("frame_numbers", [10**18])[0] if g.get("frame_numbers") else 10**18))
    for group in ordered:
        bus = str(group.get("bus_id") if group.get("bus_id") is not None else "?")
        req = group.get("request") if isinstance(group.get("request"), dict) else {}
        is_device_descriptor = (int(req.get("bRequest", -1)) == 6 and
                                (int(req.get("bmRequestType", 0)) & 0x80) and
                                ((int(req.get("wValue", 0)) >> 8) & 0xff) == 1)
        current = active_by_bus.get(bus)
        # A new Device Descriptor starts a new physical enumeration after the
        # previous enumeration reached SET_CONFIGURATION (successful OR failed),
        # or after the host began tearing down the previous endpoint. Do not
        # require successful configuration: that would merge later fuzz cases
        # precisely when a mutated descriptor is rejected by Windows.
        previous_attempt_finished = bool(current and (
            current.get("configuration_attempted") or current.get("teardown_seen")))
        if is_device_descriptor and (current is None or previous_attempt_finished):
            counters[bus] += 1
            first_frame = group.get("frame_numbers", [None])[0]
            sid = f"bus{bus}-session{counters[bus]:03d}"
            current = {"session_id": sid, "bus_id": group.get("bus_id"),
                       "first_frame": first_frame, "last_frame": first_frame,
                       "first_time": group.get("time_epoch"), "last_time": group.get("time_epoch"),
                       "configured": False, "configuration_attempted": False,
                       "teardown_seen": False, "group_count": 0,
                       "device_descriptor_frame": first_frame}
            sessions.append(current)
            active_by_bus[bus] = current
        if current is None:
            group["session_id"] = None
            continue
        group["session_id"] = current["session_id"]
        current["group_count"] += 1
        frames = group.get("frame_numbers") or []
        if frames:
            current["last_frame"] = max(current.get("last_frame") or 0, max(frames))
        if group.get("time_epoch") is not None:
            current["last_time"] = group.get("time_epoch")
        if group.get("is_abort_pipe"):
            current["teardown_seen"] = True
        if int(req.get("bRequest", -1)) == 9 and group.get("complete_seen"):
            # Mark the enumeration as attempted even when the host returned an
            # error. This closes it before the next Device Descriptor while
            # configured remains a separate, stricter success state.
            current["configuration_attempted"] = True
            if (int(req.get("wValue", 0)) & 0xff) != 0 and \
                    group.get("status") == "COMPLETED" and not group.get("is_urb_error"):
                current["configured"] = True
                current["set_configuration_value"] = int(req.get("wValue", 0)) & 0xff
    for session in sessions:
        session.pop("configured", None)
    return sessions


def choose_payload(rows: list[dict[str, Any]]) -> bytes | None:
    candidates: list[tuple[int, int, bytes]] = []
    for row in rows:
        for rank, key in enumerate(("get_descriptor_response", "control_response", "data_fragment", "capdata")):
            value = row.get(key)
            parsed = parse_hex_field(value)
            if parsed is not None:
                complete_bonus = 1 if urb_class(row.get("urb_type")) in {"C", "E"} else 0
                candidates.append((rank, -len(parsed), parsed))
    if not candidates:
        return None
    # Prefer parsed descriptor/control-response fields, then the longest capture.
    candidates.sort(key=lambda x: (x[0], x[1]))
    return candidates[0][2]


def transfer_status(rows: list[dict[str, Any]]) -> str:
    """Classify the terminal URB status without treating PENDING as an error."""
    saw_status = False
    saw_cancelled = False
    for row in rows:
        raw = row.get("urb_status")
        if raw is None or raw == "":
            continue
        code = parse_int(raw)
        low = str(raw).lower()
        if code is None:
            if "stall" in low:
                return "STALL"
            if "timeout" in low or "timed out" in low:
                return "TIMEOUT"
            if "cancelled" in low or "canceled" in low:
                saw_cancelled = True
                continue
            if any(x in low for x in ("error", "failed")):
                return "ERROR"
            continue
        # 0x40000000 is an in-flight URB status, not a completed failure.
        if code == 0x40000000:
            continue
        saw_status = True
        if code == 0xC0010000:
            saw_cancelled = True
            continue
        if code != 0:
            return "ERROR"
    if any(urb_class(r.get("urb_type")) == "E" for r in rows):
        return "ERROR"
    has_completion = any(urb_class(r.get("urb_type")) == "C" or
                         parse_int(r.get("control_stage")) == 3 or
                         "CONTROL_TRANSFER" in str(r.get("urb_function") or "").upper()
                         for r in rows)
    if saw_cancelled:
        return "CANCELLED"
    if has_completion:
        return "COMPLETED" if saw_status else "COMPLETION_FRAME_OBSERVED"
    return "NO_COMPLETION"


def descriptor_name(dtype: int, index: int, lang: int = 0, iface: int | None = None) -> str:
    base = DESC_NAMES.get(dtype, f"Unknown type 0x{dtype:02x}")
    suffix = f"index={index}"
    if dtype == 3:
        suffix += f", lang=0x{lang:04x}"
    if dtype == 0x22 and iface is not None:
        suffix += f", interface={iface}"
    return f"{base} ({suffix})"


def case_expected(profile: dict[str, Any], verifier: Any) -> tuple[dict[tuple[int, int, int], bytes], list[dict[str, Any]]]:
    standard = verifier.build_expected_descriptors(profile)
    catalog: list[dict[str, Any]] = []
    seen = set()
    for (dtype, index, lang), data in standard.items():
        key = (dtype, index, lang)
        seen.add(key)
        catalog.append({"type": dtype, "index": index, "language_id": lang, "interface": None,
                        "configuration_value": None, "key": key, "name": descriptor_name(dtype, index, lang),
                        "bytes": data, "expected_hex": data.hex()})
    # Interface-specific HID report descriptors override the generic 34:0 descriptor.
    for key_text, value in (profile.get("interface_descriptors") or {}).items():
        try:
            config_text, interface_text = key_text.split(":", 1)
            config_index, interface = int(config_text, 0), int(interface_text, 0)
            raw = verifier.hexbytes(value)
        except Exception:
            continue
        catalog.append({"type": 0x22, "index": 0, "language_id": 0, "interface": interface,
                        "configuration_value": config_index,
                        "key": (0x22, 0, 0), "name": descriptor_name(0x22, 0, 0, interface),
                        "bytes": raw, "expected_hex": raw.hex()})
    catalog.sort(key=lambda x: (x["type"], x["index"], x.get("language_id") or 0,
                                x.get("configuration_value") if x.get("configuration_value") is not None else -1,
                                x.get("interface") if x.get("interface") is not None else -1))
    return standard, catalog


def resolve_expected(profile: dict[str, Any], standard: dict[tuple[int, int, int], bytes],
                     dtype: int, index: int, windex: int, active_config_value: int) -> tuple[bytes | None, str]:
    if dtype == 0x22:
        override = profile.get("interface_descriptors") or {}
        # The key is configuration-array index : interface number. SET_CONFIGURATION
        # carries bConfigurationValue, which is not necessarily the array index.
        config_index = next((i for i, cfg in enumerate(profile.get("configurations", []) or [])
                             if int(cfg.get("bConfigurationValue", 1)) == int(active_config_value)), None)
        candidate_keys = [f"{config_index}:{windex}"] if config_index is not None else []
        candidate_keys.append(f"{active_config_value}:{windex}")  # legacy profiles may use the value as index
        for key in candidate_keys:
            if key in override:
                try:
                    return bytes.fromhex(re.sub(r"\s+", "", str(override[key]))), f"interface_descriptors[{key}]"
                except ValueError:
                    return None, f"interface_descriptors[{key}] (invalid hex)"
    lang = windex if dtype == 3 else 0
    found = standard.get((dtype, index, lang))
    if found is None and dtype == 3:
        found = standard.get((dtype, index, 0))
    if found is not None:
        return found, f"descriptor type={dtype} index={index}"
    return None, "not defined in profile"


def bytes_diff(expected: bytes, actual: bytes | None) -> dict[str, Any]:
    if actual is None:
        return {"status": "HOST_BYTES_NOT_EXTRACTED", "first_diff_offset": None, "different_offsets": []}
    limit = min(len(expected), len(actual))
    different = [i for i in range(limit) if expected[i] != actual[i]]
    first = different[0] if different else None
    if len(expected) != len(actual):
        first = min(len(expected), len(actual)) if first is None else first
    if not different and len(expected) == len(actual):
        status = "MATCH"
    else:
        status = "MISMATCH"
    return {"status": status, "first_diff_offset": first, "different_offsets": different,
            "expected_length": len(expected), "actual_length": len(actual)}


def describe_descriptor(dtype: int, data: bytes) -> list[str]:
    """Decode common standard descriptor headers, preserving raw bytes elsewhere."""
    lines: list[str] = []
    if len(data) >= 2:
        lines.append(f"bLength={data[0]} (0x{data[0]:02x})")
        lines.append(f"bDescriptorType={data[1]} (0x{data[1]:02x})")
    if dtype == 1 and len(data) >= 18:
        bcdusb = data[2] | data[3] << 8
        bcddev = data[12] | data[13] << 8
        vid = data[8] | data[9] << 8
        pid = data[10] | data[11] << 8
        lines.extend([f"bcdUSB=0x{bcdusb:04x}", f"bDeviceClass=0x{data[4]:02x}",
                      f"bDeviceSubClass=0x{data[5]:02x}", f"bDeviceProtocol=0x{data[6]:02x}",
                      f"bMaxPacketSize0={data[7]} (0x{data[7]:02x})", f"idVendor=0x{vid:04x}",
                      f"idProduct=0x{pid:04x}", f"bcdDevice=0x{bcddev:04x}",
                      f"iManufacturer={data[14]}", f"iProduct={data[15]}", f"iSerialNumber={data[16]}",
                      f"bNumConfigurations={data[17]}"])
        if data[0] != 18:
            lines.append(f"INVALID: Device descriptor bLength={data[0]}, expected 18")
    elif dtype == 2 and len(data) >= 9:
        total = data[2] | data[3] << 8
        lines.extend([f"wTotalLength={total} (0x{total:04x})", f"bNumInterfaces={data[4]}",
                      f"bConfigurationValue={data[5]}", f"iConfiguration={data[6]}",
                      f"bmAttributes=0x{data[7]:02x}", f"bMaxPower={data[8]} (2 mA units for USB 2.0)"])
        if total != len(data):
            relation = "short" if len(data) < total else "long"
            lines.append(f"INVALID/INCOMPLETE: captured Configuration bytes={len(data)}, wTotalLength={total} ({relation} descriptor)")
        off = 9
        while off + 2 <= len(data):
            length = data[off]
            stype = data[off + 1]
            if length < 2:
                lines.append(f"offset {off}: malformed bLength={length}; stop decoding")
                break
            if off + length > len(data):
                lines.append(f"offset {off}: descriptor type=0x{stype:02x}, bLength={length} exceeds captured bytes")
                break
            chunk = data[off:off+length]
            if stype == 4 and length >= 9:
                iface_no = chunk[2]
                lines.append(f"offset {off}: Interface number={iface_no}, alternate={chunk[3]}, endpoints={chunk[4]}, class=0x{chunk[5]:02x}, subclass=0x{chunk[6]:02x}, protocol=0x{chunk[7]:02x}, iInterface={chunk[8]}")
                if iface_no >= data[4]:
                    lines.append(f"INVALID: bInterfaceNumber={iface_no} is outside bNumInterfaces={data[4]} (valid interface numbers normally 0..{max(0, data[4]-1)})")
            elif stype == 4:
                lines.append(f"INVALID: Interface descriptor at offset {off} has bLength={length}; USB Interface descriptor requires 9 bytes")
                if length >= 3:
                    lines.append(f"partial Interface fields: bInterfaceNumber={chunk[2]}")
            elif stype == 5 and length >= 7:
                packet = chunk[4] | chunk[5] << 8
                lines.append(f"offset {off}: Endpoint address=0x{chunk[2]:02x}, attributes=0x{chunk[3]:02x}, max_packet={packet}, interval={chunk[6]}")
            elif stype == 0x21 and length >= 6:
                lines.append(f"offset {off}: HID bcdHID=0x{(chunk[2] | chunk[3]<<8):04x}, country={chunk[4]}, subordinate_count={chunk[5]}")
                expected_hid_len = 6 + 3 * chunk[5]
                if length != expected_hid_len:
                    lines.append(f"INVALID: HID descriptor bLength={length}, expected {expected_hid_len} for bNumDescriptors={chunk[5]}")
            else:
                lines.append(f"offset {off}: subdescriptor type=0x{stype:02x}, len={length}")
            off += length
    elif dtype == 3 and len(data) >= 2:
        try:
            text = data[2:].decode("utf-16le", errors="replace")
            lines.append(f"String={text!r}")
        except Exception:
            pass
    elif dtype == 4 and len(data) >= 9:
        lines.extend([f"bInterfaceNumber={data[2]}", f"bAlternateSetting={data[3]}",
                      f"bNumEndpoints={data[4]}", f"bInterfaceClass=0x{data[5]:02x}",
                      f"bInterfaceSubClass=0x{data[6]:02x}", f"bInterfaceProtocol=0x{data[7]:02x}", f"iInterface={data[8]}"])
    elif dtype == 5 and len(data) >= 7:
        lines.extend([f"bEndpointAddress=0x{data[2]:02x}", f"bmAttributes=0x{data[3]:02x}",
                      f"wMaxPacketSize={data[4] | data[5]<<8}", f"bInterval={data[6]}"])
    elif dtype == 0x22:
        lines.append("HID Report Descriptor: raw report-item bytes (no claim of semantic parsing)")
    return lines


def hex_lines(data: bytes | None, expected: bytes | None = None) -> list[dict[str, Any]]:
    if data is None:
        return []
    out = []
    for base in range(0, len(data), 16):
        row = []
        for offset in range(base, min(base + 16, len(data))):
            value = data[offset]
            exp_value = expected[offset] if expected is not None and offset < len(expected) else None
            row.append({"offset": offset, "hex": f"{value:02X}",
                        "different": exp_value is not None and exp_value != value,
                        "expected_missing": expected is not None and offset >= len(expected)})
        out.append({"offset": base, "bytes": row})
    return out


def byte_diff_text(expected: bytes, actual: bytes | None) -> str:
    if actual is None:
        return "Байты ответа не удалось извлечь из USBPcap."
    lines = ["offset | expected | USBPcap | result", "-------+----------+---------+-------"]
    max_len = max(len(expected), len(actual))
    for off in range(max_len):
        e = f"{expected[off]:02X}" if off < len(expected) else "--"
        a = f"{actual[off]:02X}" if off < len(actual) else "--"
        mark = "==" if off < len(expected) and off < len(actual) and expected[off] == actual[off] else "!!"
        lines.append(f"{off:04X}   | {e:>8} | {a:>7} | {mark}")
    return "\n".join(lines)


def case_profile_path(row: dict[str, Any], campaign_dir: Path) -> Path:
    raw = row.get("profile")
    if raw:
        p = Path(raw)
        if not p.is_absolute():
            p = (ROOT / p).resolve()
        if p.is_file():
            return p
    num = int(row.get("case", 0))
    return campaign_dir / f"case-{num:05d}.json"


def case_trace_path(row: dict[str, Any], campaign_dir: Path) -> Path | None:
    raw = row.get("trace")
    if raw:
        p = Path(raw)
        if not p.is_absolute():
            p = (ROOT / p).resolve()
        return p
    num = int(row.get("case", 0))
    p = campaign_dir / "traces" / f"case-{num:05d}.device.jsonl"
    return p


def event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(str(e.get("event", "UNKNOWN")) for e in events)
    config_values = [int(e.get("configuration_value") or 0) for e in events
                     if e.get("event") == "SET_CONFIGURATION" and e.get("configuration_value") is not None]
    return {
        "event_counts": dict(sorted(counts.items())),
        "get_descriptor_requests": [e.get("request") for e in events
                                     if e.get("event") == "CONTROL_REQUEST" and
                                     isinstance(e.get("request"), dict) and int(e["request"].get("bRequest", -1)) == 6],
        "control_request_count": counts["CONTROL_REQUEST"],
        "control_response_complete_count": counts["CONTROL_RESPONSE_COMPLETE"],
        "configuration_values": config_values,
        "configured_observed": any(v != 0 for v in config_values),
        "stall_count": counts["CONTROL_STALL"],
        "reset_count": counts["USB_RESET"] + counts["USB_RESET_OR_DISCONNECT"],
        "disconnect_count": sum(v for k, v in counts.items() if "DISCONNECT" in k),
        "error_count": sum(v for k, v in counts.items() if "ERROR" in k or "FAILED" in k or "MALFORMED" in k),
    }


def make_expected_display(profile: dict[str, Any], verifier: Any) -> tuple[dict, list[dict]]:
    standard, catalog = case_expected(profile, verifier)
    display = []
    for item in catalog:
        data = item["bytes"]
        display.append({k: v for k, v in item.items() if k != "bytes"} | {
            "expected_hex": data.hex(), "length": len(data),
            "decoded": describe_descriptor(item["type"], data),
            "hex_lines": hex_lines(data),
        })
    return standard, display


def device_trace_descriptor_summary(events: list[dict[str, Any]], profile: dict[str, Any] | None,
                                    standard: dict[tuple[int, int, int], bytes]) -> list[dict[str, Any]]:
    """List GET_DESCRIPTOR exchanges recorded by Raw Gadget; this is not host-PCAP evidence."""
    pending: dict[tuple[int, int, int, int, int], deque[dict[str, Any]]] = defaultdict(deque)
    result = []
    active_config_value = 0
    active_device_address = 0
    def key_of(event: dict[str, Any]) -> tuple[int, int, int, int, int] | None:
        req = event.get("request")
        if not isinstance(req, dict):
            return None
        try:
            return tuple(int(req[k]) for k in ("bmRequestType", "bRequest", "wValue", "wIndex", "wLength"))
        except (ValueError, TypeError, KeyError):
            return None
    for event in events:
        name = event.get("event")
        if name == "SET_ADDRESS_OBSERVED":
            active_device_address = int(event.get("address") or 0)
        elif name == "SET_CONFIGURATION":
            active_config_value = int(event.get("configuration_value") or 0)
        elif name in ("USB_RESET", "USB_RESET_OR_DISCONNECT", "USB_DISCONNECT"):
            active_config_value = 0
            active_device_address = 0
        key = key_of(event)
        if name == "CONTROL_REQUEST" and key and key[1] == 6 and key[0] & 0x80:
            pending[key].append({"sequence": event.get("sequence"), "request": event.get("request"),
                                 "timestamp_wall_ns": event.get("timestamp_wall_ns")})
        elif name == "CONTROL_RESPONSE_COMPLETE" and key and key[1] == 6 and key[0] & 0x80:
            req_item = pending[key].popleft() if pending.get(key) else {"sequence": None, "request": event.get("request"),
                                                                          "timestamp_wall_ns": None}
            req = event.get("request") or {}
            dtype, index = (int(req.get("wValue", 0)) >> 8) & 0xff, int(req.get("wValue", 0)) & 0xff
            windex, wlength = int(req.get("wIndex", 0)), int(req.get("wLength", 0))
            expected, source = resolve_expected(profile or {}, standard, dtype, index, windex, active_config_value)
            actual = parse_hex_field(event.get("payload_hex"))
            exp = expected[:wlength] if expected is not None else None
            diff = bytes_diff(exp, actual) if exp is not None else {"status": "NOT_DEFINED_IN_PROFILE"}
            request_ns = req_item.get("timestamp_wall_ns")
            response_ns = event.get("timestamp_wall_ns")
            result.append({"request_sequence": req_item.get("sequence"), "response_sequence": event.get("sequence"),
                           "request_key": list(key), "device_address": active_device_address,
                           "request_time_epoch": (float(request_ns) / 1e9) if request_ns is not None else None,
                           "response_time_epoch": (float(response_ns) / 1e9) if response_ns is not None else None,
                           "request": req_item.get("request"), "name": descriptor_name(dtype, index, windex if dtype == 3 else 0, windex if dtype == 0x22 else None),
                           "expected_source": source, "expected_length": len(exp) if exp is not None else None,
                           "trace_length": len(actual) if actual is not None else None,
                           "result": diff.get("status"), "expected_hex": exp.hex() if exp is not None else None,
                           "trace_payload_hex": actual.hex() if actual is not None else None,
                           "trace_status": event.get("status"), "trace_actual_length": event.get("actual_length")})
    return result


def request_signature(request: dict[str, Any] | None) -> tuple[int, int, int, int, int] | None:
    if not isinstance(request, dict):
        return None
    try:
        return tuple(int(request[k]) for k in ("bmRequestType", "bRequest", "wValue", "wIndex", "wLength"))
    except (KeyError, TypeError, ValueError):
        return None


def three_way_status(expected_hex: str | None, device_hex: str | None,
                     host_hex: str | None) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    expected = bytes.fromhex(expected_hex) if expected_hex is not None else None
    device = bytes.fromhex(device_hex) if device_hex is not None else None
    host = bytes.fromhex(host_hex) if host_hex is not None else None
    expected_device = bytes_diff(expected, device) if expected is not None else {
        "status": "EXPECTED_BYTES_UNDEFINED", "first_diff_offset": None, "different_offsets": []}
    device_host = bytes_diff(device, host) if device is not None else {
        "status": "DEVICE_TRACE_BYTES_UNAVAILABLE", "first_diff_offset": None, "different_offsets": []}
    expected_host = bytes_diff(expected, host) if expected is not None else {
        "status": "EXPECTED_BYTES_UNDEFINED", "first_diff_offset": None, "different_offsets": []}
    if device is None:
        status = "DEVICE_TRACE_BYTES_NOT_RECORDED"
    elif expected is not None and expected_device["status"] == "MISMATCH":
        status = "DEVICE_TRACE_BYTES_MISMATCH_PROFILE"
    elif host is None:
        status = "HOST_BYTES_NOT_CAPTURED"
    elif device_host["status"] == "MISMATCH":
        status = "HOST_BYTES_MISMATCH_DEVICE_TRACE"
    elif expected is not None and expected_host["status"] == "MISMATCH":
        status = "HOST_BYTES_MISMATCH_PROFILE"
    elif expected is not None:
        status = "ALL_THREE_BYTE_STREAMS_MATCH"
    else:
        status = "DEVICE_TRACE_AND_HOST_BYTES_MATCH"
    return status, expected_device, device_host, expected_host


def make_three_way_byte_table(expected_hex: str | None, device_hex: str | None,
                              host_hex: str | None) -> str:
    expected = bytes.fromhex(expected_hex) if expected_hex is not None else b""
    device = bytes.fromhex(device_hex) if device_hex is not None else b""
    host = bytes.fromhex(host_hex) if host_hex is not None else b""
    max_len = max(len(expected), len(device), len(host))
    if max_len == 0:
        return "Нет доступных байтов для сравнения."
    lines = ["offset | expected | Raw Gadget | USBPcap | verdict",
             "-------+----------+------------+---------+-------"]
    for off in range(max_len):
        e = f"{expected[off]:02X}" if off < len(expected) else "--"
        d = f"{device[off]:02X}" if off < len(device) else "--"
        h = f"{host[off]:02X}" if off < len(host) else "--"
        if off < len(expected) and off < len(device) and e != d:
            verdict = "PROFILE!=DEVICE"
        elif off < len(device) and off < len(host) and d != h:
            verdict = "DEVICE!=HOST"
        elif off >= len(expected) or off >= len(device) or off >= len(host):
            verdict = "LENGTH/NOT_CAPTURED"
        else:
            verdict = "MATCH"
        lines.append(f"{off:04X}   | {e:>8} | {d:>10} | {h:>7} | {verdict}")
    return "\n".join(lines)


def correlate_descriptor_transactions(host_transactions: list[dict[str, Any]],
                                       trace_transactions: list[dict[str, Any]],
                                       clock_offset: float, tolerance: float,
                                       use_timestamps: bool = True) -> None:
    """Pair host GET_DESCRIPTOR responses with Raw Gadget EP0 responses by SETUP tuple and time.

    A single PCAPNG can span the campaign; the case time window is already applied.
    Matching is deliberately conservative: exact SETUP signature is required.
    """
    used: set[int] = set()
    for host in host_transactions:
        sig = request_signature(host.get("request"))
        host_time = host.get("time_epoch")
        aligned_host_time = (float(host_time) - clock_offset) if host_time is not None else None
        candidates = []
        for index, trace in enumerate(trace_transactions):
            if index in used or tuple(trace.get("request_key") or ()) != sig:
                continue
            host_address = host.get("device_address")
            trace_address = trace.get("device_address")
            if use_timestamps and host_address is not None and trace_address is not None and int(host_address) != int(trace_address):
                continue
            trace_time = trace.get("response_time_epoch") or trace.get("request_time_epoch")
            distance = abs(aligned_host_time - float(trace_time)) if use_timestamps and aligned_host_time is not None and trace_time is not None else None
            candidates.append((distance if distance is not None else float("inf"), index, trace))
        if not candidates:
            host["device_trace_match_status"] = "NO_MATCHING_DEVICE_TRACE_RESPONSE"
            host["device_trace_payload_hex"] = None
            host["three_way_status"] = "DEVICE_TRACE_RESPONSE_NOT_CORRELATED"
            host["expected_vs_device"] = {"status": "NO_DEVICE_TRACE_MATCH"}
            host["device_vs_host"] = {"status": "NO_DEVICE_TRACE_MATCH"}
            host["three_way_byte_table"] = make_three_way_byte_table(host.get("expected_hex"), None, host.get("actual_hex"))
            continue
        candidates.sort(key=lambda x: (x[0], x[1]))
        distance, index, trace = candidates[0]
        # When clocks are present, reject a distant same-signature request rather than mis-pair it.
        if distance != float("inf") and distance > max(2.0, tolerance * 4):
            host["device_trace_match_status"] = "TRACE_TIME_OUTSIDE_MATCH_WINDOW"
            host["device_trace_payload_hex"] = None
            host["three_way_status"] = "DEVICE_TRACE_RESPONSE_NOT_CORRELATED"
            host["expected_vs_device"] = {"status": "TRACE_TIME_OUTSIDE_MATCH_WINDOW"}
            host["device_vs_host"] = {"status": "TRACE_TIME_OUTSIDE_MATCH_WINDOW"}
            host["three_way_byte_table"] = make_three_way_byte_table(host.get("expected_hex"), None, host.get("actual_hex"))
            continue
        used.add(index)
        trace_hex = trace.get("trace_payload_hex")
        status, expected_device, device_host, expected_host = three_way_status(
            host.get("expected_hex"), trace_hex, host.get("actual_hex"))
        host["device_trace_match_status"] = "MATCHED_BY_SETUP_AND_TIME" if use_timestamps and distance != float("inf") else "MATCHED_BY_SETUP_ORDER_NO_CLOCK_CORRELATION"
        host["device_trace_request_sequence"] = trace.get("request_sequence")
        host["device_trace_response_sequence"] = trace.get("response_sequence")
        host["device_trace_response_time_epoch"] = trace.get("response_time_epoch")
        host["device_trace_payload_hex"] = trace_hex
        host["device_trace_length"] = trace.get("trace_length")
        host["device_trace_status"] = trace.get("trace_status")
        host["device_trace_result_vs_profile"] = trace.get("result")
        host["three_way_status"] = status
        host["expected_vs_device"] = expected_device
        host["device_vs_host"] = device_host
        host["expected_vs_host"] = expected_host
        host["three_way_byte_table"] = make_three_way_byte_table(
            host.get("expected_hex"), trace_hex, host.get("actual_hex"))
        trace["matched_host_frames"] = host.get("frames", [])
        trace["host_payload_hex"] = host.get("actual_hex")
        trace["three_way_status"] = status
    for index, trace in enumerate(trace_transactions):
        if index not in used:
            trace["host_match_status"] = "NO_MATCHING_HOST_RESPONSE_IN_PCAP"


def expected_profile_control_payload(profile: dict[str, Any] | None, request: dict[str, Any] | None,
                                      active_config_value: int) -> bytes | None:
    """Return statically derivable class/vendor control-IN bytes when profile defines them."""
    if not profile or not isinstance(request, dict):
        return None
    try:
        bm = int(request.get("bmRequestType", 0))
        req = int(request.get("bRequest", -1))
        value = int(request.get("wValue", 0))
        index = int(request.get("wIndex", 0))
        length = int(request.get("wLength", 0))
    except (TypeError, ValueError):
        return None
    # Explicit control_responses take precedence.
    for item in profile.get("control_responses", []) or []:
        try:
            if int(item.get("bmRequestType", -1)) != bm or int(item.get("bRequest", -1)) != req:
                continue
            if "wValue" in item and int(item["wValue"]) != value:
                continue
            if "wIndex" in item and int(item["wIndex"]) != index:
                continue
            data = parse_hex_field(item.get("data_hex"))
            return data[:length] if data is not None else None
        except (TypeError, ValueError):
            continue
    # Standard class-interface IN requests with deterministic profile/runtime defaults.
    if not (bm & 0x80) or (bm & 0x60) != 0x20 or (bm & 0x1f) != 1:
        return None
    runtime_item = None
    for item in (profile.get("runtime", {}).get("interfaces", []) or []):
        try:
            cfg = int(item.get("configuration_value", 1))
            iface = int(item.get("interface_number", 0))
        except (TypeError, ValueError):
            continue
        if cfg == (active_config_value or 1) and iface == index:
            runtime_item = item
            break
    klass = str((runtime_item or {}).get("class", ""))
    data = None
    if klass == "cdc-acm" and req == 0x21:  # GET_LINE_CODING default from backend
        data = bytes.fromhex("00c20100000008")
    elif klass == "hid" and req == 0x01:  # GET_REPORT
        data = parse_hex_field((runtime_item or {}).get("control_report_hex"))
        if data is None and runtime_item and runtime_item.get("interrupt_in_endpoint") is not None:
            address = int(runtime_item["interrupt_in_endpoint"])
            value_hex = (profile.get("endpoint_io", {}).get("in_payloads", {}) or {}).get(str(address))
            if value_hex is None:
                value_hex = (profile.get("endpoint_io", {}).get("in_payloads", {}) or {}).get(str(address & 0xff))
            data = parse_hex_field(value_hex)
    elif klass == "hid" and req == 0x02:  # GET_IDLE defaults to zero before SET_IDLE
        data = b"\x00"
    elif klass == "hid" and req == 0x03:  # GET_PROTOCOL defaults according to boot_protocol
        data = bytes([1 if (runtime_item or {}).get("boot_protocol", False) else 0])
    elif klass == "msc-bot" and req == 0xfe:  # GET_MAX_LUN
        data = b"\x00"
    return data[:length] if data is not None else None


def device_trace_data_transfers(events: list[dict[str, Any]], profile: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Extract non-descriptor payloads recorded at EP0 and endpoints."""
    expected_endpoint_payloads: dict[int, bytes] = {}
    if profile:
        for address, value in (profile.get("endpoint_io", {}).get("in_payloads", {}) or {}).items():
            try:
                expected_endpoint_payloads[int(address, 0) if isinstance(address, str) else int(address)] = parse_hex_field(value) or b""
            except (TypeError, ValueError):
                continue
        for runtime in (profile.get("runtime", {}).get("interfaces", []) or []):
            for endpoint_key in ("interrupt_in_endpoint",):
                if runtime.get(endpoint_key) is not None:
                    address = int(runtime[endpoint_key])
                    payload = parse_hex_field(runtime.get("interrupt_in_payload_hex"))
                    if payload is not None:
                        expected_endpoint_payloads[address] = payload
    out = []
    active_device_address = 0
    active_config_value = 0
    ignored = {"DEVICE_IN_TRANSFER_QUEUED"}
    for event in events:
        name = str(event.get("event", ""))
        if name == "SET_CONFIGURATION":
            active_config_value = int(event.get("configuration_value") or 0)
        elif name in ("USB_RESET", "USB_RESET_OR_DISCONNECT", "USB_DISCONNECT"):
            active_config_value = 0
        if name == "SET_ADDRESS_OBSERVED":
            active_device_address = int(event.get("address") or 0)
            continue
        if name in ("USB_RESET", "USB_RESET_OR_DISCONNECT", "USB_DISCONNECT"):
            active_device_address = 0
        if name in ignored:
            continue
        if name == "CONTROL_RESPONSE_COMPLETE":
            req = event.get("request") or {}
            try:
                is_descriptor_response = int(req.get("bRequest", -1)) == 6 and (int(req.get("bmRequestType", 0)) & 0x80)
            except (TypeError, ValueError):
                is_descriptor_response = False
            if is_descriptor_response:
                continue  # descriptor responses are listed separately
        payload = parse_hex_field(event.get("payload_hex"))
        preview = parse_hex_field(event.get("payload_preview_hex"))
        if payload is None and preview is None:
            continue
        endpoint = event.get("endpoint_address", 0)
        try:
            endpoint = int(endpoint)
        except (TypeError, ValueError):
            continue
        direction = event.get("direction")
        if not direction:
            direction = "device_to_host" if endpoint & 0x80 else "host_to_device"
        req = event.get("request") if isinstance(event.get("request"), dict) else None
        timestamp_ns = event.get("timestamp_wall_ns")
        expected_payload = expected_endpoint_payloads.get(endpoint) if direction == "device_to_host" else None
        if endpoint == 0 and direction == "device_to_host":
            expected_payload = expected_profile_control_payload(profile, req, active_config_value)
        actual_payload_hex = payload.hex() if payload is not None else None
        expected_payload_hex = expected_payload.hex() if expected_payload is not None else None
        expected_result = bytes_diff(expected_payload, payload) if expected_payload is not None and payload is not None else None
        out.append({"event": name, "sequence": event.get("sequence"), "time_epoch": float(timestamp_ns) / 1e9 if timestamp_ns is not None else None,
                    "endpoint_address": endpoint, "direction": direction,
                    "device_address": active_device_address,
                    "expected_payload_hex": expected_payload_hex,
                    "expected_vs_trace_status": expected_result.get("status") if expected_result else "NOT_DEFINED_IN_PROFILE",
                    "payload_hex": actual_payload_hex,
                    "payload_preview_hex": preview.hex() if preview is not None else None,
                    "payload_length": len(payload) if payload is not None else event.get("actual_length"),
                    "payload_complete": payload is not None and not event.get("payload_truncated", False),
                    "request": req, "status": event.get("status")})
    return out


def correlate_data_transfers(trace_transfers: list[dict[str, Any]], host_groups: list[dict[str, Any]],
                             clock_offset: float, tolerance: float,
                             use_timestamps: bool = True) -> list[dict[str, Any]]:
    used: set[int] = set()
    result = []
    for trace in trace_transfers:
        req_sig = request_signature(trace.get("request"))
        candidates = []
        for idx, host in enumerate(host_groups):
            if idx in used or host.get("payload") is None:
                continue
            trace_address = trace.get("device_address")
            host_address = host.get("device_address")
            if use_timestamps and trace_address is not None and host_address is not None and int(trace_address) != int(host_address):
                continue
            if req_sig:
                if request_signature(host.get("request")) != req_sig:
                    continue
            else:
                if host.get("endpoint_address") != trace.get("endpoint_address"):
                    continue
                ep = int(trace.get("endpoint_address", 0))
                host_direction = "device_to_host" if ep & 0x80 else "host_to_device"
                if host_direction != trace.get("direction"):
                    continue
            host_time = host.get("time_epoch")
            trace_time = trace.get("time_epoch")
            distance = abs((float(host_time) - clock_offset) - float(trace_time)) if use_timestamps and host_time is not None and trace_time is not None else float("inf")
            if use_timestamps and distance != float("inf") and distance > max(2.0, tolerance * 4):
                continue
            trace_payload = bytes.fromhex(trace["payload_hex"]) if trace.get("payload_hex") else None
            host_payload = host.get("payload")
            exact_bonus = 0 if trace_payload is not None and host_payload == trace_payload else 1
            candidates.append((distance, exact_bonus, idx, host))
        if not candidates:
            item = dict(trace)
            item["host_match_status"] = "NO_MATCHING_HOST_TRANSFER_IN_PCAP"
            item["host_payload_hex"] = None
            item["comparison_status"] = "HOST_BYTES_NOT_CAPTURED"
            result.append(item)
            continue
        candidates.sort(key=lambda x: (x[0], x[1], x[2]))
        _, _, idx, host = candidates[0]
        used.add(idx)
        sent = bytes.fromhex(trace["payload_hex"]) if trace.get("payload_hex") else None
        received = host.get("payload")
        if sent is None and trace.get("payload_preview_hex"):
            comparison = {"status": "TRACE_PAYLOAD_TRUNCATED", "captured_preview_bytes": len(bytes.fromhex(trace["payload_preview_hex"]))}
        elif sent is None or received is None:
            comparison = {"status": "BYTES_UNAVAILABLE"}
        elif len(sent) != len(received):
            comparison = {"status": "LENGTH_DIFFERENCE_OR_USB_PACKET_FRAGMENTATION", "sent_length": len(sent), "received_length": len(received)}
        else:
            comparison = bytes_diff(sent, received)
        item = dict(trace)
        item.update({"host_match_status": "MATCHED_BY_ENDPOINT_DIRECTION_AND_TIME" if use_timestamps else "MATCHED_BY_ENDPOINT_DIRECTION_AND_SESSION_ORDER",
                     "host_frames": host.get("frame_numbers", []),
                     "host_payload_hex": received.hex() if received is not None else None,
                     "comparison_status": comparison.get("status"), "comparison": comparison})
        result.append(item)
    return result



def descriptor_key_from_transaction(t: dict[str, Any]) -> tuple[int, int, int, int | None]:
    return (int(t.get("descriptor_type", -1)), int(t.get("descriptor_index", 0)),
            int(t.get("language_id", 0)), t.get("interface"))

def decode_device_ids(data: bytes | None) -> dict[str, str | None]:
    if not data or len(data) < 12 or data[1] != 1:
        return {"vid": None, "pid": None}
    return {"vid": f"0x{data[8] | data[9] << 8:04X}",
            "pid": f"0x{data[10] | data[11] << 8:04X}"}

def reconstruct_host_configuration(transactions: list[dict[str, Any]], expected_catalogue: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct the richest descriptor inventory actually observed in USBPcap.

    This is deliberately an observed-data inventory, not an assertion that unrequested
    descriptors do not exist. Repeated short/long reads are retained as observations;
    the longest successful payload is selected as the best available representation.
    """
    observations: dict[tuple[int, int, int, int | None], list[dict[str, Any]]] = defaultdict(list)
    for t in transactions:
        key = descriptor_key_from_transaction(t)
        raw_hex = t.get("actual_hex")
        raw = bytes.fromhex(raw_hex) if raw_hex else None
        observations[key].append({"raw": raw, "frames": t.get("frames", []),
                                  "status": t.get("host_transfer_status"),
                                  "requested_length": (t.get("request") or {}).get("wLength"),
                                  "result": t.get("result")})
    host_map: dict[tuple[int, int, int, int | None], bytes] = {}
    for key, items in observations.items():
        usable = [x for x in items if x["raw"] is not None]
        if usable:
            # Prefer complete/successful reads, then the longest payload, then latest observation.
            usable.sort(key=lambda x: (x["status"] in ("COMPLETED", "COMPLETION_FRAME_OBSERVED", "SUCCESS", "0", None), len(x["raw"]), len(x["frames"])), reverse=True)
            host_map[key] = usable[0]["raw"]
    expected_map: dict[tuple[int, int, int, int | None], bytes] = {}
    for item in expected_catalogue:
        try:
            key = (int(item["type"]), int(item["index"]), int(item.get("language_id") or 0), item.get("interface"))
            expected_map[key] = bytes.fromhex(item["expected_hex"])
        except Exception:
            continue
    all_keys = sorted(set(expected_map) | set(host_map), key=lambda k: (k[0], k[1], k[2], -1 if k[3] is None else k[3]))
    entries = []
    for key in all_keys:
        dtype, index, lang, iface = key
        exp, got = expected_map.get(key), host_map.get(key)
        if exp is None:
            state, result = "HOST_ONLY", "ADDED_ON_HOST"
        elif got is None:
            state, result = ("NOT_REQUESTED", "NOT_OBSERVED") if key not in observations else ("REQUESTED_NO_PAYLOAD", "INCOMPLETE")
        elif len(exp) == len(got) and exp == got:
            state, result = "RECEIVED", "IDENTICAL"
        elif len(got) < len(exp):
            state, result = "PARTIAL_RECEIVED", "DIFFERENT_OR_TRUNCATED"
        else:
            state, result = "RECEIVED", "DIFFERENT"
        entries.append({"key": list(key), "name": descriptor_name(dtype, index, lang, iface),
                        "type": dtype, "index": index, "language_id": lang, "interface": iface,
                        "state": state, "result": result, "expected_hex": exp.hex() if exp is not None else None,
                        "host_hex": got.hex() if got is not None else None,
                        "expected_length": len(exp) if exp is not None else None,
                        "host_length": len(got) if got is not None else None,
                        "expected_decoded": describe_descriptor(dtype, exp) if exp is not None else [],
                        "host_decoded": describe_descriptor(dtype, got) if got is not None else [],
                        "host_observations": [{"frames": x["frames"], "status": x["status"],
                                               "requested_length": x["requested_length"],
                                               "payload_length": len(x["raw"]) if x["raw"] is not None else None}
                                              for x in observations.get(key, [])]})
    expected_device = expected_map.get((1, 0, 0, None))
    host_device = host_map.get((1, 0, 0, None))
    exp_ids, host_ids = decode_device_ids(expected_device), decode_device_ids(host_device)
    host_configurations = []
    for key, raw in host_map.items():
        if key[0] == 2:
            host_configurations.append({"index": key[1], "length": len(raw), "hex": raw.hex(),
                                        "decoded": describe_descriptor(2, raw),
                                        "complete_by_wTotalLength": len(raw) >= (raw[2] | raw[3] << 8) if len(raw) >= 4 else False})
    return {"status": "OBSERVED" if host_map else "NOT_OBSERVED",
            "expected_ids": exp_ids, "host_ids": host_ids, "entries": entries,
            "host_configuration_descriptors": host_configurations,
            "observed_descriptor_count": len(host_map),
            "not_requested_count": sum(x["state"] == "NOT_REQUESTED" for x in entries),
            "partial_count": sum(x["state"] in ("PARTIAL_RECEIVED", "REQUESTED_NO_PAYLOAD") for x in entries),
            "different_count": sum(x["result"] in ("DIFFERENT", "DIFFERENT_OR_TRUNCATED", "ADDED_ON_HOST") for x in entries)}

def configuration_comparison_html(data: dict[str, Any]) -> str:
    entries = data.get("entries", [])
    rows = []
    for item in entries:
        state = item["state"]
        cls = "added" if state == "HOST_ONLY" else ("unobserved" if state == "NOT_REQUESTED" else ("changed" if item["result"] not in ("IDENTICAL", "NOT_OBSERVED") else "same"))
        def pane(label: str, raw_hex: str | None, decoded: list[str]) -> str:
            dump = " ".join(raw_hex[i:i+2].upper() for i in range(0, len(raw_hex), 2)) if raw_hex else "Нет полученных данных"
            return f'<div><b>{label}</b><pre>{html.escape(dump)}</pre><ul>' + ''.join(f'<li>{html.escape(x)}</li>' for x in decoded) + '</ul></div>'
        rows.append(f'<article class="descriptor-row {cls}"><h4>{html.escape(item["name"])} — {html.escape(item["result"])}</h4><div class="descriptor-pair">{pane("EXPECTED / PROFILE", item.get("expected_hex"), item.get("expected_decoded", []))}{pane("HOST RECEIVED / USBPcap", item.get("host_hex"), item.get("host_decoded", []))}</div><p class="muted">Состояние: {html.escape(state)}; длина expected={item.get("expected_length")}; host={item.get("host_length")}; наблюдения={html.escape(json.dumps(item.get("host_observations", []), ensure_ascii=False))}</p></article>')
    ids = data.get("expected_ids", {})
    host_ids = data.get("host_ids", {})
    header = f'<div class="id-grid"><div><b>EXPECTED VID/PID</b><p>VID {html.escape(str(ids.get("vid") or "N/A"))} · PID {html.escape(str(ids.get("pid") or "N/A"))}</p></div><div><b>HOST RECEIVED VID/PID</b><p>VID {html.escape(str(host_ids.get("vid") or "NOT RECEIVED"))} · PID {html.escape(str(host_ids.get("pid") or "NOT RECEIVED"))}</p></div></div>'
    return header + f'<p>USBPcap восстановил {data.get("observed_descriptor_count", 0)} типов/вариантов дескрипторов; не запрошено: {data.get("not_requested_count", 0)}; частично/без payload: {data.get("partial_count", 0)}; отличий: {data.get("different_count", 0)}.</p>' + ''.join(rows)


def setup_packet_hex(request: dict[str, Any] | None) -> str | None:
    """USB SETUP packet as transmitted: bmRequestType, bRequest, then LE words."""
    if not isinstance(request, dict):
        return None
    try:
        values = [int(request[k]) for k in ("bmRequestType", "bRequest", "wValue", "wIndex", "wLength")]
        bm, br, wv, wi, wl = values
        if not (0 <= bm <= 255 and 0 <= br <= 255 and all(0 <= x <= 0xffff for x in (wv, wi, wl))):
            return None
        return bytes((bm, br, wv & 255, wv >> 8, wi & 255, wi >> 8, wl & 255, wl >> 8)).hex()
    except (KeyError, TypeError, ValueError):
        return None


def decode_usb_string_descriptor(raw_hex: str | None) -> str | None:
    if not raw_hex:
        return None
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    if len(data) < 2 or data[1] != 3:
        return None
    declared = data[0]
    if declared < 2 or declared > len(data):
        return None
    try:
        return data[2:declared].decode("utf-16le", errors="strict").rstrip("\x00")
    except UnicodeDecodeError:
        return None


def build_host_capture_inventory(host_groups: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct descriptors and configuration independently for each enumeration session."""
    if any(not g.get("session_id") for g in host_groups):
        assign_usb_enumeration_sessions(host_groups)
    sessions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    control_events = []
    address_changes = []
    descriptor_request_count = 0
    for g in host_groups:
        sid = g.get("session_id")
        if not sid:
            continue
        sessions[str(sid)].append(g)
        req = g.get("request")
        if not isinstance(req, dict):
            continue
        bm = int(req.get("bmRequestType") or 0)
        br = int(req.get("bRequest") if req.get("bRequest") is not None else -1)
        wv = int(req.get("wValue") or 0)
        wi = int(req.get("wIndex") or 0)
        wl = int(req.get("wLength") or 0)
        payload = g.get("payload")
        event = {"session_id": str(sid), "frames": g.get("frame_numbers", []), "time_epoch": g.get("time_epoch"),
                 "bus_id": g.get("bus_id"), "device_address": g.get("device_address"),
                 "urb_id": g.get("urb_id"), "irp_id": g.get("irp_id"), "urb_status": g.get("status"),
                 "complete_seen": g.get("complete_seen", False),
                 "setup": {"bmRequestType": bm, "bRequest": br, "wValue": wv, "wIndex": wi, "wLength": wl},
                 "setup_hex": setup_packet_hex(req), "payload_hex": payload.hex() if payload is not None else None}
        control_events.append(event)
        if br == 5 and not (bm & 0x80):
            address_changes.append({**event, "new_address": wv & 0x7f})
        if br == 6 and (bm & 0x80):
            descriptor_request_count += 1

    output_devices = []
    for sid, groups in sorted(sessions.items(), key=lambda kv: min((g.get("frame_numbers") or [10**18])[0] for g in kv[1])):
        transactions = []
        set_configs = []
        addresses = set()
        for g in groups:
            if g.get("device_address") is not None:
                addresses.add(int(g["device_address"]))
            req = g.get("request")
            if not isinstance(req, dict):
                continue
            bm = int(req.get("bmRequestType") or 0)
            br = int(req.get("bRequest") if req.get("bRequest") is not None else -1)
            wv = int(req.get("wValue") or 0)
            wi = int(req.get("wIndex") or 0)
            wl = int(req.get("wLength") or 0)
            if br == 5 and not (bm & 0x80):
                addresses.add(wv & 0x7f)
            if br == 9:
                set_configs.append({"value": wv & 0xff, "frames": g.get("frame_numbers", []),
                                    "status": g.get("status"), "complete_seen": g.get("complete_seen", False),
                                    "error": g.get("is_urb_error", False) or g.get("status") == "ERROR"})
            if br != 6 or not (bm & 0x80):
                continue
            dtype, index = (wv >> 8) & 0xff, wv & 0xff
            lang = wi if dtype == 3 and index else 0
            iface = wi if dtype == 0x22 else None
            key = (dtype, index, lang, iface)
            payload = g.get("payload")
            transactions.append({"session_id": sid, "frames": g.get("frame_numbers", []),
                "time_epoch": g.get("time_epoch"), "bus_id": g.get("bus_id"),
                "device_address": g.get("device_address"), "urb_id": g.get("urb_id"),
                "irp_id": g.get("irp_id"), "urb_status": g.get("status"),
                "complete_seen": g.get("complete_seen", False),
                "setup": {"bmRequestType": bm, "bRequest": br, "wValue": wv, "wIndex": wi, "wLength": wl},
                "setup_hex": setup_packet_hex(req), "payload_hex": payload.hex() if payload is not None else None,
                "key": list(key), "descriptor_type": dtype, "descriptor_index": index,
                "descriptor_name": descriptor_name(dtype, index, lang, iface),
                "requested_length": wl, "actual_length": len(payload) if payload is not None else None,
                "actual_hex": payload.hex() if payload is not None else None,
                "decoded": describe_descriptor(dtype, payload) if payload is not None else []})

        # Prefer completed, non-truncated, longest response for each descriptor key.
        best: dict[tuple[Any, ...], dict[str, Any]] = {}
        for tx in transactions:
            key = tuple(tx["key"])
            old = best.get(key)
            score = (tx.get("complete_seen", False) and tx.get("urb_status") == "COMPLETED",
                     tx.get("actual_length") or 0)
            old_score = ((old.get("complete_seen", False) and old.get("urb_status") == "COMPLETED"),
                         old.get("actual_length") or 0) if old else None
            if old is None or score > old_score:
                best[key] = tx
        dev = best.get((1, 0, 0, None))
        serial_index = None
        if dev and dev.get("actual_hex"):
            try:
                raw_device = bytes.fromhex(dev["actual_hex"])
                if len(raw_device) >= 17 and raw_device[1] == 1:
                    serial_index = raw_device[16]
            except ValueError:
                pass
        serial_tx = best.get((3, serial_index, 0, None)) if serial_index else None
        if serial_tx is None and serial_index:
            serial_tx = next((x for k, x in best.items() if k[0] == 3 and k[1] == serial_index), None)
        serial = decode_usb_string_descriptor(serial_tx.get("actual_hex")) if serial_tx else None
        configured_set = [x for x in set_configs if x["value"] != 0]
        configured = any(x.get("complete_seen") and x.get("status") == "COMPLETED" and not x.get("error")
                         for x in configured_set)
        configurations = []
        for key, x in sorted(best.items(), key=lambda item: item[0]):
            if key[0] != 2:
                continue
            raw = bytes.fromhex(x["actual_hex"]) if x.get("actual_hex") else b""
            configurations.append({"name": x["descriptor_name"], "hex": x.get("actual_hex"),
                "decoded": x.get("decoded", []), "length": x.get("actual_length"),
                "bConfigurationValue": raw[5] if len(raw) >= 6 else None,
                "declared_total_length": (raw[2] | raw[3] << 8) if len(raw) >= 4 else None})
        frames = [f for g in groups for f in (g.get("frame_numbers") or [])]
        times = [float(g["time_epoch"]) for g in groups if g.get("time_epoch") is not None]
        first_frame, last_frame = (min(frames), max(frames)) if frames else (None, None)
        bus = next((g.get("bus_id") for g in groups if g.get("bus_id") is not None), None)
        address = next((x for x in sorted(addresses) if x != 0), None)
        if address is None:
            address = next((g.get("device_address") for g in groups if g.get("device_address") is not None), None)
        cancelled_events = [{"frames": g.get("frame_numbers", []), "endpoint": g.get("endpoint_address"),
                             "status_details": g.get("status_details", [])}
                            for g in groups if g.get("status") == "CANCELLED"]
        teardown_events = [{"frames": g.get("frame_numbers", []), "endpoint": g.get("endpoint_address"),
                            "urb_functions": g.get("urb_functions", []),
                            "status_details": g.get("status_details", [])}
                           for g in groups if g.get("status") == "TEARDOWN_ABORT_PIPE"]
        output_devices.append({"session_id": sid, "bus_id": bus, "device_address": address,
            "device_addresses": sorted(addresses), "first_frame": first_frame, "last_frame": last_frame,
            "session_first_epoch": min(times) if times else None, "session_last_epoch": max(times) if times else None,
            "vid_pid": decode_device_ids(bytes.fromhex(dev["actual_hex"]) if dev and dev.get("actual_hex") else None),
            "serial_index": serial_index, "serial_number": serial,
            "serial_status": "SERIAL_READ" if serial is not None else ("SERIAL_REQUEST_NOT_OBSERVED" if serial_index else "NO_SERIAL_INDEX_IN_DEVICE_DESCRIPTOR"),
            "device_descriptor_seen": bool(dev), "set_configuration_observed": bool(set_configs),
            "set_configuration": set_configs, "configured_observed": configured,
            "enumeration_status": "CONFIGURED_OBSERVED" if configured else ("ENUMERATION_INCOMPLETE" if dev else "DEVICE_DESCRIPTOR_NOT_OBSERVED"),
            "descriptor_count": len(best), "transactions": transactions,
            "descriptors": [best[k] for k in sorted(best)], "configurations": configurations,
            "cancelled_transfer_count": len(cancelled_events), "cancelled_transfers": cancelled_events,
            "abort_pipe_count": len(teardown_events), "teardown_events": teardown_events,
            "endpoint_transfer_count": sum(1 for g in groups if g.get("transfer_type") in (0, 1, 3)
                                            and g.get("endpoint_address") is not None)})
    return {"source": "USBPcap native sessions split by Device Descriptor and SET_CONFIGURATION; first skipped packets excluded",
            "control_transfer_count": len(control_events), "get_descriptor_count": descriptor_request_count,
            "devices": output_devices, "control_events": control_events,
            "address_changes": address_changes}


def _profile_expected_fingerprints(profile: dict[str, Any], verifier: Any) -> dict[str, Any]:
    standard, catalog = case_expected(profile, verifier)
    device = standard.get((1, 0, 0))
    config = standard.get((2, 0, 0))
    report_items = [x["bytes"] for x in catalog if x.get("type") == 0x22 and x.get("bytes")]
    report = report_items[0] if report_items else standard.get((0x22, 0, 0))
    runtime_endpoints = []
    for runtime in (profile.get("runtime", {}).get("interfaces", []) or []):
        try:
            endpoint = int(runtime.get("interrupt_in_endpoint"))
            payload = parse_hex_field(runtime.get("interrupt_in_payload_hex"))
            if payload is not None:
                runtime_endpoints.append((endpoint, payload))
        except (TypeError, ValueError):
            continue
    if not runtime_endpoints:
        for endpoint_text, payload_text in (profile.get("endpoint_io", {}).get("in_payloads", {}) or {}).items():
            try:
                endpoint = int(endpoint_text, 0) if isinstance(endpoint_text, str) else int(endpoint_text)
                payload = parse_hex_field(payload_text)
                if payload is not None:
                    runtime_endpoints.append((endpoint, payload))
            except (TypeError, ValueError):
                continue
    return {"device": device, "config": config, "report": report,
            "vid": device[8] | device[9] << 8 if device and len(device) >= 12 else None,
            "pid": device[10] | device[11] << 8 if device and len(device) >= 12 else None,
            "runtime_endpoints": runtime_endpoints}


def score_host_session_against_profile(device: dict[str, Any], profile: dict[str, Any], verifier: Any) -> dict[str, Any]:
    """Compare bytes captured in one host session with one exact case profile."""
    expected = _profile_expected_fingerprints(profile, verifier)
    actual_descriptors = {tuple(x.get("key", [])): parse_hex_field(x.get("actual_hex"))
                          for x in device.get("descriptors", [])}
    actual_device = actual_descriptors.get((1, 0, 0, None))
    actual_config = actual_descriptors.get((2, 0, 0, None))
    actual_report = next((v for k, v in actual_descriptors.items() if k and k[0] == 0x22), None)
    evidence: dict[str, Any] = {}
    score = 0
    expected_device = expected["device"]
    if expected["vid"] is not None:
        ids = device.get("vid_pid") or {}
        actual_vid = parse_int(ids.get("vid"))
        actual_pid = parse_int(ids.get("pid"))
        if (actual_vid, actual_pid) != (expected["vid"], expected["pid"]):
            return {"score": -10000, "eligible": False, "reason": "VID_PID_MISMATCH",
                    "evidence": {"expected_vid": expected["vid"], "expected_pid": expected["pid"],
                                 "actual_vid": actual_vid, "actual_pid": actual_pid}}
        score += 25
        evidence["vid_pid"] = "MATCH"
    if expected_device is not None and actual_device is not None:
        if actual_device == expected_device:
            score += 30
            evidence["device_descriptor"] = "EXACT"
        else:
            score -= 15
            evidence["device_descriptor"] = "MISMATCH"
    elif expected_device is not None:
        evidence["device_descriptor"] = "NOT_CAPTURED"

    expected_config = expected["config"]
    if expected_config is not None and actual_config is not None:
        if actual_config == expected_config:
            score += 50
            evidence["configuration_descriptor"] = "EXACT"
        elif len(actual_config) >= 9 and len(expected_config) >= 9 and actual_config[:9] == expected_config[:9]:
            score += 18
            evidence["configuration_descriptor"] = "HEADER_EXACT_FULL_NOT_EXACT"
        else:
            score -= 25
            evidence["configuration_descriptor"] = "MISMATCH"
    elif expected_config is not None:
        evidence["configuration_descriptor"] = "NOT_CAPTURED"

    expected_report = expected["report"]
    if expected_report is not None and actual_report is not None:
        if actual_report == expected_report:
            score += 25
            evidence["hid_report_descriptor"] = "EXACT"
        else:
            score -= 15
            evidence["hid_report_descriptor"] = "MISMATCH"

    endpoint_evidence = []
    for endpoint, expected_payload in expected["runtime_endpoints"]:
        # Endpoint payloads are attached to the device by the caller, via an exact session-group scan.
        endpoint_map = device.get("endpoint_payloads", {})
        actual_payloads = endpoint_map.get(str(endpoint), [])
        if any(x == expected_payload.hex() for x in actual_payloads):
            score += 30
            endpoint_evidence.append({"endpoint": endpoint, "status": "EXACT_PAYLOAD_OBSERVED"})
        elif actual_payloads:
            score -= 25
            endpoint_evidence.append({"endpoint": endpoint, "status": "PAYLOAD_MISMATCH"})
        else:
            endpoint_evidence.append({"endpoint": endpoint, "status": "NO_PAYLOAD_OBSERVED"})
    if endpoint_evidence:
        evidence["interrupt_in"] = endpoint_evidence

    # VID/PID alone is not identity. Permit a match when at least one
    # descriptor fingerprint is exact and the combined evidence is strong;
    # sequence alignment will preserve ambiguity when multiple cases share it.
    robust_fingerprint = any(evidence.get(key) == "EXACT" for key in (
        "device_descriptor", "configuration_descriptor", "hid_report_descriptor")) or any(
        item.get("status") == "EXACT_PAYLOAD_OBSERVED" for item in evidence.get("interrupt_in", []))
    eligible = score >= 50 and evidence.get("vid_pid") == "MATCH" and robust_fingerprint
    return {"score": score, "eligible": eligible,
            "reason": "FINGERPRINT_SCORE" if eligible else "INSUFFICIENT_FINGERPRINT_EVIDENCE",
            "evidence": evidence}


def match_usb_sessions_to_cases(campaign_rows: list[dict[str, Any]], inventory: dict[str, Any],
                                host_groups: list[dict[str, Any]], profiles: dict[int, dict[str, Any] | None],
                                verifier: Any) -> dict[str, Any]:
    """Monotonic sequence alignment: cases and host sessions are ordered, clocks are not used."""
    devices = sorted(inventory.get("devices", []), key=lambda d: (d.get("first_frame") or 10**18, d.get("session_id") or ""))
    cases = sorted(campaign_rows, key=lambda r: int(r.get("case", 0)))
    groups_by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group in host_groups:
        if group.get("session_id"):
            groups_by_session[str(group["session_id"])].append(group)
    for dev in devices:
        ep: dict[str, list[str]] = defaultdict(list)
        for group in groups_by_session.get(str(dev.get("session_id")), []):
            endpoint = group.get("endpoint_address")
            payload = group.get("payload")
            if endpoint is not None and int(group.get("transfer_type") or -1) != 2 and isinstance(payload, bytes):
                ep[str(int(endpoint))].append(payload.hex())
        dev["endpoint_payloads"] = dict(ep)

    n, m = len(cases), len(devices)
    scores: list[list[int | None]] = [[None] * m for _ in range(n)]
    details: list[list[dict[str, Any] | None]] = [[None] * m for _ in range(n)]
    skipped_case_statuses = {"NOT_RUN", "DRY_RUN_ONLY", "GENERATED", "NO_CHANGE", "START_FAILED", "LAUNCH_ERROR"}
    for i, row in enumerate(cases):
        profile = profiles.get(int(row.get("case", 0)))
        if str(row.get("status", "")).upper() in skipped_case_statuses:
            continue

        # The campaign generator assigns a per-case USB serial. If Windows
        # actually requested and returned that String Descriptor, it is the
        # strongest identity key and takes precedence over descriptor scoring.
        # When it was not requested, use the byte fingerprints below.
        case_serial = str(row.get("serial_number") or "").strip()
        serial_hits = [j for j, dev in enumerate(devices)
                       if case_serial and str(dev.get("serial_number") or "").strip() == case_serial]
        if serial_hits:
            for j in serial_hits:
                dev = devices[j]
                try:
                    fingerprint = score_host_session_against_profile(dev, profile, verifier) if profile else None
                except Exception as exc:
                    fingerprint = {"score": 0, "eligible": False,
                                   "reason": f"PROFILE_ERROR: {exc}", "evidence": {}}
                if fingerprint and fingerprint.get("reason") == "VID_PID_MISMATCH":
                    details[i][j] = fingerprint
                    continue
                base_evidence = dict((fingerprint or {}).get("evidence", {}))
                base_evidence["serial_number"] = "EXACT"
                result = {"score": 100000 + int((fingerprint or {}).get("score", 0)),
                          "eligible": True, "reason": "EXACT_SERIAL_NUMBER",
                          "evidence": base_evidence}
                details[i][j] = result
                scores[i][j] = result["score"]
            continue

        if not profile:
            continue
        for j, dev in enumerate(devices):
            try:
                result = score_host_session_against_profile(dev, profile, verifier)
            except Exception as exc:
                result = {"score": -10000, "eligible": False, "reason": f"PROFILE_ERROR: {exc}", "evidence": {}}
            details[i][j] = result
            if result.get("eligible"):
                scores[i][j] = int(result["score"])

    # Forward/backward maximum-score dynamic programming. This also detects ties
    # rather than silently choosing an arbitrary case when profiles are identical.
    neg = -10**12
    forward = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            best = max(forward[i - 1][j], forward[i][j - 1])
            value = scores[i - 1][j - 1]
            if value is not None:
                best = max(best, forward[i - 1][j - 1] + value)
            forward[i][j] = best
    backward = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            best = max(backward[i + 1][j], backward[i][j + 1])
            value = scores[i][j]
            if value is not None:
                best = max(best, value + backward[i + 1][j + 1])
            backward[i][j] = best
    optimum = forward[n][m]
    by_case: dict[str, dict[str, Any]] = {}
    by_session: dict[str, dict[str, Any]] = {}
    for j, dev in enumerate(devices):
        possible_cases = [i for i in range(n) if scores[i][j] is not None and
                          forward[i][j] + scores[i][j] + backward[i + 1][j + 1] == optimum]
        can_be_skipped = any(forward[i][j] + backward[i][j + 1] == optimum for i in range(n + 1))
        sid = str(dev.get("session_id"))
        if len(possible_cases) == 1 and not can_be_skipped:
            i = possible_cases[0]
            case_no = int(cases[i].get("case", 0))
            record = {"status": "MATCHED", "case": case_no, "session_id": sid,
                      "score": scores[i][j], "evidence": (details[i][j] or {}).get("evidence", {})}
            by_case[str(case_no)] = record
            by_session[sid] = record
        elif possible_cases:
            record = {"status": "AMBIGUOUS", "session_id": sid,
                      "candidate_cases": [int(cases[i].get("case", 0)) for i in possible_cases],
                      "scores": {str(int(cases[i].get("case", 0))): scores[i][j] for i in possible_cases},
                      "can_be_unmatched_in_optimal_alignment": can_be_skipped}
            by_session[sid] = record
            for i in possible_cases:
                by_case.setdefault(str(int(cases[i].get("case", 0))), record)
        else:
            by_session[sid] = {"status": "UNMATCHED", "session_id": sid}
    return {"mode": "SEQUENTIAL_PROFILE_FINGERPRINT", "clock_correlation_used": False,
            "case_count": n, "host_session_count": m, "optimal_alignment_score": optimum,
            "by_case": by_case, "by_session": by_session,
            "score_matrix": [{"case": int(cases[i].get("case", 0)),
                              "scores": {str(devices[j].get("session_id")): scores[i][j]
                                         for j in range(m) if scores[i][j] is not None}}
                             for i in range(n)]}


def reconcile_campaign_devices(campaign_rows: list[dict[str, Any]], inventory: dict[str, Any],
                               session_matches: dict[str, Any] | None = None,
                               clock_offset: float = 0.0, tolerance: float = 0.75) -> dict[str, Any]:
    """Reconcile sent cases with host sessions; sequence/fingerprint matching does not use clocks."""
    session_matches = session_matches or {}
    observed_by_serial: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_sid = {str(d.get("session_id")): d for d in inventory.get("devices", [])}
    for dev in inventory.get("devices", []):
        if dev.get("serial_number"):
            observed_by_serial[str(dev["serial_number"])].append(dev)
    sent = []
    for row in sorted(campaign_rows, key=lambda x: int(x.get("case", 0))):
        case_no = int(row.get("case", 0))
        serial = row.get("serial_number")
        hits = observed_by_serial.get(str(serial), []) if serial else []
        match_method = "SERIAL_NUMBER" if len(hits) == 1 else None
        mapping = session_matches.get("by_case", {}).get(str(case_no), {})
        if not hits and mapping.get("status") == "MATCHED":
            dev = by_sid.get(str(mapping.get("session_id")))
            hits = [dev] if dev else []
            match_method = "SEQUENTIAL_PROFILE_FINGERPRINT"
        if len(hits) > 1:
            status = "AMBIGUOUS_MULTIPLE_HOST_SESSIONS"
        elif mapping.get("status") == "AMBIGUOUS":
            status = "AMBIGUOUS_SEQUENCE_MATCH"
        elif hits and hits[0].get("configured_observed"):
            status = "RECEIVED_AND_CONFIGURED"
        elif hits:
            status = "RECEIVED_ENUMERATION_INCOMPLETE"
        elif inventory.get("devices"):
            # USB devices were reconstructed, but this campaign case could not
            # be bound to one of them. Do not mislabel this as absent/blocked.
            status = "HOST_SESSION_FOUND_CASE_IDENTITY_UNRESOLVED"
        else:
            status = "NOT_OBSERVED_IN_PCAP"
        sent.append({"case": case_no, "device_id": row.get("device_id"),
                     "campaign_id": row.get("campaign_id"), "serial_number": serial,
                     "run_status": row.get("status"), "host_status": status,
                     "match_method": match_method,
                     "match_evidence": mapping.get("evidence", {}),
                     "host_sessions": [{"session_id": d.get("session_id"), "first_frame": d.get("first_frame"),
                                        "last_frame": d.get("last_frame"), "bus_id": d.get("bus_id"),
                                        "device_address": d.get("device_address"), "vid_pid": d.get("vid_pid"),
                                        "serial_number": d.get("serial_number"),
                                        "enumeration_status": d.get("enumeration_status")} for d in hits]})
    known = {str(x.get("serial_number")) for x in sent if x.get("serial_number")}
    foreign = [{"serial_number": k, "sessions": len(v)} for k, v in observed_by_serial.items() if k not in known]
    counts = dict(Counter(x["host_status"] for x in sent))
    return {"sent_count": len(sent), "observed_serial_count": len(observed_by_serial),
            "status_counts": counts, "sent_devices": sent, "unmatched_host_serials": foreign,
            "matching_mode": session_matches.get("mode", "SERIAL_OR_UNMATCHED"),
            "clock_correlation_used": False,
            "note": "Сопоставление выполняется по порядку запусков и USB-сессий, а затем по отпечатку фактически захваченных дескрипторов и endpoint payload. Часы Raspberry Pi и Windows не используются. HOST_SESSION_FOUND_CASE_IDENTITY_UNRESOLVED означает, что устройства в USBPcap есть, но связь с Case не доказана. NOT_OBSERVED_IN_PCAP не доказывает блокировку фильтром: нужен журнал ALLOW/BLOCK."}


def host_inventory_html(inventory: dict[str, Any]) -> str:
    out=[f'<p><b>Захват после отсечения первых пакетов:</b> control transfers={inventory["control_transfer_count"]}; GET_DESCRIPTOR={inventory["get_descriptor_count"]}. Первые шесть packet records исключены до декодирования.</p>']
    for dev in inventory.get("devices",[]):
        ids=dev.get("vid_pid",{})
        out.append(f'<h3>{html.escape(str(dev.get("session_id")))} — frames {html.escape(str(dev.get("first_frame")))}–{html.escape(str(dev.get("last_frame")))} — USB bus {html.escape(str(dev.get("bus_id")))} / address {html.escape(str(dev.get("device_address")))} — VID {html.escape(str(ids.get("vid") or "unknown"))} PID {html.escape(str(ids.get("pid") or "unknown"))} — serial {html.escape(str(dev.get("serial_number") or dev.get("serial_status")))} — {html.escape(str(dev.get("enumeration_status")))}</h3>')
        out.append(f'<p>Endpoint transfers: {dev.get("endpoint_transfer_count", 0)}; отменённые при остановке: {dev.get("cancelled_transfer_count", 0)}; URB_FUNCTION_ABORT_PIPE: {dev.get("abort_pipe_count", 0)}. Отмена/AbortPipe показаны отдельно и не считаются ошибкой GET_DESCRIPTOR или SET_CONFIGURATION.</p>')
        out.append('<table><thead><tr><th>Frame</th><th>Descriptor</th><th>Setup parameters</th><th>Request HEX</th><th>Status</th><th>Requested / received</th><th>Response HEX</th></tr></thead><tbody>')
        for tx in dev.get("transactions",[]):
            q=tx["setup"]; setup=' '.join(f'{q[k]:04X}' for k in ("bmRequestType","bRequest","wValue","wIndex","wLength"))
            hx=tx.get("actual_hex") or "NO RESPONSE DATA"
            reqhex=tx.get("setup_hex") or "N/A"
            requested=tx.get("requested_length")
            actual=tx.get("actual_length")
            out.append(f'<tr><td>{html.escape(str(tx.get("frames")))}</td><td>{html.escape(tx["descriptor_name"])}</td><td><code>{setup}</code></td><td><code>{html.escape(reqhex.upper())}</code></td><td>{html.escape(str(tx.get("urb_status")))}</td><td>{requested} / {actual if actual is not None else "—"}</td><td><code>{html.escape(hx.upper())}</code></td></tr>')
        out.append('</tbody></table>')
        for d in dev.get("descriptors",[]):
            out.append(f'<details><summary>{html.escape(d["descriptor_name"])} — {d.get("actual_length")} bytes</summary><pre>{html.escape((d.get("actual_hex") or "NO DATA").upper())}</pre><ul>'+''.join(f'<li>{html.escape(x)}</li>' for x in d.get("decoded",[]))+'</ul></details>')
    if not inventory.get("devices"):
        out.append('<p class="missing">В захвате не восстановлено ни одного GET_DESCRIPTOR. Проверь USBPcap Root Hub и наличие completion/data stage.</p>')
    return ''.join(out)

def render_case(row: dict[str, Any], profile_path: Path, trace_path: Path | None,
                profile: dict[str, Any] | None, device_events: list[dict[str, Any]],
                host_groups: list[dict[str, Any]], verifier: Any,
                time_tolerance: float, clock_offset: float,
                assigned_host_groups: list[dict[str, Any]] | None = None,
                correlation_mode: str = "time",
                session_match: dict[str, Any] | None = None) -> dict[str, Any]:
    case_no = int(row.get("case", 0))
    run_status = str(row.get("status", "NOT_RUN"))
    started = row.get("started_epoch")
    ended = row.get("ended_epoch")
    if started is not None:
        try: started = float(started)
        except (TypeError, ValueError): started = None
    if ended is not None:
        try: ended = float(ended)
        except (TypeError, ValueError): ended = None
    per_case_groups: list[dict[str, Any]] = []
    if assigned_host_groups is not None:
        per_case_groups = list(assigned_host_groups)
    elif started is not None:
        end = ended if ended is not None else started + float(row.get("dwell_seconds_requested", 10) or 10)
        # Legacy mode only: host and Pi clocks must be synchronized or calibrated.
        for g in host_groups:
            t = g.get("time_epoch")
            if t is not None and started - time_tolerance <= (t - clock_offset) <= end + time_tolerance:
                per_case_groups.append(g)
    if run_status in ("NOT_RUN", "DRY_RUN_ONLY", "GENERATED", "NO_CHANGE", "START_FAILED", "LAUNCH_ERROR"):
        per_case_groups = []
    if profile is None:
        standard, catalog = {}, []
        profile_error = f"не удалось прочитать профиль: {profile_path}"
    else:
        try:
            standard, catalog = case_expected(profile, verifier)
            profile_error = None
        except Exception as exc:
            standard, catalog = {}, []
            profile_error = str(exc)

    config_values_expected = []
    if profile:
        for cfg in profile.get("configurations", []):
            try: config_values_expected.append(int(cfg.get("bConfigurationValue", 1)))
            except (ValueError, TypeError): pass

    descriptor_transactions = []
    active_config_value = 0
    host_set_configs = []
    host_errors = []
    host_cancellations = []
    host_teardown_events = []
    host_control_requests = 0
    data_transfers = []
    # PCAP frame order is the only ordering source used in sequential mode.
    group_sort_key = (lambda x: (x.get("frame_numbers", [10**18])[0] if x.get("frame_numbers") else 10**18)) if correlation_mode == "sequential" else (lambda x: (x.get("time_epoch") or 0, x.get("frame_numbers", [0])[0] if x.get("frame_numbers") else 0))
    for g in sorted(per_case_groups, key=group_sort_key):
        if g.get("status") == "CANCELLED":
            host_cancellations.append({"frames": g.get("frame_numbers", []), "status": g.get("status"),
                                       "status_details": g.get("status_details", []),
                                       "endpoint": g.get("endpoint_address")})
            continue
        if g.get("status") == "TEARDOWN_ABORT_PIPE":
            host_teardown_events.append({"frames": g.get("frame_numbers", []), "status": g.get("status"),
                                         "status_details": g.get("status_details", []),
                                         "endpoint": g.get("endpoint_address"),
                                         "urb_functions": g.get("urb_functions", [])})
            continue
        req = g.get("request")
        if not isinstance(req, dict):
            if g.get("status") == "ERROR" and not g.get("is_irp_info"):
                host_errors.append({"frames": g.get("frame_numbers", []), "status": g.get("status"),
                                    "status_details": g.get("status_details", []), "endpoint": g.get("endpoint_address")})
            continue
        brequest = req.get("bRequest")
        bm = req.get("bmRequestType", 0) or 0
        wvalue = req.get("wValue", 0) or 0
        windex = req.get("wIndex", 0) or 0
        wlength = req.get("wLength", 0) or 0
        host_control_requests += 1
        if g.get("status") == "ERROR":
            host_errors.append({"frames": g.get("frame_numbers", []), "status": g.get("status"),
                                "status_details": g.get("status_details", []), "request": req})
        if brequest == 9:
            value = wvalue & 0xff
            host_set_configs.append({"value": value, "frames": g.get("frame_numbers", []),
                                     "status": g.get("status"), "complete_seen": g.get("complete_seen", False),
                                     "error": g.get("is_urb_error", False) or g.get("status") == "ERROR"})
            active_config_value = value
            continue
        if brequest == 6 and (bm & 0x80):
            dtype, dindex = (wvalue >> 8) & 0xff, wvalue & 0xff
            expected, source = resolve_expected(profile or {}, standard, dtype, dindex, windex, active_config_value)
            actual = g.get("payload")
            expected_truncated = expected[:wlength] if expected is not None else None
            diff = bytes_diff(expected_truncated, actual) if expected_truncated is not None else {
                "status": "NOT_DEFINED_IN_PROFILE", "first_diff_offset": None, "different_offsets": []}
            status = diff["status"]
            if expected is None:
                status = "UNEXPECTED_OR_UNDEFINED_DESCRIPTOR"
            descriptor_transactions.append({
                "time_epoch": g.get("time_epoch"), "frames": g.get("frame_numbers", []),
                "bus_id": g.get("bus_id"), "device_address": g.get("device_address"),
                "urb_id": g.get("urb_id"), "urb_types": g.get("urb_types"),
                "request": req, "descriptor_type": dtype, "descriptor_index": dindex,
                "language_id": windex if dtype == 3 else 0,
                "interface": windex if dtype == 0x22 else None,
                "descriptor_name": descriptor_name(dtype, dindex, windex if dtype == 3 else 0, windex if dtype == 0x22 else None),
                "expected_source": source,
                "expected_hex": expected_truncated.hex() if expected_truncated is not None else None,
                "actual_hex": actual.hex() if actual is not None else None,
                "expected_length": len(expected_truncated) if expected_truncated is not None else None,
                "actual_length": len(actual) if actual is not None else None,
                "result": status, "first_diff_offset": diff.get("first_diff_offset"),
                "different_offsets": diff.get("different_offsets", []),
                "byte_table": byte_diff_text(expected_truncated, actual) if expected_truncated is not None else "В профиле нет ожидаемого ответа для этого запроса.",
                "expected_decoded": describe_descriptor(dtype, expected_truncated) if expected_truncated is not None else [],
                "actual_decoded": describe_descriptor(dtype, actual) if actual is not None else [],
                "expected_hex_lines": hex_lines(expected_truncated) if expected_truncated is not None else [],
                "actual_hex_lines": hex_lines(actual, expected_truncated) if actual is not None else [],
                "host_transfer_status": g.get("status"),
                "payload_available": actual is not None,
            })
        elif g.get("endpoint_address") is not None and g.get("payload") is not None:
            data_transfers.append({"frames": g.get("frame_numbers", []), "endpoint_address": g.get("endpoint_address"),
                                   "payload_hex": g["payload"].hex(), "status": g.get("status")})

    # A case must not inherit unrelated host frames as positive evidence when the gadget never started.
    if run_status in ("NOT_RUN", "DRY_RUN_ONLY", "GENERATED", "NO_CHANGE") and started is None:
        verdict = "NOT_RUN_NOT_CAPTURE_MATCHABLE"
    elif run_status in ("START_FAILED", "LAUNCH_ERROR"):
        verdict = "DEVICE_START_FAILED"
    elif profile_error:
        verdict = "PROFILE_BYTES_UNAVAILABLE"
    elif not per_case_groups or not any(g.get("request") for g in per_case_groups):
        verdict = "NO_HOST_EVIDENCE_FOR_CASE"
    elif any(t["result"] == "MISMATCH" for t in descriptor_transactions):
        verdict = "HOST_DESCRIPTOR_BYTES_MISMATCH"
    elif host_errors:
        verdict = "HOST_TRANSFER_ERROR_OBSERVED"
    elif any(t["result"] == "HOST_BYTES_NOT_EXTRACTED" for t in descriptor_transactions):
        verdict = "HOST_RESPONSE_BYTES_UNAVAILABLE"
    elif any(t["result"] == "UNEXPECTED_OR_UNDEFINED_DESCRIPTOR" for t in descriptor_transactions):
        verdict = "HOST_REQUESTED_DESCRIPTOR_NOT_DEFINED_IN_PROFILE"
    elif descriptor_transactions and all(t["result"] == "MATCH" for t in descriptor_transactions):
        host_cfg_ok = any(c["value"] != 0 and c["complete_seen"] and not c["error"] for c in host_set_configs)
        device_summary = event_summary(device_events)
        if host_cfg_ok and device_summary["configured_observed"]:
            verdict = "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED"
        elif host_cfg_ok or device_summary["configured_observed"]:
            verdict = "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURATION_PARTIAL"
        else:
            verdict = "EXPECTED_DESCRIPTOR_BYTES_MATCH_ENUMERATION_INCOMPLETE"
    elif descriptor_transactions:
        verdict = "PARTIAL_DESCRIPTOR_CHECK"
    else:
        verdict = "HOST_CONTROL_TRAFFIC_OBSERVED_NO_DESCRIPTOR_RESPONSE"

    if profile is None:
        catalogue_display = []
        changed_fields = []
    else:
        _, catalogue_display = make_expected_display(profile, verifier)
        changed_fields = row.get("changes") or []
    device_sum = event_summary(device_events)
    trace_descriptor_transactions = device_trace_descriptor_summary(device_events, profile, standard) if profile else []
    use_timestamps = correlation_mode != "sequential"
    correlate_descriptor_transactions(descriptor_transactions, trace_descriptor_transactions, clock_offset, time_tolerance,
                                      use_timestamps=use_timestamps)
    trace_payload_transfers = device_trace_data_transfers(device_events, profile)
    # Timestamps are deliberately not compared in sequential mode: Pi and Windows clocks differ.
    if use_timestamps and started is not None:
        end_epoch = ended if ended is not None else started + float(row.get("dwell_seconds_requested", 10) or 10)
        trace_payload_transfers = [x for x in trace_payload_transfers if x.get("time_epoch") is None or
                                   started - time_tolerance <= x["time_epoch"] <= end_epoch + time_tolerance]
    correlated_data_transfers = correlate_data_transfers(trace_payload_transfers, per_case_groups, clock_offset,
                                                         time_tolerance, use_timestamps=use_timestamps)
    byte_statuses = [t.get("three_way_status") for t in descriptor_transactions]
    if any(x == "DEVICE_TRACE_BYTES_MISMATCH_PROFILE" for x in byte_statuses):
        byte_correlation_status = "DEVICE_TRACE_BYTES_MISMATCH_PROFILE"
    elif any(x == "HOST_BYTES_MISMATCH_DEVICE_TRACE" for x in byte_statuses):
        byte_correlation_status = "HOST_BYTES_MISMATCH_DEVICE_TRACE"
    elif any(x == "HOST_BYTES_MISMATCH_PROFILE" for x in byte_statuses):
        byte_correlation_status = "HOST_BYTES_MISMATCH_PROFILE"
    elif any(x == "HOST_BYTES_NOT_CAPTURED" for x in byte_statuses):
        byte_correlation_status = "HOST_BYTES_NOT_CAPTURED"
    elif descriptor_transactions and all(x == "ALL_THREE_BYTE_STREAMS_MATCH" for x in byte_statuses):
        byte_correlation_status = "ALL_THREE_BYTE_STREAMS_MATCH"
    elif descriptor_transactions:
        byte_correlation_status = "PARTIAL_BYTE_CORRELATION"
    else:
        byte_correlation_status = "NO_DESCRIPTOR_BYTE_CORRELATION"
    if byte_correlation_status in ("DEVICE_TRACE_BYTES_MISMATCH_PROFILE", "HOST_BYTES_MISMATCH_DEVICE_TRACE", "HOST_BYTES_MISMATCH_PROFILE"):
        verdict = byte_correlation_status
    requested_keys = {(x["descriptor_type"], x["descriptor_index"], x["language_id"], x.get("interface"))
                      for x in descriptor_transactions}
    for item in catalogue_display:
        key = (item["type"], item["index"], item.get("language_id", 0), item.get("interface"))
        item["observed_in_pcap"] = key in requested_keys
        item["capture_state"] = "OBSERVED_IN_PCAP" if key in requested_keys else "NOT_OBSERVED_IN_PCAP"
        if item["type"] == 0x22 and item.get("interface") is None and profile and profile.get("interface_descriptors"):
            item["capture_state"] = "GENERIC_REPORT_OVERRIDDEN_BY_INTERFACE_DESCRIPTOR"
            item["observed_in_pcap"] = any(t["descriptor_type"] == 0x22 for t in descriptor_transactions)
    return {
        "case": case_no, "profile": str(profile_path), "profile_name": profile.get("profile_name") if profile else None,
        "profile_sha256": row.get("profile_sha256") or row.get("sha256"), "run_status": run_status,
        "run_started_epoch": started, "run_ended_epoch": ended, "duration_seconds": row.get("duration_seconds"),
        "returncode": row.get("returncode"), "trace": str(trace_path) if trace_path else None,
        "profile_error": profile_error, "changes": changed_fields, "verdict": verdict,
        "time_window": {"start_epoch": started, "end_epoch": ended, "tolerance_seconds": time_tolerance,
                        "host_clock_offset_seconds": clock_offset},
        "device_trace_summary": device_sum,
        "host_groups_in_window": len(per_case_groups), "host_control_requests_in_window": host_control_requests,
        "host_session_id": (session_match or {}).get("session_id"),
        "host_session_match": session_match or {}, "correlation_mode": correlation_mode,
        "host_set_configuration": host_set_configs, "host_errors": host_errors,
        "host_cancellations": host_cancellations, "host_teardown_events": host_teardown_events,
        "descriptor_transactions": descriptor_transactions,
        "device_trace_descriptor_transactions": trace_descriptor_transactions,
        "byte_correlation_status": byte_correlation_status,
        "device_trace_payload_transfers": trace_payload_transfers,
        "correlated_data_transfers": correlated_data_transfers,
        "expected_descriptor_catalogue": catalogue_display,
        "configuration_comparison": reconstruct_host_configuration(descriptor_transactions, catalogue_display),
        "non_control_payload_transfers": data_transfers,
        "note": "PCAP/USBPcap shows host-stack observations. Sequential mode binds this case to one descriptor-fingerprint session in campaign order and does not compare Windows/Pi timestamps. USBPcap is not an electrical USB analyzer." if correlation_mode == "sequential" else "PCAP/USBPcap shows host-stack observations. Timestamp mode requires synchronized clocks. USBPcap is not an electrical USB analyzer."
    }


def human_verdict(code: str) -> str:
    return {
        "HOST_CORRELATION_AMBIGUOUS_SHARED_FRAMES": "КОРРЕЛЯЦИЯ НЕОДНОЗНАЧНА — кадры попали в несколько временных окон",
        "NOT_RUN_NOT_CAPTURE_MATCHABLE": "СЛУЧАЙ НЕ ЗАПУСКАЛСЯ — USBPcap не сопоставляется",
        "DEVICE_START_FAILED": "УСТРОЙСТВО НЕ СТАРТОВАЛО — трафик этому случаю не приписываем",
        "PROFILE_BYTES_UNAVAILABLE": "НЕ УДАЛОСЬ СОБРАТЬ ОЖИДАЕМЫЕ ДЕСКРИПТОРЫ ИЗ ПРОФИЛЯ",
        "NO_HOST_EVIDENCE_FOR_CASE": "НЕТ USB-НАБЛЮДЕНИЙ В ОКНЕ ЭТОГО СЛУЧАЯ",
        "HOST_DESCRIPTOR_BYTES_MISMATCH": "ОШИБКА: БАЙТЫ ДЕСКРИПТОРА В USBPcap НЕ СОВПАЛИ С ПРОФИЛЕМ",
        "HOST_TRANSFER_ERROR_OBSERVED": "НАБЛЮДАЛАСЬ ОШИБКА ПЕРЕДАЧИ ХОСТА — НУЖНА ПРОВЕРКА",
        "HOST_RESPONSE_BYTES_UNAVAILABLE": "ЗАПРОС ВИДЕН, НО БАЙТЫ ОТВЕТА НЕ ИЗВЛЕЧЕНЫ",
        "HOST_REQUESTED_DESCRIPTOR_NOT_DEFINED_IN_PROFILE": "ХОСТ ЗАПРОСИЛ ДЕСКРИПТОР, НЕ ОПИСАННЫЙ В ПРОФИЛЕ",
        "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED": "БАЙТЫ ДЕСКРИПТОРОВ СОВПАЛИ; CONFIGURED НАБЛЮДАЛСЯ НА ХОСТЕ И УСТРОЙСТВЕ",
        "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURATION_PARTIAL": "БАЙТЫ ДЕСКРИПТОРОВ СОВПАЛИ; CONFIGURED ПОДТВЕРЖДЁН ТОЛЬКО ОДНИМ ИСТОЧНИКОМ",
        "EXPECTED_DESCRIPTOR_BYTES_MATCH_ENUMERATION_INCOMPLETE": "БАЙТЫ ЗАПРОШЕННЫХ ДЕСКРИПТОРОВ СОВПАЛИ, НО CONFIGURED НЕ ПОДТВЕРЖДЁН",
        "PARTIAL_DESCRIPTOR_CHECK": "ЧАСТИЧНАЯ ПРОВЕРКА ДЕСКРИПТОРОВ",
        "HOST_CONTROL_TRAFFIC_OBSERVED_NO_DESCRIPTOR_RESPONSE": "УПРАВЛЯЮЩИЙ ТРАФИК ЕСТЬ, ОТВЕТЫ НА ДЕСКРИПТОРЫ НЕ НАЙДЕНЫ",
        "DEVICE_TRACE_BYTES_MISMATCH_PROFILE": "ОШИБКА: БАЙТЫ В TRACE RAW GADGET НЕ СОВПАЛИ С ПРОФИЛЕМ",
        "HOST_BYTES_MISMATCH_DEVICE_TRACE": "ОШИБКА: USBPcap НАБЛЮДАЛ БАЙТЫ, ОТЛИЧНЫЕ ОТ TRACE RAW GADGET",
        "HOST_BYTES_MISMATCH_PROFILE": "ОШИБКА: БАЙТЫ USBPcap НЕ СОВПАЛИ С ОЖИДАЕМЫМ ПРОФИЛЕМ",
    }.get(code, code)


def build_txt(report: dict[str, Any]) -> str:
    lines = ["USB CAMPAIGN — ПОБАЙТОВЫЙ ОТЧЁТ", "=" * 96,
             f"Кампания: {report['campaign_dir']}", f"PCAP/PCAPNG: {report['host_pcap']}",
             f"Всего случаев: {len(report['cases'])}", "", "СВОДКА СТАТУСОВ:"]
    inv = report.get("host_capture_inventory", {})
    lines.extend(["", "USB ENUMERATION ИЗ USBPcap (первые пакеты исключены до декодирования)", f"Control transfers: {inv.get('control_transfer_count', 0)}; GET_DESCRIPTOR: {inv.get('get_descriptor_count', 0)}"])
    for dev in inv.get("devices", []):
        ids = dev.get("vid_pid", {})
        lines.append(f"{dev.get('session_id')} frames={dev.get('first_frame')}-{dev.get('last_frame')} USB bus={dev.get('bus_id')} address={dev.get('device_address')} VID={ids.get('vid')} PID={ids.get('pid')} serial={dev.get('serial_number') or dev.get('serial_status')} state={dev.get('enumeration_status')}")
        lines.append(f"  endpoint transfers={dev.get('endpoint_transfer_count', 0)}; CANCELLED={dev.get('cancelled_transfer_count', 0)}; ABORT_PIPE={dev.get('abort_pipe_count', 0)} (teardown, не ошибка дескрипторов)")
        for tx in dev.get("transactions", []):
            lines.append(f"  frame={tx.get('frames')} {tx.get('descriptor_name')} status={tx.get('urb_status')} HEX={tx.get('actual_hex') or 'NO DATA'}")
    recon = report.get("device_reconciliation", {})
    lines.extend(["", "СОПОСТАВЛЕНИЕ: ОТПРАВЛЕНО ЭМУЛЯТОРОМ → НАЙДЕНО В USBPcap",
                  f"Отправлено: {recon.get('sent_count', 0)}; серийников обнаружено: {recon.get('observed_serial_count', 0)}"])
    for status, count in sorted(recon.get("status_counts", {}).items()):
        lines.append(f"  {status}: {count}")
    for item in recon.get("sent_devices", []):
        lines.append(f"  CASE {int(item.get('case') or 0):05d} {item.get('serial_number')} -> {item.get('host_status')} (run={item.get('run_status')})")
    lines.append("  ВАЖНО: NOT_OBSERVED_IN_PCAP не является доказательством блокировки фильтром.")
    for status, count in sorted(report["status_counts"].items()):
        lines.append(f"  {status}: {count}")
    lines.extend(["", f"РЕЖИМ СОПОСТАВЛЕНИЯ: {report.get('host_correlation_mode')}; синхронизация часов для sequential mode не требуется.",
                  "NOT_OBSERVED_IN_PCAP не доказывает BLOCK; для вывода о фильтре нужен его журнал ALLOW/BLOCK.",
                  "USBPcap — наблюдение USB host stack, не анализатор электрической шины."])
    for case in report["cases"]:
        lines.extend(["", "=" * 96,
                      f"CASE {case['case']:05d} | run={case['run_status']} | verdict={case['verdict']}",
                      human_verdict(case['verdict']), f"Профиль: {case['profile']}",
                      f"SHA-256: {case.get('profile_sha256')}", f"Длительность: {case.get('duration_seconds')} s",
                      f"Trace: {case.get('trace')}", f"Host session: {case.get('host_session_id') or case.get('host_session_match', {}).get('status')}; frames/groups: {case['host_groups_in_window']}",
                      f"USB control requests in window: {case['host_control_requests_in_window']}",
                      f"BYTE CORRELATION: {case.get('byte_correlation_status', 'NOT_EVALUATED')}"])
        if case.get("profile_error"):
            lines.append("ОШИБКА ПРОФИЛЯ: " + case["profile_error"])
        lines.append("Изменённые поля:")
        lines.extend("  " + str(x) for x in case.get("changes", [])) if case.get("changes") else lines.append("  (изменения не записаны в manifest)")
        ts = case["device_trace_summary"]
        lines.append(f"Trace: requests={ts['control_request_count']}, responses={ts['control_response_complete_count']}, configured={ts['configured_observed']}, STALL={ts['stall_count']}, reset={ts['reset_count']}, disconnect={ts['disconnect_count']}, errors={ts['error_count']}")
        lines.append("GET_DESCRIPTOR, записанные Raw Gadget (payload trace — отдельное наблюдение, не PCAP):")
        if case.get("device_trace_descriptor_transactions"):
            for item in case["device_trace_descriptor_transactions"]:
                lines.append(f"  {item['name']}: trace={item.get('result')}, request seq={item.get('request_sequence')}, response seq={item.get('response_sequence')}, trace_len={item.get('trace_length')}, expected_len={item.get('expected_length')}")
        else:
            lines.append("  в trace нет завершённых ответов GET_DESCRIPTOR")
        lines.append("SET_CONFIGURATION, замеченный USBPcap:")
        if case["host_set_configuration"]:
            lines.extend(f"  value={x['value']} frames={x['frames']} status={x['status']} complete={x['complete_seen']} error={x['error']}" for x in case["host_set_configuration"])
        else:
            lines.append("  не наблюдался")
        lines.append(f"Host teardown: CANCELLED={len(case.get('host_cancellations', []))}; ABORT_PIPE={len(case.get('host_teardown_events', []))}; прочих ошибок={len(case.get('host_errors', []))}")
        for event in case.get("host_cancellations", []) + case.get("host_teardown_events", []):
            lines.append(f"  frames={event.get('frames')} endpoint={event.get('endpoint')} status={event.get('status')} details={event.get('status_details')}")
        for event in case.get("host_errors", []):
            lines.append(f"  HOST ERROR frames={event.get('frames')} status={event.get('status')} details={event.get('status_details')}")
        lines.extend(["", "ОТВЕТЫ НА GET_DESCRIPTOR (ОЖИДАЕМЫЕ БАЙТЫ ПРОФИЛЯ VS USBPcap):"])
        if not case["descriptor_transactions"]:
            lines.append("  Не найдена однозначно сопоставленная USB-сессия для этого Case.")
        for n, t in enumerate(case["descriptor_transactions"], 1):
            lines.extend(["", f"  [{n}] {t['descriptor_name']} | result={t['result']} | frames={t['frames']} | USB address={t.get('device_address')}",
                          f"      wLength={t['request'].get('wLength')} | expected_len={t.get('expected_length')} | host_len={t.get('actual_length')} | transfer={t.get('host_transfer_status')}",
                          "      " + (f"first diff offset: 0x{t['first_diff_offset']:04X}" if t.get("first_diff_offset") is not None and t['result'] == "MISMATCH" else "байтовое сравнение: " + t['result']),
                          "      PROFILE / EXPECTED (HEX):", "      " + (t.get("expected_hex") or "<не определено в профиле>"),
                          "      DEVICE TRACE / Raw Gadget payload (HEX):", "      " + (t.get("device_trace_payload_hex") or "<ответ не записан в trace или не сопоставлен>"),
                          "      WINDOWS USBPcap / HOST OBSERVED (HEX):", "      " + (t.get("actual_hex") or "<байты не извлечены>"),
                          "      DEVICE TRACE vs PROFILE: " + str(t.get("expected_vs_device", {}).get("status", t.get("device_trace_result_vs_profile", "UNKNOWN"))),
                          "      USBPcap vs DEVICE TRACE: " + str(t.get("device_vs_host", {}).get("status", "UNKNOWN")),
                          "      THREE-WAY STATUS: " + str(t.get("three_way_status", "UNKNOWN")),
                          "      ПОБАЙТОВОЕ СРАВНЕНИЕ (offset | expected | Raw Gadget | USBPcap):"])
            lines.extend("      " + ln for ln in t.get("three_way_byte_table", t.get("byte_table", "")).splitlines())
            if t.get("expected_decoded"):
                lines.append("      Расшифровка expected:")
                lines.extend("        " + x for x in t["expected_decoded"])
            if t.get("actual_decoded"):
                lines.append("      Расшифровка USBPcap:")
                lines.extend("        " + x for x in t["actual_decoded"])
        lines.extend(["", "ДЕСКРИПТОРЫ ИЗ ПРОФИЛЯ, НЕ НАБЛЮДЁННЫЕ В PCAP:"])
        unseen = [x for x in case.get("expected_descriptor_catalogue", []) if x.get("capture_state") == "NOT_OBSERVED_IN_PCAP"]
        if unseen:
            for item in unseen:
                lines.append(f"  {item['name']}: {item['expected_hex']} (NOT_OBSERVED_IN_PCAP; это не доказывает, что хост не запрашивал его вне окна/захвата)")
        else:
            lines.append("  все каталогизированные ключи дескрипторов наблюдались (не обязательно все байты сравнивались)")
        comparison = case.get("configuration_comparison", {})
        lines.extend(["", "ПОЛНОЕ ВОССТАНОВЛЕНИЕ КОНФИГУРАЦИИ ПО USBPcap (только наблюдавшиеся данные):",
                      f"  EXPECTED VID={comparison.get('expected_ids', {}).get('vid')} PID={comparison.get('expected_ids', {}).get('pid')}",
                      f"  HOST VID={comparison.get('host_ids', {}).get('vid')} PID={comparison.get('host_ids', {}).get('pid')}"])
        for item in comparison.get("entries", []):
            lines.extend([f"  {item['name']} | {item['result']} | state={item['state']}",
                          f"    EXPECTED HEX: {item.get('expected_hex') or '<нет в профиле>'}",
                          f"    HOST HEX:     {item.get('host_hex') or '<не получено>'}"])
            lines.extend("    EXPECTED: " + x for x in item.get("expected_decoded", []))
            lines.extend("    HOST: " + x for x in item.get("host_decoded", []))
        if case.get("host_errors"):
            lines.extend(["", "ОШИБОЧНЫЕ HOST TRANSFERS:"])
            lines.extend(f"  frames={e.get('frames')} status={e.get('status')} request={e.get('request')}" for e in case["host_errors"])
        if case.get("correlated_data_transfers"):
            lines.extend(["", "DATA ENDPOINT / CONTROL PAYLOADS (TRACE TX/RX VS USBPcap):"])
            for x in case["correlated_data_transfers"]:
                trace_hex = x.get("payload_hex") or x.get("payload_preview_hex") or "<не записано>"
                host_hex = x.get("host_payload_hex") or "<не получено/не извлечено>"
                lines.append(f"  event={x.get('event')} endpoint=0x{int(x.get('endpoint_address',0)):02X} direction={x.get('direction')} result={x.get('comparison_status')} host_frames={x.get('host_frames')}")
                lines.append(f"    PROFILE EXPECTED HEX: {x.get('expected_payload_hex') or '<не задано в профиле>'}")
                lines.append(f"    DEVICE TRACE HEX:     {trace_hex}")
                lines.append(f"    USBPcap HEX:          {host_hex}")
                lines.append(f"    PROFILE vs TRACE:     {x.get('expected_vs_trace_status', 'NOT_DEFINED_IN_PROFILE')}")
                if x.get("comparison"):
                    lines.append(f"    comparison={x['comparison']}")
        if case.get("non_control_payload_transfers"):
            lines.extend(["", "HOST DATA TRANSFERS WITH PAYLOAD:"])
            for x in case["non_control_payload_transfers"]:
                lines.append(f"  frames={x['frames']} endpoint=0x{int(x['endpoint_address']):02x} bytes={len(bytes.fromhex(x['payload_hex']))} status={x['status']} hex={x['payload_hex']}")
    lines.append("")
    return "\n".join(lines)


def html_byte_dump(data: bytes | None, expected: bytes | None = None) -> str:
    if data is None:
        return '<p class="missing">Байты ответа не извлечены из PCAPNG.</p>'
    rows = []
    for base in range(0, len(data), 16):
        cells = []
        for offset in range(base, min(base + 16, len(data))):
            value = data[offset]
            mismatch = expected is not None and (offset >= len(expected) or expected[offset] != value)
            cells.append(f'<span class="byte {"bad" if mismatch else "good"}" title="offset 0x{offset:04X}">{value:02X}</span>')
        ascii_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[base:base+16])
        rows.append(f'<div class="hexrow"><span class="offset">{base:04X}</span><code>{" ".join(cells)}</code><span class="ascii">{html.escape(ascii_text)}</span></div>')
    return '<div class="hexdump">' + ''.join(rows) + '</div>'


def descriptor_html(t: dict[str, Any], index: int) -> str:
    result = t.get("three_way_status", t.get("result", "UNKNOWN"))
    status_class = "match" if result in ("ALL_THREE_BYTE_STREAMS_MATCH", "DEVICE_TRACE_AND_HOST_BYTES_MATCH") else ("mismatch" if "MISMATCH" in result else "warn")
    expected = bytes.fromhex(t["expected_hex"]) if t.get("expected_hex") else None
    device = bytes.fromhex(t["device_trace_payload_hex"]) if t.get("device_trace_payload_hex") else None
    actual = bytes.fromhex(t["actual_hex"]) if t.get("actual_hex") else None
    def fields(items: list[str]) -> str:
        return '<ul class="decoded">' + ''.join(f'<li>{html.escape(x)}</li>' for x in items) + '</ul>' if items else '<p class="muted">Нет декодированных полей.</p>'
    expected_panel = f'''<section class="pane expected"><h4>ОЖИДАЛОСЬ — JSON PROFILE</h4><p>Источник: {html.escape(t.get('expected_source','profile'))}; длина: {t.get('expected_length')}</p>{html_byte_dump(expected)}<h5>Расшифровка</h5>{fields(t.get('expected_decoded',[]))}</section>'''
    device_panel = f'''<section class="pane sent"><h4>ОТПРАВЛЕНО — RAW GADGET TRACE</h4><p>Длина: {t.get('device_trace_length')}; статус: {html.escape(str(t.get('device_trace_status')))}; trace seq: {html.escape(str(t.get('device_trace_response_sequence')))}</p>{html_byte_dump(device, expected)}<p class="muted">Payload, переданный в EP0_WRITE и записанный trace; это не электрическое измерение шины.</p></section>'''
    host_panel = f'''<section class="pane observed"><h4>ПОЛУЧЕНО — WINDOWS USBPcap</h4><p>Длина: {t.get('actual_length')}; состояние URB: {html.escape(str(t.get('host_transfer_status')))}; frames: {html.escape(str(t.get('frames')))}</p>{html_byte_dump(actual, device if device is not None else expected)}<h5>Расшифровка</h5>{fields(t.get('actual_decoded',[]))}</section>'''
    byte_table = t.get("three_way_byte_table") or t.get("byte_table", "")
    return f'''<details class="descriptor">
<summary><b>GET_DESCRIPTOR #{index}: {html.escape(t['descriptor_name'])}</b><span class="pill {status_class}">{html.escape(result)}</span><span class="muted">frames {html.escape(str(t['frames']))}; host address {html.escape(str(t.get('device_address')))}</span></summary>
<div class="comparegrid threeway">{expected_panel}{device_panel}{host_panel}</div>
<div class="diffline"><b>Сравнение:</b> expected → trace: {html.escape(str(t.get('expected_vs_device', {}).get('status', 'UNKNOWN')))}; trace → USBPcap: {html.escape(str(t.get('device_vs_host', {}).get('status', 'UNKNOWN')))}; общий статус: {html.escape(result)}.</div>
<details><summary>Побайтовая таблица</summary><pre>{html.escape(byte_table)}</pre></details>
</details>'''


def build_html(report: dict[str, Any]) -> str:
    cards = []
    for case in report["cases"]:
        case_class = "bad" if ("MISMATCH" in case["verdict"] or "ERROR" in case["verdict"] or "FAILED" in case["verdict"]) else ("good" if case["verdict"] == "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED" else "warn")
        changes = ''.join(f'<li>{html.escape(str(x))}</li>' for x in case.get("changes", [])) or '<li class="muted">Нет записанных мутаций.</li>'
        descriptor_parts = ''.join(descriptor_html(t, i) for i, t in enumerate(case.get("descriptor_transactions", []), 1))
        if not descriptor_parts:
            if case.get("host_session_match", {}).get("status") == "AMBIGUOUS":
                descriptor_parts = '<p class="missing">Сессия PCAP есть, но её нельзя однозначно назначить конкретному Case по отпечатку профиля.</p>'
            else:
                descriptor_parts = '<p class="missing">Для этого Case не найдена однозначная USB-сессия в PCAP после исключения первых шести пакетов.</p>'
        unseen = [x for x in case.get("expected_descriptor_catalogue", []) if x.get("capture_state") == "NOT_OBSERVED_IN_PCAP"]
        unseen_html = ''.join(f'<details><summary>{html.escape(x["name"])} — ожидаемо, в PCAP не замечено</summary><pre>{html.escape(x["expected_hex"])}</pre>{html_byte_dump(bytes.fromhex(x["expected_hex"]))}</details>' for x in unseen)
        events = case["device_trace_summary"]
        setcfg = ''.join(f'<li>value={x["value"]}; frames={html.escape(str(x["frames"]))}; transfer={html.escape(str(x["status"]))}; complete={x["complete_seen"]}; error={x["error"]}</li>' for x in case["host_set_configuration"]) or '<li>SET_CONFIGURATION не наблюдался в PCAP.</li>'
        cards.append(f'''<details class="case {case_class}" open>
<summary><span class="case-title">CASE {case['case']:05d}</span><span class="pill {case_class}">{html.escape(case['verdict'])}</span><span class="muted">run={html.escape(case['run_status'])}; session={html.escape(str(case.get('host_session_id') or case.get('host_session_match', {}).get('status') or 'NOT_ASSIGNED'))}; host groups={case['host_groups_in_window']}</span></summary>
<div class="meta"><p><b>Профиль:</b> {html.escape(case['profile'])}</p><p><b>SHA-256:</b> <code>{html.escape(str(case.get('profile_sha256')))}</code></p><p><b>Trace:</b> {html.escape(str(case.get('trace')))}</p><p><b>События на Pi:</b> control requests={events['control_request_count']}, completed EP0={events['control_response_complete_count']}, CONFIGURED={events['configured_observed']}, STALL={events['stall_count']}, reset={events['reset_count']}, disconnect={events['disconnect_count']}, errors={events['error_count']}</p><p><b>Windows USBPcap:</b> реальные ошибки={len(case.get('host_errors', []))}; CANCELLED при остановке={len(case.get('host_cancellations', []))}; ABORT_PIPE teardown={len(case.get('host_teardown_events', []))}</p><p><b>Проверка байтов:</b> {html.escape(str(case.get('byte_correlation_status')))}</p>{''.join('<p class="missing">'+html.escape(str(w))+'</p>' for w in case.get('warnings', []))}</div>
<h3>Что изменено в этом профиле</h3><ul>{changes}</ul>
<h3>Полная конфигурация: EXPECTED ↔ максимально восстановленная USBPcap</h3>{configuration_comparison_html(case.get("configuration_comparison", {}))}
<h3>Что Raw Gadget записал в trace</h3><ul>{''.join(f'<li>{html.escape(str(x["name"]))}: trace={html.escape(str(x.get("result")))}, request seq={html.escape(str(x.get("request_sequence")))}, response seq={html.escape(str(x.get("response_sequence")))}, байт={html.escape(str(x.get("trace_length")))} / expected={html.escape(str(x.get("expected_length")))}</li>' for x in case.get("device_trace_descriptor_transactions", [])) or '<li>Нет завершённых ответов GET_DESCRIPTOR в trace.</li>'}</ul>
<h3>События SET_CONFIGURATION в хостовом захвате</h3><ul>{setcfg}</ul>
<h3>Побайтовая проверка дескрипторов: профиль → Raw Gadget → USBPcap</h3>{descriptor_parts}
<h3>Данные endpoint/control после enumeration</h3>{''.join(f'<details><summary>{html.escape(str(x.get("event")))} endpoint=0x{int(x.get("endpoint_address",0)):02X} {html.escape(str(x.get("direction")))} — {html.escape(str(x.get("comparison_status")))}</summary><p>PROFILE EXPECTED HEX</p><pre>{html.escape(str(x.get("expected_payload_hex") or "НЕ ЗАДАНО В ПРОФИЛЕ"))}</pre><p>DEVICE TRACE HEX</p><pre>{html.escape(str(x.get("payload_hex") or x.get("payload_preview_hex") or "НЕ ЗАПИСАНО"))}</pre><p>WINDOWS USBPcap HEX</p><pre>{html.escape(str(x.get("host_payload_hex") or "НЕ ПОЛУЧЕНО / НЕ ИЗВЛЕЧЕНО"))}</pre><p>PROFILE vs TRACE={html.escape(str(x.get("expected_vs_trace_status")))}; frames={html.escape(str(x.get("host_frames")))}</p></details>' for x in case.get("correlated_data_transfers", [])) or '<p class="muted">Нет сопоставимых payload endpoint/control transfers в trace.</p>'}
<h3>Ожидаемые дескрипторы, не замеченные в PCAP</h3>{unseen_html or '<p>Все ожидаемые ключи дескрипторов были замечены в захвате (это не гарантирует наличие данных по каждому запросу).</p>'}
</details>''')
    counts = ''.join(f'<div class="summarybox"><b>{n}</b><span>{html.escape(s)}</span></div>' for s, n in sorted(report["status_counts"].items()))
    recon = report.get("device_reconciliation", {})
    recon_rows = ''.join(f'<tr><td>{html.escape(str(x.get("case")))}</td><td>{html.escape(str(x.get("device_id")))}</td><td>{html.escape(str(x.get("serial_number")))}</td><td>{html.escape(str(x.get("run_status")))}</td><td>{html.escape(str(x.get("host_status")))}</td><td>{html.escape(str(x.get("host_sessions")))}</td></tr>' for x in recon.get("sent_devices", []))
    reconciliation_html = f'''<p>Запусков эмулятора: <b>{recon.get("sent_count", 0)}</b>; прочитанных серийников: <b>{recon.get("observed_serial_count", 0)}</b>; режим сопоставления: <b>{html.escape(str(recon.get("matching_mode")))}</b>.</p><table><thead><tr><th>Case</th><th>Device ID</th><th>Serial ID</th><th>Gadget run</th><th>Результат на хосте</th><th>Сессии</th></tr></thead><tbody>{recon_rows}</tbody></table><p class="note">Сопоставление не использует часы Windows/Raspberry Pi. NOT_OBSERVED_IN_PCAP не доказывает блокировку фильтром — для этого нужен журнал ALLOW/BLOCK.</p>'''
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>USB campaign byte report</title>
<style>
:root{{color-scheme:light dark;--border:#7d8790;--bg:#12171c;--panel:#1c242c;--text:#e8edf2;--muted:#aeb8c2;--ok:#214d38;--bad:#6c252a;--warn:#5d4a1f;--byte:#313b45}}
body{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;background:var(--bg);color:var(--text);margin:0;padding:22px;line-height:1.42}}h1,h2,h3,h4,h5{{font-family:system-ui,sans-serif}}h1{{margin:0 0 6px}}h2{{margin-top:26px}}.meta,.muted{{color:var(--muted);overflow-wrap:anywhere}}.summary{{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0}}.summarybox{{border:1px solid var(--border);border-radius:8px;padding:10px;min-width:130px;display:flex;flex-direction:column;gap:5px}}.summarybox b{{font-size:22px}}.case{{border:1px solid var(--border);border-radius:10px;margin:14px 0;padding:12px;background:var(--panel)}}summary{{cursor:pointer;display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:4px}}.case-title{{font-size:18px;font-weight:bold}}.pill{{padding:3px 8px;border-radius:5px;font-size:12px;overflow-wrap:anywhere}}.pill.match,.pill.good{{background:var(--ok)}}.pill.mismatch,.pill.bad{{background:var(--bad)}}.pill.warn{{background:var(--warn)}}.comparegrid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:10px 0}}.pane{{min-width:0;border:1px solid var(--border);border-radius:8px;padding:10px}}.pane h4{{margin:0 0 10px}}.expected{{border-top:4px solid #3f9a64}}.observed{{border-top:4px solid #c18d41}}.sent{{border-top:4px solid #5288bd}}.hexdump{{overflow-x:auto;background:#0e1216;padding:8px;border-radius:5px}}.hexrow{{display:flex;gap:8px;white-space:nowrap}}.offset{{color:#8da0b3;min-width:42px}}.ascii{{color:#93a5b7;margin-left:8px}}.byte{{display:inline-block;padding:1px 2px;border-radius:2px;margin-right:1px;background:var(--byte)}}.byte.bad{{background:#a72f39;color:#fff;font-weight:bold}}.byte.good{{background:#254633}}.missing{{color:#ffbd8f;border:1px solid #9a653d;padding:10px;border-radius:5px}}.descriptor-row{{border:1px solid var(--border);border-left:5px solid #777;border-radius:7px;padding:10px;margin:9px 0}}.descriptor-row.added{{border-left-color:#27ae60;background:#123322}}.descriptor-row.unobserved{{border-left-color:#77818a;background:#242a30}}.descriptor-row.changed{{border-left-color:#d69e36;background:#332b18}}.descriptor-row.same{{border-left-color:#568c6b}}.descriptor-pair,.id-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}.descriptor-pair pre{{overflow-wrap:anywhere}}.decoded{{margin-top:7px;padding-left:20px;overflow-wrap:anywhere}}.diffline{{margin:10px 0;padding:8px;background:#0e1216;border-radius:5px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0e1216;padding:10px;border-radius:5px}}.note{{border-left:4px solid #c18d41;padding:10px;margin:12px 0}}@media(max-width:850px){{.comparegrid{{grid-template-columns:1fr}}}}
</style></head><body>
<h1>USB Research Toolkit — побайтовый отчёт кампании</h1><p class="meta">Кампания: {html.escape(report['campaign_dir'])}<br>PCAPNG: {html.escape(report['host_pcap'])}<br>Generated: {html.escape(report['created_utc'])}</p>
<div class="note">Три источника: ожидаемые байты JSON-профиля; payload Raw Gadget; USBPcap host-stack. Для native USBPcap linktype 249 используется прямой разбор PCAPNG, первые шесть packet records исключаются. Cases сопоставляются с USB enumeration-сессиями по порядку и фактическим дескрипторам/endpoint payload, без сравнения часов Raspberry Pi и Windows. Это не электрический USB-анализатор.</div>
<div class="summary">{counts}</div>
<h2>Сопоставление запусков эмулятора с USB-сессиями Windows</h2>{reconciliation_html}<h2>USB-конфигурация, восстановленная из USBPcap после исключения первых пакетов</h2><p class="note">Первые шесть packet records не участвуют ни в инвентаре, ни в построении USB-сессий. Остальной захват анализируется целиком, независимо от временных окон Raspberry Pi.</p>{host_inventory_html(report.get('host_capture_inventory', {}))}<h2>Случаи фаззинга и сопоставление</h2>{''.join(cards)}
</body></html>'''


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Побайтовый отчёт USB-кампании: JSON profile → Raw Gadget trace → USBPcap (TXT + HTML + JSON).")
    ap.add_argument("--campaign-dir", required=True, help="каталог кампании с campaign.jsonl, case-*.json, traces/")
    ap.add_argument("--host-pcap", required=True, help="один PCAP/PCAPNG со всей кампанией")
    ap.add_argument("--out-prefix", help="префикс выходных файлов (по умолчанию <campaign-dir>/protocol-report)")
    ap.add_argument("--tshark", default="tshark", help="путь к tshark (только для не-USBPcap fallback)")
    ap.add_argument("--skip-host-packets", type=int, default=6,
                    help="сколько начальных packet records PCAPNG игнорировать (default: 6 для USBPcap)")
    ap.add_argument("--host-correlation-mode", choices=("auto", "sequential", "time"), default="auto",
                    help="auto: sequential для USBPcap linktype 249, time для остальных; sequential не использует clocks")
    ap.add_argument("--time-tolerance", type=float, default=0.75, help="допуск временного сопоставления, seconds")
    ap.add_argument("--host-clock-offset-seconds", type=float, default=0.0,
                    help="legacy time mode only: host minus Pi clock offset")
    args = ap.parse_args(argv)
    campaign_dir = Path(args.campaign_dir).resolve()
    pcap = Path(args.host_pcap).resolve()
    if not campaign_dir.is_dir():
        ap.error(f"каталог кампании не найден: {campaign_dir}")
    if not pcap.is_file():
        ap.error(f"PCAP/PCAPNG не найден: {pcap}")
    if args.time_tolerance < 0:
        ap.error("--time-tolerance должен быть >= 0")
    if args.skip_host_packets < 0:
        ap.error("--skip-host-packets должен быть >= 0")

    rows = load_campaign_rows(campaign_dir)
    if not rows:
        rows = []
        for case_path in sorted(campaign_dir.glob("case-*.json")):
            match = re.search(r"case-(\d+)", case_path.name)
            if match:
                rows.append({"case": int(match.group(1)), "profile": str(case_path), "status": "NOT_RUN",
                             "trace": str(campaign_dir / "traces" / f"case-{int(match.group(1)):05d}.device.jsonl")})
    rows = merge_manifest_cases(campaign_dir, rows)
    if not rows:
        ap.error(f"в {campaign_dir} не найден campaign.jsonl/manifest.json с результатами или case-*.json")

    print(f"Читаю PCAPNG: {pcap}", flush=True)
    host_rows, fields, capture_meta = read_host_capture_rows(pcap, args.tshark, skip_packets=args.skip_host_packets)
    host_groups = build_transfer_groups(host_rows)
    session_summaries = assign_usb_enumeration_sessions(host_groups)
    host_inventory = build_host_capture_inventory(host_groups)
    verifier = import_verifier()

    profile_by_case: dict[int, dict[str, Any] | None] = {}
    profile_path_by_case: dict[int, Path] = {}
    trace_path_by_case: dict[int, Path | None] = {}
    events_by_case: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        number = int(row.get("case", 0))
        profile_path = case_profile_path(row, campaign_dir)
        profile_path_by_case[number] = profile_path
        profile = None
        if profile_path.is_file():
            try:
                profile = json.loads(profile_path.read_text(encoding="utf-8-sig"))
            except Exception:
                profile = None
        profile_by_case[number] = profile
        trace_path = case_trace_path(row, campaign_dir)
        trace_path_by_case[number] = trace_path
        events_by_case[number] = load_jsonl(trace_path) if trace_path and trace_path.is_file() else []

    if args.host_correlation_mode == "auto":
        correlation_mode = "sequential" if 249 in capture_meta.get("linktypes", []) else "time"
    else:
        correlation_mode = args.host_correlation_mode
    if correlation_mode == "sequential":
        session_matches = match_usb_sessions_to_cases(rows, host_inventory, host_groups, profile_by_case, verifier)
        groups_by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for group in host_groups:
            if group.get("session_id"):
                groups_by_session[str(group["session_id"])].append(group)
        assigned_by_case: dict[int, list[dict[str, Any]]] = {}
        for row in rows:
            number = int(row.get("case", 0))
            mapping = session_matches.get("by_case", {}).get(str(number), {})
            if mapping.get("status") == "MATCHED":
                assigned_by_case[number] = groups_by_session.get(str(mapping.get("session_id")), [])
            else:
                assigned_by_case[number] = []
    else:
        session_matches = {"mode": "TIME_WINDOW_LEGACY", "clock_correlation_used": True, "by_case": {}, "by_session": {}}
        assigned_by_case = {}

    device_reconciliation = reconcile_campaign_devices(rows, host_inventory, session_matches,
                                                        args.host_clock_offset_seconds, args.time_tolerance)
    print(f"USBPcap: captured={capture_meta.get('packet_count')}, skipped={capture_meta.get('skipped_packets')}, "
          f"decoded={len(host_rows)}, transfer_groups={len(host_groups)}; parser={capture_meta.get('parser')}", flush=True)
    print("USB enumeration sessions: " + ", ".join(
        f"{x['session_id']} frames {x['first_frame']}-{x['last_frame']}" for x in session_summaries), flush=True)
    if correlation_mode == "sequential":
        for case_no, match in sorted(session_matches.get("by_case", {}).items(), key=lambda x: int(x[0])):
            if match.get("status") == "MATCHED":
                print(f"MATCH CASE {int(case_no):05d} <- {match['session_id']} score={match['score']}", flush=True)
        for sid, match in session_matches.get("by_session", {}).items():
            if match.get("status") == "AMBIGUOUS":
                print(f"AMBIGUOUS {sid}: candidates={match.get('candidate_cases')}", flush=True)

    cases = []
    for row in sorted(rows, key=lambda x: int(x.get("case", 0))):
        number = int(row.get("case", 0))
        profile_path = profile_path_by_case[number]
        profile = profile_by_case[number]
        trace_path = trace_path_by_case[number]
        events = events_by_case[number]
        mapping = session_matches.get("by_case", {}).get(str(number), {})
        cases.append(render_case(row, profile_path, trace_path, profile, events, host_groups, verifier,
                                 args.time_tolerance, args.host_clock_offset_seconds,
                                 assigned_host_groups=assigned_by_case.get(number) if correlation_mode == "sequential" else None,
                                 correlation_mode=correlation_mode, session_match=mapping))
        c = cases[-1]
        match_count = sum(t["result"] == "MATCH" for t in c["descriptor_transactions"])
        mismatch_count = sum(t["result"] == "MISMATCH" for t in c["descriptor_transactions"])
        print(f"CASE {number:05d}: {c['verdict']} | host session={c.get('host_session_id') or mapping.get('status', 'NOT_ASSIGNED')} "
              f"| descriptor responses={len(c['descriptor_transactions'])} match={match_count} mismatch={mismatch_count}", flush=True)

    # Same PCAP frame must never be attributed to two fuzz cases in sequential mode.
    frame_owners: dict[int, set[int]] = defaultdict(set)
    for case in cases:
        for transfer in case.get("descriptor_transactions", []):
            for frame in transfer.get("frames", []):
                if frame is not None:
                    frame_owners[int(frame)].add(int(case["case"]))
        for transfer in case.get("correlated_data_transfers", []):
            for frame in transfer.get("host_frames", []):
                if frame is not None:
                    frame_owners[int(frame)].add(int(case["case"]))
    duplicate_frames = {frame: owners for frame, owners in frame_owners.items() if len(owners) > 1}
    if duplicate_frames:
        raise RuntimeError("Внутренняя ошибка: кадры PCAP назначены нескольким Case: " +
                           ", ".join(f"{frame}:{sorted(owners)}" for frame, owners in list(duplicate_frames.items())[:20]))

    status_counts = dict(Counter(case["verdict"] for case in cases))
    report = {"report_version": 3, "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "campaign_dir": str(campaign_dir), "host_pcap": str(pcap),
              "host_capture_parser": capture_meta, "tshark_fields": fields,
              "host_correlation_mode": correlation_mode, "host_clock_synchronized": False if correlation_mode == "sequential" else None,
              "time_tolerance_seconds": args.time_tolerance, "host_clock_offset_seconds": args.host_clock_offset_seconds,
              "host_frame_count": len(host_rows), "host_transfer_group_count": len(host_groups),
              "usb_enumeration_sessions": session_summaries, "session_matching": session_matches,
              "status_counts": status_counts, "host_capture_inventory": host_inventory,
              "device_reconciliation": device_reconciliation, "cases": cases,
              "limitations": [
                  "USBPcap records Windows USB host-stack/URB observations; it is not an electrical USB analyzer.",
                  "The first six captured packet records were excluded before USBPcap parsing, as configured.",
                  "Sequential matching uses campaign order and descriptor/endpoint fingerprints; Windows/Pi timestamps are not compared.",
                  "A host session not observed in this capture is not proof of a filter BLOCK without a filter ALLOW/BLOCK event log.",
                  "A successful SET_CONFIGURATION completion proves the host stack completed that request, not that the class driver loaded or the device functioned correctly.",
              ]}
    prefix = Path(args.out_prefix).resolve() if args.out_prefix else campaign_dir / "protocol-report"
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = prefix.with_suffix(".json")
    txt_path = prefix.with_suffix(".txt")
    html_path = prefix.with_suffix(".html")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    txt_path.write_text(build_txt(report), encoding="utf-8")
    html_path.write_text(build_html(report), encoding="utf-8")
    print("\n=== ОТЧЁТ СОЗДАН ===")
    print(f"TXT : {txt_path}")
    print(f"HTML: {html_path}")
    print(f"JSON: {json_path}")
    print("Сводка:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"report-usb-campaign: ошибка: {exc}", file=sys.stderr)
        raise SystemExit(2)
