#!/usr/bin/env python3
"""Tests per-case USB serial identity and PCAPNG sent/observed reconciliation."""
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

reporter = load("report_identity", ROOT / "scripts/report-usb-campaign.py")
gadget = load("gadget_identity", ROOT / "scripts/usb-gadget-campaign.py")


def group(frame, t, addr, request, payload=None, status="COMPLETED"):
    return {"frame_numbers": [frame, frame + 1], "time_epoch": t, "bus_id": 1,
            "device_address": addr, "urb_id": f"irp-{frame}", "irp_id": f"irp-{frame}",
            "status": status, "complete_seen": True, "request": request,
            "payload": bytes.fromhex(payload) if payload else None}


def test_campaign_serial_injection():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        profile = json.loads((ROOT / "profiles/valid/minimal-device.json").read_text())
        p = out / "case-00001.json"
        p.write_text(json.dumps(profile))
        cases = [{"case": 1, "profile": str(p), "changes": []}]
        campaign_id = gadget.stamp_campaign_identity(cases, out, "test")
        saved = json.loads(p.read_text())
        idx = saved["device"]["iSerialNumber"]
        serial = saved["strings"]["1033"][str(idx)]
        assert serial == f"URTK-{campaign_id}-00001"
        assert cases[0]["serial_number"] == serial
        manifest = json.loads((out / "manifest.json").read_text())
        assert manifest["cases"][0]["serial_number"] == serial


def test_host_serial_and_configured_reconciliation():
    serial = "URTK-ABC1234567-00001"
    dev = bytes([18, 1, 0, 2, 0, 0, 0, 64, 0x09, 0x12, 0x34, 0x12, 0, 1, 1, 2, 3, 1]).hex()
    string = (bytes([2 + len(serial.encode("utf-16le")), 3]) + serial.encode("utf-16le")).hex()
    groups = [
        group(1, 100.0, 0, {"bmRequestType": 0x80, "bRequest": 6, "wValue": 0x0100, "wIndex": 0, "wLength": 18}, dev),
        group(3, 100.1, 0, {"bmRequestType": 0, "bRequest": 5, "wValue": 1, "wIndex": 0, "wLength": 0}),
        group(5, 100.2, 1, {"bmRequestType": 0x80, "bRequest": 6, "wValue": 0x0303, "wIndex": 0x0409, "wLength": len(bytes.fromhex(string))}, string),
        group(7, 100.3, 1, {"bmRequestType": 0, "bRequest": 9, "wValue": 1, "wIndex": 0, "wLength": 0}),
    ]
    inv = reporter.build_host_capture_inventory(groups)
    session = next(x for x in inv["devices"] if x["device_address"] == 1)
    assert session["serial_number"] == serial
    assert session["configured_observed"] is True
    recon = reporter.reconcile_campaign_devices([{"case": 1, "device_id": "case-00001",
        "campaign_id": "ABC1234567", "serial_number": serial, "status": "COMPLETED"}], inv)
    assert recon["sent_devices"][0]["host_status"] == "RECEIVED_AND_CONFIGURED"


def test_missing_serial_is_not_claimed_as_filter_block():
    inv = {"devices": []}
    recon = reporter.reconcile_campaign_devices([{"case": 2, "serial_number": "URTK-X-00002", "status": "COMPLETED"}], inv)
    assert recon["sent_devices"][0]["host_status"] == "NOT_OBSERVED_IN_PCAP"
    assert "не доказывает блокировку" in recon["note"]


def test_host_seen_but_string_descriptor_not_requested():
    dev = bytes([18, 1, 0, 2, 0, 0, 0, 64, 0x09, 0x12, 0x34, 0x12, 0, 1, 1, 2, 0, 1]).hex()
    groups = [
        group(1, 200.0, 0, {"bmRequestType": 0x80, "bRequest": 6, "wValue": 0x0100, "wIndex": 0, "wLength": 18}, dev),
        group(3, 200.1, 0, {"bmRequestType": 0, "bRequest": 5, "wValue": 2, "wIndex": 0, "wLength": 0}),
        group(5, 200.2, 2, {"bmRequestType": 0, "bRequest": 9, "wValue": 1, "wIndex": 0, "wLength": 0}),
    ]
    inv = reporter.build_host_capture_inventory(groups)
    recon = reporter.reconcile_campaign_devices([{"case": 4, "serial_number": "URTK-X-00004",
        "status": "COMPLETED", "started_epoch": 199.9, "ended_epoch": 200.5}], inv)
    assert recon["sent_devices"][0]["host_status"] == "HOST_SESSION_FOUND_CASE_IDENTITY_UNRESOLVED"
    assert recon["sent_devices"][0]["match_method"] is None
    assert recon["clock_correlation_used"] is False

if __name__ == "__main__":
    test_campaign_serial_injection()
    test_host_serial_and_configured_reconciliation()
    test_missing_serial_is_not_claimed_as_filter_block()
    test_host_seen_but_string_descriptor_not_requested()
    print("test_campaign_device_identity: PASS")
