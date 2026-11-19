#!/usr/bin/env python3
"""Regression tests for native USBPcap PCAPNG decoding and sequential matching."""
import importlib.util
import struct
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("usbpcap_sequential", ROOT / "scripts/report-usb-campaign.py")
REPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORTER)


def _block(block_type: int, body: bytes) -> bytes:
    body += b"\x00" * ((-len(body)) % 4)
    total = 8 + len(body) + 4
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _usbpcap_packet(irp: int, function: int, info: int, bus: int, address: int,
                    endpoint: int, transfer_type: int, stage: int | None,
                    status: int, payload: bytes) -> bytes:
    header_len = 28 if stage is not None else 27
    packet = bytearray(header_len)
    struct.pack_into("<H", packet, 0, header_len)
    struct.pack_into("<Q", packet, 2, irp)
    struct.pack_into("<I", packet, 10, status)
    struct.pack_into("<H", packet, 14, function)
    packet[16] = info
    struct.pack_into("<H", packet, 17, bus)
    struct.pack_into("<H", packet, 19, address)
    packet[21] = endpoint
    packet[22] = transfer_type
    struct.pack_into("<I", packet, 23, len(payload))
    if stage is not None:
        packet[27] = stage
    return bytes(packet) + payload


def _pcapng(records: list[bytes]) -> bytes:
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _block(1, struct.pack("<HHI", 249, 0, 65535))
    epbs = []
    for i, packet in enumerate(records, 1):
        body = struct.pack("<IIIII", 0, 0, i * 1000, len(packet), len(packet)) + packet
        epbs.append(_block(6, body))
    return shb + idb + b"".join(epbs)


def test_first_six_raw_packet_records_are_skipped():
    # Six unrelated records first, then one real GET_DESCRIPTOR(Device) IRP.
    unrelated = [_usbpcap_packet(i, 0x0009, 0, 1, 2, 0x01, 3, None, 0, b"xx") for i in range(1, 7)]
    device = bytes.fromhex("12 01 00 02 00 00 00 40 09 12 00 12 00 01 01 02 03 01")
    setup = struct.pack("<BBHHH", 0x80, 6, 0x0100, 0, 18)
    records = unrelated + [
        _usbpcap_packet(0xABC, 0x000B, 0, 1, 1, 0, 2, 0, 0, setup),
        _usbpcap_packet(0xABC, 0x0008, 1, 1, 1, 0, 2, 3, 0, device),
    ]
    with tempfile.TemporaryDirectory() as td:
        capture = Path(td) / "fixture.pcapng"
        capture.write_bytes(_pcapng(records))
        rows, meta = REPORTER.read_usbpcap_pcapng_rows(capture, skip_packets=6)
    assert meta["packet_count"] == 8
    assert meta["skipped_packets"] == 6
    assert meta["first_included_frame"] == 7
    assert [r["frame_number"] for r in rows] == [7, 8]
    groups = REPORTER.build_transfer_groups(rows)
    assert len(groups) == 1
    assert groups[0]["frame_numbers"] == [7, 8]
    assert groups[0]["payload"] == device


def test_teardown_does_not_become_host_transfer_failure():
    rows = [
        {"frame_number": 10, "bus_id": 1, "device_address": 1, "irp_id": "a",
         "urb_type": "S", "urb_function": "URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER (0x0009)",
         "usbpcap_function": 9, "urb_status": 0x40000000, "endpoint_address": 0x81,
         "transfer_type": 1, "payload": None},
        {"frame_number": 11, "bus_id": 1, "device_address": 1, "irp_id": "a",
         "urb_type": "C", "urb_function": "URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER (0x0009)",
         "usbpcap_function": 9, "urb_status": 0xC0010000, "endpoint_address": 0x81,
         "transfer_type": 1, "payload": None},
        {"frame_number": 12, "bus_id": 1, "device_address": 1, "irp_id": "b",
         "urb_type": "C", "urb_function": "URB_FUNCTION_ABORT_PIPE (0x0002)",
         "usbpcap_function": 2, "urb_status": 0x80000300, "endpoint_address": 0x81,
         "transfer_type": 0xFE, "payload": None},
    ]
    groups = REPORTER.build_transfer_groups(rows)
    assert len(groups) == 2
    cancelled = next(g for g in groups if g["status"] == "CANCELLED")
    abort = next(g for g in groups if g["status"] == "TEARDOWN_ABORT_PIPE")
    assert any(x["name"] == "USBD_STATUS_CANCELED" for x in cancelled["status_details"])
    assert any(x["name"] == "USBD_STATUS_INVALID_PARAMETER" for x in abort["status_details"])
    assert abort["is_irp_info"] is True


def test_sessions_split_by_successful_configuration_and_case_mapping_ignores_clocks():
    device = bytes.fromhex("12 01 00 02 00 00 00 40 09 12 00 12 00 01 01 02 03 01")
    config1 = bytes.fromhex("09 02 09 00 00 01 00 80 32")
    config2 = bytes.fromhex("09 02 09 00 00 FF 00 80 32")
    def group(frame, request, payload=None):
        return {"frame_numbers": [frame, frame + 1], "bus_id": 1, "device_address": 1,
                "request": request, "payload": payload, "status": "COMPLETED", "complete_seen": True}
    groups = []
    for first, cfg in ((1, config1), (10, config2)):
        groups += [
            group(first, {"bmRequestType": 0x80, "bRequest": 6, "wValue": 0x0100, "wIndex": 0, "wLength": 18}, device),
            group(first + 2, {"bmRequestType": 0x80, "bRequest": 6, "wValue": 0x0200, "wIndex": 0, "wLength": 9}, cfg),
            group(first + 4, {"bmRequestType": 0, "bRequest": 9, "wValue": cfg[5], "wIndex": 0, "wLength": 0}),
        ]
    sessions = REPORTER.assign_usb_enumeration_sessions(groups)
    assert [x["session_id"] for x in sessions] == ["bus1-session001", "bus1-session002"]
    assert groups[0]["session_id"] != groups[3]["session_id"]


def test_failed_set_configuration_still_closes_session_before_next_case():
    device = bytes.fromhex("12 01 00 02 00 00 00 40 09 12 00 12 00 01 01 02 03 01")
    def group(frame, request, status="COMPLETED", complete=True):
        return {"frame_numbers": [frame, frame + 1], "bus_id": 1, "device_address": 1,
                "request": request, "payload": device if request.get("wValue") == 0x0100 else None,
                "status": status, "complete_seen": complete,
                "time_epoch": 9_000_000_000.0 + frame}
    get_device = {"bmRequestType": 0x80, "bRequest": 6, "wValue": 0x0100, "wIndex": 0, "wLength": 18}
    set_config = {"bmRequestType": 0, "bRequest": 9, "wValue": 1, "wIndex": 0, "wLength": 0}
    groups = [group(7, get_device), group(20, set_config, status="ERROR"), group(30, get_device)]
    sessions = REPORTER.assign_usb_enumeration_sessions(groups)
    assert [x["session_id"] for x in sessions] == ["bus1-session001", "bus1-session002"]
    assert groups[0]["session_id"] == "bus1-session001"
    assert groups[2]["session_id"] == "bus1-session002"
    assert sessions[0]["first_frame"] == 7
    assert sessions[1]["first_frame"] == 30


def test_observed_unique_serial_overrides_profile_fingerprint_and_does_not_use_clocks():
    rows = [{"case": 7, "status": "COMPLETED", "serial_number": "URTK-ABC-00007",
             "started_epoch": 1.0, "ended_epoch": 2.0}]
    inventory = {"devices": [{"session_id": "bus1-session003", "first_frame": 500,
                              "serial_number": "URTK-ABC-00007", "vid_pid": {"vid": 0x1209, "pid": 0x1200}}]}
    result = REPORTER.match_usb_sessions_to_cases(rows, inventory, [], {}, None)
    match = result["by_case"]["7"]
    assert match["status"] == "MATCHED"
    assert match["session_id"] == "bus1-session003"
    assert match["evidence"]["serial_number"] == "EXACT"
    assert result["clock_correlation_used"] is False
    assert result["mode"] == "SEQUENTIAL_PROFILE_FINGERPRINT"


if __name__ == "__main__":
    test_first_six_raw_packet_records_are_skipped()
    test_teardown_does_not_become_host_transfer_failure()
    test_sessions_split_by_successful_configuration_and_case_mapping_ignores_clocks()
    test_failed_set_configuration_still_closes_session_before_next_case()
    test_observed_unique_serial_overrides_profile_fingerprint_and_does_not_use_clocks()
    print("test_usbpcap_sequential_matching: PASS")
