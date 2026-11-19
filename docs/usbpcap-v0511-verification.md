# USBPcap sequential parser verification (0.5.11)

## Capture supplied for regression

The supplied `campaign(4).pcapng` was parsed with the native PCAPNG/USBPcap parser (`linktype 249`). The first six packet records were excluded before decoding and before transfer/session construction.

Observed parser counters:

- packet records in capture: 17,616
- excluded packet records: 6
- decoded USBPcap records: 17,610
- transfer groups: 8,805
- parser warnings: 0

Three enumeration sessions were reconstructed:

| Session | Original PCAP frames | VID:PID | SET_CONFIGURATION | Result |
|---|---:|---|---:|---|
| bus1-session001 | 7–5978 | 1209:1200 | 1 | completion status 0 |
| bus1-session002 | 5979–11944 | 1209:1200 | 255 | completion status 0 |
| bus1-session003 | 11945–17616 | 1209:1200 | 1 | completion status 0 |

For all three sessions, Device Descriptor, Configuration Descriptor and HID Report Descriptor responses were recovered. The Device Descriptor has `iSerialNumber=3`, but this capture contains no request for String Descriptor index 3. It is therefore correctly reported as `SERIAL_REQUEST_NOT_OBSERVED`; the parser must not invent a serial number from the profile.

The capture also contains endpoint cancellation and `URB_FUNCTION_ABORT_PIPE` teardown records. They remain visible but are not reported as failed descriptor/configuration transfers.

## Matching mode

For USBPcap linktype 249, `auto` selects sequential matching. No comparison is made between Raspberry Pi epoch timestamps and Windows PCAP timestamps. The ordered session/profile matching is based on captured descriptor and endpoint bytes; a serial match takes precedence only when its string was actually read from the host capture.

The uploaded project ZIP did not contain the original campaign's `campaign.jsonl`, `manifest.json`, per-case profile files or Raw Gadget traces. Therefore the actual PCAP session reconstruction is verified against the real capture, while end-to-end matching to the original Case IDs and three-way Raw Gadget/profile/Windows comparison still requires that campaign result directory.

## Automated verification

- CMake build completed successfully.
- CTest: 14/14 tests passed.
- New `test_usbpcap_sequential_matching.py` covers packet skipping, failed configuration session boundaries, serial-first matching and no clock correlation.
