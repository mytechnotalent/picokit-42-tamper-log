![picokit-42-tamper-log](https://raw.githubusercontent.com/mytechnotalent/picokit-42-tamper-log/main/picokit-42-tamper-log.png)

<br>

## FREE Reverse Engineering Self-Study Course [HERE](https://github.com/mytechnotalent/reverse-engineering)
## FREE Embedded Hacking Course [HERE](https://github.com/mytechnotalent/Embedded-Hacking)

<br>

# PICOKIT-42 TAMPER LOG

### BLAKE2b Hash-Chained Event Log and Recompute on Read
#### Lesson 42 of the Picokit Series

<br>

***
**LEGAL DISCLAIMER:**
The information, tools, and code provided in this repository and course are strictly for educational, research, and defensive purposes only.

You are explicitly prohibited from using any materials contained herein to access, test, modify, or exploit any device, network, or system that you do not own 100% or for which you do not have explicit, documented, and legally binding authorization to interact with.

By using this repository and course, you acknowledge and agree that:

1. Any illegal, unauthorized, or malicious use of this information is solely your responsibility.
2. The author(s) and contributor(s) of this repository and course shall not be held liable for any damages, legal repercussions, criminal charges, or unauthorized actions resulting from the use, misuse, or abuse of the contents herein.
3. You will comply with all applicable local, state, national, and international laws regarding cybersecurity and computer fraud.

**IF YOU DO NOT AGREE WITH THESE TERMS, DO NOT USE THIS REPOSITORY AND COURSE.**
***

<br>
<br>

## Overview

The forty-second Picokit lesson. The node keeps a tamper-evident event log:
every event is folded into a running BLAKE2b hash chain, and on each heartbeat
the node recomputes the whole chain from the retained events and compares it to
the stored head. Any edit to a logged event changes the recomputed head, so the
heartbeat reports `v=0`. An intact log reports `v=1`.

<br>

## What it teaches

- Chaining events with an unkeyed BLAKE2b hash so order and content are bound.
- Recomputing the chain from the raw log on every heartbeat.
- Detecting a single flipped byte in any logged event.
- Reporting the chain verdict in an authenticated heartbeat.

<br>

## Hardware

| Peripheral | Pico 2 pin | Role |
| --- | --- | --- |
| Red / Yellow / Green | GP16 / GP18 / GP17 | tamper verdict (red) and intact (green) |
| Onboard LED | GP25 | heartbeat, one blink per transmit |
| RYLR998 | GP8 TX / GP9 RX | LoRa heartbeat |
| Debug Probe | SWCLK/SWDIO/GND, GP0/GP1 | SWD and the console |

<br>

## How it works

The node runs `monitor_step` in a loop. Every 5 seconds it appends the current
sequence number to the chain, recomputes the chain from the retained events,
and compares it to the stored head. The heartbeat body
`{"n":42,"s":<seq>,"v":<1=valid>}` is sealed with the shared field key and sent
over LoRa. The green lamp lights while the chain verifies and the red lamp
lights when it does not.

<br>

## Build and flash

```bash
cd firmware
cmake -S . -B build -G Ninja -DPICO_BOARD=pico2 -DPICO_PLATFORM=rp2350-arm-s
cmake --build build
openocd -f interface/cmsis-dap.cfg -f target/rp2350.cfg \
  -c "program build/picokit_42_tamper_log.elf verify reset exit"
```

<br>

## Watch the node

Open the console at 115200 and reset:

```text
BOOT
=== PICOKIT-42 TAMPER LOG // BLAKE2b HASH CHAIN ===
TAMPER n=42 valid=1 seq=1
TAMPER n=42 valid=1 seq=2
RX from 0x0001, N bytes
```

<br>

## The gateway

```bash
cd gateway
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 listen.py --port /dev/cu.usbserial-A50285BI --hub 0001 --network 18 --db gateway.db
```

It prints `OK node=42 rssi=...` per authenticated heartbeat. The terminal
dashboard `python3 tui.py --db gateway.db` and the web dashboard
`python3 web/app.py --db gateway.db` show the same rows.

<br>

## Verify

```bash
python3 .opencode/skill/embedded-c-standard/audit_c_standard.py
python3 .opencode/skill/embedded-python-standard/audit_python_standard.py
python3 .opencode/skill/iot-readme-standard/validate_readme.py
python3 .opencode/skill/iot-banner-standard/validate_banner.py
python3 scripts/run_tests.py
python3 scripts/check_coverage.py
```

<br>

# Next
[picokit-43-swd-breakpoints](https://github.com/mytechnotalent/picokit-43-swd-breakpoints)

<br>

# License
[MIT License](https://github.com/mytechnotalent/picokit-42-tamper-log/blob/main/LICENSE)
