# Home Network Assessor

A local check of a home network you own. It lists the devices Nmap can see, scores the open ports, reads the router's port-forward list when the router answers, and writes an HTML report plus a JSON report.

Read [GUIDE.md](GUIDE.md) for the security reasoning, and [README-IMPORTANT.md](README-IMPORTANT.md) before the first scan. The short version: this tool sends real packets, and it refuses any target that is not a private home range.

## What changed from the first draft

The first draft was a skeleton. The modules were named, and several of the advertised checks did nothing. This version does the checks, and it stops itself when a request would leave the home LAN.

- `python main.py` shows a check menu and does not probe until you pick. `scan` takes the same choices as flags. `monitor` is the other command.
- A target outside loopback, link-local, or a private home range is refused. There is no switch that turns that check off. Hostnames are refused too, so a name cannot quietly point at the public internet.
- `critical_ports` in `config.yaml` is actually used. Telnet, FTP, VNC, RTSP, MQTT, SMB, and Remote Desktop are still flagged if you delete them from that list.
- The score separates "open on the LAN" from "the router forwards this to the internet". A normal router with HTTP and HTTPS is MEDIUM. A forwarded Remote Desktop is CRITICAL.
- Version notes come from `cve_db/hints.json`. The file is short on purpose. It names the issue and the upgrade. It does not describe how to abuse anything.
- UPnP is read-only. A discovery answer that points at a public URL is ignored. The forward list is part of the report.
- Public-IP lookup is off unless you set `lookup_public_ip: true`.
- The HTML report escapes device names and service text, and it sends a Content-Security-Policy that blocks scripts.
- The monitor waits for repeated misses, keys devices by MAC, and does not treat a totally empty scan as "everyone powered off".
- The magic-packet hook stays off until `block_magic_packets: true`. The shipped hook only writes a log line.
- Local Wake-on-LAN disable is one fixed command, `ethtool -s <interface> wol d`, over key-based SSH. The profile cannot supply its own command.
- Nmap is called only with a fixed profile. `--script vuln` is in the open-ports profile and in the open-ports phase of all. A hand-written `nmap_args` line still cannot contain `--script`, `--script-args`, `-sC`, `-A`, an output flag, or a shell character. `--open` is not used, so closed and filtered ports can be recorded.
- `tests/` runs without scanning anything.

## Thought process

A home assessment has two different questions.

The first is what is running inside the house. A Windows PC with file sharing and Remote Desktop is ordinary. A router with a web page on ports 80 and 443 is ordinary. Telnet is not ordinary. An old Apache with a known flaw is not ordinary either. The points follow that. Dangerous-by-default services get a high LAN score. Common home services get a small score so they show up without painting the whole house red.

The second question is what the router publishes. A forward is a path from the internet to a computer in the house. That is a different fact from "the port is open on the LAN", so it adds its own points and it lifts the level. Forwarding Telnet, FTP, SMB, Remote Desktop, VNC, RTSP, or MQTT is CRITICAL even when the point total is still modest. Any other forward is at least HIGH.

The levels are:

| Level | Rule |
| --- | --- |
| CRITICAL | 70 points or more, or a forward of port 21, 23, 445, 3389, 5900, 554, or 1883 |
| HIGH | 40 points or more, or any other forward |
| MEDIUM | 10 points or more |
| LOW | under 10 |

Each scored host gets one sentence that names that rule and the findings that added the points. A vulnerability script is one of those findings: the sentence quotes the script name and what it reported. If the script text looked like an exploit recipe, the sentence keeps the script name and the port, and it tells you to read the vendor advisory. A score of 0 says LOW because nothing in that scan added points. That is not a clean result. Scripts stay quiet when the probed ports are closed or filtered, and the scan only covered the ports you chose.

LAN points for a port:

| Port | Points | Why it is scored this way |
| --- | --- | --- |
| 23 Telnet | 40 | Logins are not encrypted. Turn it off. |
| 21 FTP | 40 | Logins are not encrypted. Turn it off. |
| 5900 VNC | 40 | Often a weak or empty password. |
| 554 RTSP | 25 | Usually a camera. Fine on the LAN, bad if forwarded. |
| 1883 MQTT | 20 | Often no login. Keep it on the LAN. |
| 445 SMB | 15 | Normal on a Windows PC. Bad if forwarded. |
| 3389 Remote Desktop | 15 | Normal on a PC you manage. Bad if forwarded. |
| 22, 80, 443, 8080 | 10 | Only when they stay on your review list. |
| Any other review port | 10 | Your choice in `config.yaml`. |

A matching line in `cve_db/hints.json` adds its own points on top of the port. Two examples from the tests:

- Telnet, SMB, Apache 2.4.49, and OpenSSH 7.2 together are CRITICAL (130). The Apache line and the old SSH line are doing real work there, and so is Telnet.
- A router with only HTTP and HTTPS is MEDIUM (20). The first draft scored that router as LOW and ignored the version numbers.

No match in the hint file is not a clean result. The file only knows a few products. Everything else is "this port is open", not "this software is patched".

Vulnerability scripts run only when you pick open ports, or all. That profile is Nmap's own `vuln` category, with no extra script and no script arguments. Firewalls, address discovery, the router check, the named service check, and the monitor do not use it. Version detection stays on for every port check, so an open port can show a service name and a version. Those probes are still real traffic. The caution file says to aim the first vulnerability run, and the first full port scan, at one address.

The monitor does less, on purpose. A version scan every five minutes is a lot of traffic. The monitor uses a ping scan and only decides a device is offline after three missed checks. One ignored ping is not a powered-off PC. An empty result is ignored while the tool still thinks something is online, because that usually means this computer dropped off the LAN. Devices are remembered by MAC so a DHCP address change does not look like a new PC and an old one leaving.

Wake-on-LAN control is split the same way the network is split. `ethtool` only works while the operating system is running, so that attempt happens when the device appears. A filter in front of the computer matters once the computer is off, so the hook is offered at the offline event. Both are quiet unless you fill in a profile and, for the hook, turn the config flag on. The hook that ships with the project does not insert firewall rules. A rule you have not tested can cut a machine off, including the one you are sitting at.

UPnP is the router's own list of forwards. Reading it answers the exposure question without guessing. Writing it would change the network, so this project never sends `AddPortMapping` or `DeletePortMapping`. A discovery packet can contain any URL. The tool fetches a URL only when the host is a private IP, so a bad answer cannot make your computer request a public site.

## How to use it

Install Nmap, then the Python packages. Nmap is a separate program. The pip line does not install it.

Windows: install Nmap from [https://nmap.org/download.html](https://nmap.org/download.html), open a new terminal, and confirm `nmap --version` works. Use an elevated terminal if you want a full device list. Without it, Nmap often misses computers that ignore ping.

Debian or Ubuntu:

```bash
sudo apt install nmap
```

From this folder:

```bash
python -m pip install -r requirements.txt
```

`config.yaml` does not name a network. When the program starts it reads the private LAN on this computer and ignores VPN, virtual, loopback, and link-local adapters. It then looks for the devices that answer on that LAN. That read is not a probe. The menu still waits until you pick a check. To limit a heavy check to one computer, set `networks` to that one private address.

`python main.py` prints the check menu and waits. It does not probe before you pick a number.

```text
Network Vulnerability Testing
1. IP addresses. Who is online, plus devices seen before. You can then probe one of them.
2. Routers. The gateway, its admin ports, and the read-only UPnP forward list.
3. Firewalls. Which ports look open, closed, or filtered from this computer.
4. Open ports. Choose one address or the whole range, then run vulnerability scripts.
5. All. Run 1 through 4. The port checks can use one address or the whole range.
6. DNS, QUIC, DHCP, NTP, and IPsec. Only that named set.
7. Quit.
```

The menu then prints who is online and who has been seen before. That list is read from `reports/devices.json`. Printing it does not probe. Option 1 is the check that refreshes who is online: the addresses that answered. A device that misses that check moves to Seen before. Later checks add a device when it answers, and they do not drop the others. The monitor uses the same file and waits for three missed pings before it moves a device to Seen before. The file stays in `reports/`, which is gitignored.

Option 1 lists the addresses that answered, then asks you to probe one of them:

```text
Probe one of these hosts with vulnerability scripts?
1. 192.168.1.1  no name  Example Router
2. No. Return to the menu.
```

The last number returns to the check menu. Any other number runs the vulnerability scripts on that address only, after you pick a port range and answer the warning.

Open ports, and All, then ask which address to probe:

```text
Which address should be probed?
1. Every address on the configured range
2. One address that answered
```

Choice 2 finds the addresses that answer, then shows them as a numbered list. You pick a number. You do not type an address. The vulnerability scripts run only on that address. In All, the router check still talks to the gateway.

Checks 3, 4, and 5 then ask for a port range. Check 6 does not.

```text
Port range
1. Top 10
2. Top 100
3. Top 1000
4. Full (TCP 1-65535)
```

After that range menu the program asks `Also scan DNS, QUIC, DHCP, NTP, and IPsec? yes/no`. Pressing Enter means no. Top 1000 and a full TCP scan ask you to confirm before any probe, because one computer can take a long time and a whole `/24` can take hours. Open ports, and all, ask a second question: the vulnerability probes can upset a printer, camera, TV, or old router. No on either question exits with code 0 and sends nothing.

The same choices are flags. You do not type a port list, a script name, or raw Nmap flags.

```bash
python main.py scan addresses
python main.py scan routers
python main.py scan firewalls --range top100
python main.py scan open-ports --range top100
python main.py scan open-ports --range full --also services
python main.py scan all --range top100 --also services
python main.py scan services
python main.py monitor
```

`--range` accepts only `top10`, `top100`, `top1000`, or `full`. `--also services` adds the named UDP set on top of firewalls, open-ports, or all. `config.yaml` may set `check` and `port_scan`. The flag wins. `python main.py scan` with neither a check nor a range anywhere uses open ports and top 100, which matches the previous default, and still asks the vulnerability question before it probes.

`critical_ports` only decides which open ports get a written note. It does not decide which ports are scanned.

The program holds these argument lists and will not send anything else:

| Check | Arguments |
| --- | --- |
| IP addresses, and the monitor | `-sn -T3` |
| Routers | `-sV -p 22,23,80,443,8080,8443 -T3` |
| Firewalls, top 10 / 100 / 1000 / full | `-sV --top-ports 10 -T3`, `-sV --top-ports 100 -T3`, `-sV --top-ports 1000 -T3`, `-sV -p- -T3` |
| Open ports, same ranges | the firewall list for that range, then `--script vuln` |
| DNS, QUIC, DHCP, NTP, and IPsec | `-sV -sU -p T:53,443,U:53,67,68,123,443,500,4500 -T3` |

All runs addresses, then routers, then the firewall list, then the open-ports list. `--also services` runs the TCP profile first and the named service profile second, and keeps a host when the UDP probe returns nothing.

Each finished run names the choices on the report, for example `Check: open ports. Port scan: top 100. Also services: no`. It writes:

- `reports/report_YYYYMMDD_HHMMSS.html`
- `reports/report_YYYYMMDD_HHMMSS.json`
- `reports/latest.html` and `reports/latest.json`

Open `reports/latest.html` in a browser. The top of the page repeats the limits of the score. Then it lists router forwards, then each computer, highest score first. The terminal prints the same headlines.

`examples/sample-report.html` is a fake report, so you can see the layout before Nmap is installed. It is not your network.

Watch the LAN:

```bash
python main.py monitor
```

Ctrl+C stops it. State is kept in `reports/presence_state.json`. The default wait is 300 seconds, and a device is called offline after 3 missed checks. Both numbers are in `config.yaml`.

A profile is optional. `profiles/example-device.yaml` is not loaded, because the name starts with `example`. Copy it to something like `profiles/living-room.yaml` and set the MAC. `desired_wol: block` means two things:

- When the computer comes online, the tool tries the `ethtool` command if you also set `ssh_user`, `ssh_identity_file`, and `interface`.
- When it has been offline for the required number of checks, the tool runs the hook only if `block_magic_packets` is true.

`wol_block_list` in the config is the same mark, for a MAC or IP that does not have its own file.

To add a port you care about, put the number in `critical_ports`. To add a version note, add a product to `cve_db/hints.json` using the shape that is already there: a match string, and either an exact version or an "older than" line, plus a summary that says what to upgrade. Keep the summary free of attack steps.

Run the tests from this folder. They do not scan the network.

```bash
python -m unittest discover -s tests -t .
```

## Layout

| Path | Role |
| --- | --- |
| `main.py` | Command line |
| `assessment.py` | One scan, then the report |
| `local_lan.py` | The private LAN on this computer. It does not probe |
| `scanner.py` | Fixed Nmap profiles, plus MAC addresses from the ARP table |
| `analyzer.py` | Scores |
| `cve_db/hints.json` | The small version list |
| `exposure.py` | Public-IP lookup and read-only UPnP |
| `reporter.py` | HTML and JSON |
| `monitor.py` | The repeating check |
| `presence.py` | Online / offline decisions for the monitor |
| `devices.py` | Who is online, and the history of devices already seen |
| `profiles.py` | Per-device files |
| `actions.py` | The SSH command and the hook |
| `hooks/` | Log-only scripts |
| `config.yaml` | Ports and switches. The LAN is read from this computer |
| `GUIDE.md` | Why the safety limits exist |
| `reports/` | Output. Gitignored. Treat it as private |

## Exit codes

`0` means the run finished, or you answered no to a warning. A CRITICAL host does not change that. `1` means Nmap failed. `2` means the config, the menu, or the target was refused. No probes are sent on `2`, or when a warning is declined.
