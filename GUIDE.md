# Security guide

This file is the reasoning behind Home Network Assessor. [README.md](README.md) is how to run it. [README-IMPORTANT.md](README-IMPORTANT.md) is the short caution list. Nothing in this guide is a procedure for breaking into a system.

The project is a defensive check of a home LAN you own. The cybersecurity knowledge it is meant to show is not a bag of attacks. It is knowing where the boundary is, what the tool is allowed to send, what a result means, and what must never leave your computer.

## The job, stated as a boundary

A security tool is safe only inside a boundary you can name.

This tool's boundary is one private home network, assessed from a computer that is already on that network. The operator owns the network, or has been given permission. The tool does not join a network, log in to a device, or pick a target that was typed into the source code.

Two questions sit inside that boundary.

1. What answered on the LAN, and which of those services are worth a human look?
2. Did the router publish any of those services toward the internet, according to the read-only UPnP list?

A port that is open on the LAN is not the same fact as a port the router forwards. A Windows PC with file sharing is ordinary at home. The same port forwarded to the internet is a different problem. The score keeps those facts apart on purpose.

## What a careless scanner would get wrong

The dangerous version of this project is easy to picture, and every control below exists to stop one of these mistakes.

- A hostname, a public address, or a range that only partly overlaps a private block gets scanned because the user typed it.
- The program always aims at one address that was written into the code, so it cannot be used on any other honest home LAN, and a copy of the repo reveals that address.
- Whatever the user types is passed to Nmap, including a script name, an output file, or a shell character.
- A vulnerability script's text, including a sample request, is stored in the report and then committed.
- UPnP is used to add or delete a port forward.
- A quiet host is labeled safe.
- A device name that contains HTML is written into the report and runs when someone opens the file.
- The report, with names and MAC addresses, is pushed to GitHub.

The tests in `tests/` are there to catch those mistakes without sending a packet.

## How a target is chosen

`config.yaml` does not contain a network address. On startup `local_lan.py` reads this computer's own IPv4 adapters and the default route. It keeps a private network whose prefix is between 16 and 30. It ignores adapters whose names look like a VPN, a virtual machine, a tunnel, a loopback interface, or a link-local address. If the default route belongs to one of those adapters, another real private adapter is used instead. If nothing qualifies, the program stops and sends nothing.

That is discovery of the LAN the computer is already on. It is not a connection to a predetermined node, and it is not a scan by itself. The menu still waits until a check is chosen.

`network_guard.py` runs again before any probe. The whole target must sit inside loopback, link-local, a private home range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or the IPv6 equivalents. There is no setting that turns this off. Hostnames are refused, because a name can point at the public internet even when it looks local. Carrier-grade NAT (`100.64.0.0/10`) is refused, because those addresses can belong to an access provider. A range that starts private and ends public is refused, because checking only the first address would be a hole.

The router check reads the default gateway from the routing table. A public gateway is refused before that probe.

You can still set `networks` to one private address when you want a heavy check limited to one computer. That value is checked by the same guard. If it is set, the adapter lookup does not replace it.

## What is allowed to be sent

Nmap is a separate program. `python-nmap` only launches it. The arguments are not taken from the keyboard.

Each check has one fixed argument list in `scanner.py`.

| Check | What is sent | What it is for |
| --- | --- | --- |
| Addresses, and the monitor | `-sn -T3` | Which addresses answer. No ports, no scripts. |
| Routers | `-sV` on 22, 23, 80, 443, 8080, and 8443, timing `-T3` | The gateway's admin ports, then a read-only UPnP read. |
| Firewalls | `-sV` and a chosen top-port set, or `-p-` for a full TCP scan | Open, closed, and filtered, as seen from this computer. |
| Open ports | The firewall list for that range, plus `--script vuln` | The same port picture, plus Nmap's built-in vulnerability scripts. |
| Named services | Version detection on DNS, QUIC, DHCP, NTP, and IPsec, TCP and UDP as listed in the code | Whether those named ports answer. |

`-T3` is normal timing. One computer, one pass. The tool does not fan out, and it does not raise the timing to push a firewall over.

`--open` is not used. Closed and filtered stay in the report. Filtered means this computer did not get a normal answer. It does not mean the port is safe, and it does not mean a firewall rule was identified.

`--script vuln` appears in exactly two profiles: open ports, and the open-ports phase of All. A hand-written `nmap_args` line in the config is validated and never sent. It still cannot contain `--script`, `--script-args`, `-sC`, `-A`, an output flag, a target-file flag, or a shell character. `discovery_args` must stay `-sn -T3`.

The named-service check does not ask for a DNS zone, offer a DHCP lease, or try an IKE login. Those would be active tests against services that hand out names, addresses, and VPN sessions. Looking to see if the port answers is enough.

UPnP is read-only. Discovery is one SSDP search for an Internet Gateway Device. A location URL is fetched only when the host is private, the body is capped, and the parser refuses a document type declaration. The only UPnP call after that is `GetGenericPortMappingEntry`. `AddPortMapping` and `DeletePortMapping` are not in the program. A forward that someone typed into the router by hand does not appear, because the tool never logs into the router.

The Wake-on-LAN action, if you turn it on, is one fixed remote command: `ethtool -s <interface> wol d`. The profile cannot supply its own command. Login is by key. There is no password field. The hook that ships with the project only writes a log line, and `block_magic_packets` is false until you change it.

## What a result means

Points describe what was seen, not a proof of compromise.

| Level | Rule |
| --- | --- |
| CRITICAL | 70 points or more, or a forward of port 21, 23, 445, 3389, 5900, 554, or 1883 |
| HIGH | 40 points or more, or any other forward |
| MEDIUM | 10 points or more |
| LOW | under 10 |

Telnet, FTP, and VNC score high on the LAN because the service itself is a bad default. SMB and Remote Desktop score less, because they are common on a home PC, and they become serious when a forward exists. HTTP and HTTPS on a router score enough to be visible and not enough to paint the house red.

Each scored host gets a sentence that names the rule and the findings that added the points. A vulnerability script is one of those findings. If the script text looks like a request line, a payload, or a command, the report keeps the script name and the port and tells you to read the vendor advisory. The raw line is dropped so the JSON cannot become a copy of an exploit.

A score of 0 is LOW because nothing in that scan added points. The scripts stay quiet when the probed ports are closed or filtered, and the scan only covered the ports you chose. The report says this is not proof the device is safe. A missing address is not proof that nothing is there. A missing CVE line is not a patch check. `cve_db/hints.json` knows a handful of versions and names the upgrade. It does not describe how to use the flaw.

## Data that must stay local

A report lists addresses, names, MAC addresses, and software versions. That is a map of the house. `reports/` is gitignored except for a placeholder file. `reports/devices.json` is the history of devices this program has already seen. It is in the same ignored folder.

The HTML report escapes text that came off the network and sends a Content-Security-Policy of `default-src 'none'`. A device name cannot become a script when you open the file. That is a safety net for a local file. It is not a reason to host the report on a website.

Public-IP lookup is off. Turning it on asks `https://api.ipify.org` for the address, and that service sees the request. The rest of the tool does not phone home.

## Ideas this project is practicing

These are the security ideas in the code, named so a reader can see them.

- **Authorization before action.** The menu, the warnings, and the private-network guard all happen before a probe. A refused target exits with code 2 and sends nothing. Declining a warning exits with code 0 and sends nothing.
- **Fail closed.** An unknown check, a bad port range, a public address, a missing Nmap binary, and an empty LAN all stop the run. The program does not guess a target and continue.
- **Allow-listing.** The Nmap arguments are an allow-list of whole profiles, not a block-list of bad flags with everything else permitted. The private ranges are an allow-list too.
- **Least privilege.** The tool can read. It cannot add a forward, change a firewall, guess a password, or run a command you type. The one remote command is fixed.
- **Separation of facts.** "Open on the LAN" and "forwarded to the internet" are scored separately. "Answered a ping" and "was seen before" are stored separately. A monitor miss is not treated as powered-off until it has happened three times, and a scan that sees nobody does not declare the whole house offline.
- **Output handling.** Script text that looks like an exploit is reduced to a name and a port. Report HTML is escaped. Reports are kept out of git.
- **No predetermined target.** The LAN is observed from the computer that is running the check. A published copy of the code does not contain a home address, a MAC, or a device name.

## What this is not

This is not a penetration test, a vulnerability-management product, or a statement that a host is safe. It does not see forwards that were typed into the router by hand. It does not see a device that ignores probes and is missing from the ARP table. On Windows, an elevated terminal sees more, because Nmap can use ARP. Run it from the LAN, not from a VPN adapter that is your only route, or the adapter filter may have nothing left to choose.

The honest result of a careful check is a short list of things a person should go and look at: an old admin page, a forward you did not mean to leave on, a service that should not be installed. The tool's job is to make that list without becoming an attack tool on the way.
