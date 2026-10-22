# Important things to think about

This file is the caution list for Home Network Assessor. The how-to sits in [README.md](README.md). The longer security reasoning sits in [GUIDE.md](GUIDE.md).

## Whose network

Scan a network you own, or one where you have explicit permission. The tool refuses public addresses, hostnames, and carrier-grade NAT (`100.64.0.0/10`). That check is not a setting. It does not make scanning a school, work, or shared building network acceptable. Those LANs are often private addresses too, and they are still not yours.

The program does not use a network address from the code or from `config.yaml`. It takes the private LAN this computer is already on. VPN, virtual, and link-local adapters are ignored, so a tunnel that owns the default route is not the LAN it scans. A whole `/24` with version detection talks to every address Nmap marks as up. To limit that, set `networks` to one private address.

## What the tool sends

`python main.py` shows a menu and waits. It does not probe until you pick a check, and, for a port check, a range. Top 10, top 100, the address check, the router check, and the named service check start after that choice. Two other choices stop and ask first.

A top-1000 scan or a full TCP scan (ports 1-65535) of one computer can take a long time. A full scan of a whole `/24` can take hours. The first full scan should be a single address in `config.yaml`. Answer no and the program exits without sending probes. Full means TCP only. It does not add a UDP sweep.

Open ports, and All, add Nmap's built-in vulnerability scripts. Those probes can upset a printer, camera, TV, or old router. The first run should be one address in `config.yaml`. Answer no and nothing is sent. The other checks do not run those scripts. The monitor never asks this question and never uses those profiles.

The monitor's discovery scan is a ping scan (`-sn -T3`). It repeats. The default gap is five minutes. Do not turn that gap down to "as fast as possible". The smallest accepted value is 30 seconds. It does not read the port range.

UPnP discovery is a multicast on the LAN. It asks gateways to answer. The router check, and the router phase of All, then read the forward list. They do not add or delete forwards. The other checks skip UPnP.

The named service check version-scans DNS, QUIC, DHCP, NTP, and IPsec. It does not request a DNS zone transfer, send a DHCP lease offer, or test an IKE login. The tool does not guess passwords, inject packets, or change a firewall. The magic-packet hook stays log-only and off unless you turn it on.

`lookup_public_ip: false` is the default. Set it true only if you accept that this computer will ask `https://api.ipify.org` for the public address. That service sees the request. The rest of the tool does not phone home.

## What a score is not

A LOW host is not a safe host. The report says so in the sentence under the level. A quiet host is not proof that it is safe. A closed or filtered port is not proof either. Filtered means this computer did not get a normal answer. A missing CVE line is not a patch check. `cve_db/hints.json` knows a handful of versions. SMB and Remote Desktop on a home PC are scored as ordinary LAN services, and they become serious when a forward exists. If the router did not answer UPnP, the report cannot see forwards that were typed in by hand. The firewall and service checks do not read UPnP at all.

`critical_ports` only chooses which open ports get a note. Changing that list does not change which ports Nmap is asked to scan.

Nmap only lists what answered. A computer that ignores ping and is not in the ARP table is absent. On Windows, an elevated terminal sees more, because Nmap can use ARP. Run it from the LAN, not from a VPN adapter that is your default route, or you will inventory the wrong place.

## The report

`reports/` contains addresses, names, MAC addresses, and software versions. Do not commit it, paste it into a ticket, or put it on a website. `reports/latest.html` is overwritten each run. `reports/devices.json` is the history of devices seen on the LAN this computer is on. The timestamped files are the older reports.

Open the HTML locally. It escapes text that came off the network so a device name cannot run as a script. That is a safety net for the file, not a reason to host the report on a server.

## The monitor

Three misses are required before a device is called offline. A laptop that sleeps, a phone that drops Wi-Fi, or a TV that looks idle will still get there. That is a presence note, not proof the device failed.

A scan that sees zero hosts does not move the miss counters. If your computer leaves the LAN, the tool will not announce that the whole house turned off. The other side of that choice: a real outage that hides every device, including the router, will not raise the offline alarm either.

Identity is the MAC address when one was seen. DHCP can change the IP without creating a second device. If the first scans had no MAC, the history is weaker until a later scan fills it in.

## Wake-on-LAN and the hook

`block_magic_packets` is false. Leave it false until you have edited `hooks/block_magic_packet.ps1` or `hooks/block_magic_packet.sh` for equipment you administer. The copies in this project only log a line. A firewall rule that matches the wrong thing can disconnect a device, and it can disconnect you.

The SSH action runs only this remote command:

```text
ethtool -s <interface> wol d
```

It uses the key file you name. It does not ask for a password, and it will not run a command you type into the profile. The first success stores the server's host key (`StrictHostKeyChecking=accept-new`). Be on your own LAN when that happens. If the attempt fails, it is not retried until the device goes offline and comes back, or until you restart the monitor after fixing the profile.

`ethtool` is a Linux command. A Windows PC in the profile will not honor it. The hook is the piece that can still apply once that PC is shut down, and only after you teach the hook about your router.

## Installing and running

Nmap must be installed and visible as `nmap` in the terminal. `pip install` does not do that part.

If the scan returns no hosts, check the range in `config.yaml`, check that you are joined to that LAN, and try an elevated terminal. A refused target is the guard working. Do not look for a way to disable it inside the config. The tool is for the private side of a home network.
