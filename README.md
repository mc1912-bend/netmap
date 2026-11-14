# netmap

Map the network once, remember it forever, and see which attacks actually fit.

```
sudo netmap
```

Scan → save → dashboard. That is the whole interface.

## What it collects

| layer | fields |
|---|---|
| **access points** | SSID, BSSID, channel, signal, security (open / WPA2 / WPA3 / 802.1X) |
| **hosts** | IP, MAC, vendor, hostname, OS guess, role |
| **ports** | open TCP, service name, product and version where nmap knows |
| **SMB** | domain, OS, **signing required or not**, shares and anonymous access |
| **web** | status, page title, server header, TLS certificate CN |
| **link** | interface, IP, gateway, current SSID and security |

Everything is merged into `~/.netmap/state.json` (0600). A device seen once is
remembered forever, so a second scan only fills in what changed.

## The dashboard

```
┌ netmap ── SD43-S  192.168.50.0/24  14 hosts ──────────────────────────┐
│ NETWORKS                       HOSTS                                  │
│ SD43-S     14 hosts            192.168.50.1   router     80,443      │
│ SD43       34 hosts            192.168.50.10  DC01       88,389,445  │
│ Guest       6 hosts            192.168.50.20  NAS01      445,139     │
│                                192.168.50.44  PC07       445,3389    │
│                                ATTACKS - ranked by fit                │
│                                ██████████ 95%  Evil twin + portal     │
│                                █████████· 90%  Enumerate users, roast │
│                                ████████·· 88%  NTLM relay (rbcd)      │
└ q quit  s scan  e export   ↑↓ select   ←→ panes ────────────────────┘
```

Move to **ATTACKS** and the bottom two lines show *why* each one applies and the
exact command to run it.

| key | does |
|---|---|
| `↑` `↓` | move in the selected pane |
| `←` `→` | switch between hosts and attacks |
| `n` `p` | next / previous network |
| `s` | rescan (leaves curses, comes back) |
| `e` | export every known network to a text report |
| `q` | quit |

## Reading the attacks list

Three columns, and each of them means something specific:

- **fit%** - how well what the scan found matches what the attack needs. 95% is
  "the evidence is exactly right". 45% is "possible, but this attack is a
  stretch on this network".
- **noise** - how noticeable it is: `quiet`, `moderate`, `loud`.
- **loot** - what you actually walk away with.

The dashboard shows `why`, `loot` and `run` for whichever attack is selected, so
nothing is a mystery number. `netmap show` also prints a **not applicable**
section, which explains the attacks that did not fire and what was missing.

| finding | suggestion | noise | loot |
|---|---|---|---|
| open network | `twinstart` - evil twin + portal | moderate | portal logins, fingerprints |
| shares readable anonymously | `sharestart` | quiet | documents, and passwords inside them |
| domain controller reachable | user enum + AS-REP/Kerberoast | quiet | usernames, crackable hashes |
| DC + machines authenticating | `dcraidstart --profile stealth` | moderate | local admin, then cached creds |
| SMB signing not required | relay | moderate | admin on hosts that accept it |
| WEP | aircrack | quiet | the Wi-Fi key, in minutes |
| WPA2-Enterprise | rogue RADIUS (eaphammer) | moderate | a domain username + password |
| WPA2-PSK | handshake capture | quiet | the Wi-Fi passphrase |
| WPA3 only | transition-mode check | quiet | still a WPA2 handshake if mixed |
| admin panels found | `panelstart` | loud | routers, cameras, NAS logins |
| SNMP 161 | snmpwalk | quiet | device config, plain-text passwords |
| printer ports | PJL file access | quiet | stored documents, address books |
| RTSP 554 | camera stream | moderate | live video, camera admin login |
| RDP 3389 | direct desktop | loud | a desktop with any valid account |

The Wi-Fi rules only fire when the scan can actually tell what the network is.
If the security type is unknown, nothing is claimed - a WPA2 network is never
reported as open.

## Commands

```sh
sudo netmap              # scan, save, dashboard
sudo netmap scan         # scan only, prints the top matches
sudo netmap scan --deep  # all ports, plus SMB share enumeration
sudo netmap dash         # dashboard only, generates no traffic
netmap show              # plain text dump of everything
netmap show SD43-S       # just one network
netmap export            # report for every network you have mapped
```

## Install

```sh
sudo bash ./install.sh
```

Needs `python3` and standard curses. `nmap` and `arp-scan` make it faster and
more accurate; without them it falls back to a slow Python socket scan.

## Notes

- Scans are ordinary network traffic — ICMP, TCP connect, SMB queries, HTTP
  GETs. Nothing is written to any device.
- `~/.netmap/` is 0700 and the state file 0600, because host inventories are
  not something to leave lying around.
- The dashboard never touches the network. It only reads the state file, so you
  can look at yesterday's map on a network you are no longer on.
