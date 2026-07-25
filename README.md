# Site Sentinel Node Agent

Telemetry agent for Site Sentinel probe nodes — Raspberry Pi devices (typically
with a cellular modem) that report their vitals to the Site Sentinel fleet:
public IP, CPU temperature, uptime, modem signal strength (RSSI/RSRP/RSRQ/SINR)
and carrier information (operator, MCC/MNC, access technology).

A single-file Python 3 agent with **no dependencies beyond the standard
library**, run as a systemd service.

## Requirements

- Raspberry Pi (any model) running Raspberry Pi OS, or any Linux with systemd
- Python 3.9+ (preinstalled on Raspberry Pi OS)
- For cellular stats: a modem managed by [ModemManager](https://modemmanager.org/)
  (`mmcli` available). Without a modem the agent still runs and reports
  everything else.

## Install

```sh
git clone <this-repo> && cd <this-repo>
sudo ./install.sh
```

The installer copies the agent to `/opt/sitesentinel/`, installs and starts the
`sitesentinel-agent` systemd service, and prints the node's **registration
hash**.

## Registering a node

Onboarding works like RIPE Atlas software probes — the device proves its
identity with a key it generated itself:

1. On first start the agent generates a random 256-bit key, stores it in
   `/etc/sitesentinel/credentials.json` (mode 0600), and logs its fingerprint:

   ```
   journalctl -u sitesentinel-agent | grep "Registration hash"
   ```

2. An operator adds that hash in the Site Sentinel backoffice
   (Nodes → Add node). **Read the hash from the device yourself** (SSH or
   console) — never accept one sent to you over chat or email.

3. The agent polls the registration endpoint once a minute; as soon as the
   hash is added, the node activates itself and starts sending heartbeats.

A device whose hash was never added can poll forever and never join the fleet.

## Security model

- The key never leaves the device except once, over TLS, during registration.
  What the operator handles (the hash) is the key's SHA-256 — non-secret.
- Every heartbeat is authenticated with HMAC-SHA256 over
  `"<unix-ts>.<body>"` using the node key; the server rejects timestamps more
  than 5 minutes off and replies with its own clock so devices without an RTC
  self-correct after a cold boot.
- Revoking a node server-side discards its key and hash; the device cannot
  rejoin without an operator adding its (new) hash again.
- Keys are generated with `secrets.token_hex(32)` (OS CSPRNG) and are not
  derived from any device identifier.

## What gets reported

Every 60 seconds (server-tunable):

| Field | Source |
|---|---|
| Public IP + country | observed server-side from the connection |
| Local IP | UDP-connect route lookup |
| CPU temperature | `/sys/class/thermal/thermal_zone0/temp` (fallback `vcgencmd`) |
| Uptime | `/proc/uptime` |
| Hardware model | `/proc/device-tree/model` |
| Signal (RSSI/RSRP/RSRQ/SINR) | `mmcli --signal-get` |
| Carrier (name, MCC/MNC, access tech) | `mmcli` 3GPP status |

The modem path is rediscovered on every cycle (`mmcli -L`), so modem resets
that renumber the device don't break reporting. Any missing source degrades to
`null` — the agent never crashes on absent hardware.

## Operations

```sh
journalctl -u sitesentinel-agent -f       # live logs
sudo systemctl restart sitesentinel-agent # restart
sudo systemctl disable --now sitesentinel-agent  # stop + disable
```

Config lives in `/etc/sitesentinel/agent.env` (`SENTINEL_URL` — the fleet
endpoint). To re-key a device (e.g. after cloning an SD card), delete
`/etc/sitesentinel/credentials.json`, restart the service, and register the
newly logged hash.

## Probe commands

Operators can queue measurement commands for a node (RIPE-Atlas style) from
the Site Sentinel backoffice. Each command targets a **list of domains** and
runs one action per domain:

- `dns` — resolve the domain, report the IP set and lookup time
- `http` — HTTPS GET, report status code, final URL and latency
- `ping` — 3 ICMP probes, report average RTT and packet loss

Commands execute **strictly in queue order, one at a time**: after every
heartbeat the agent fetches the next command, runs it, uploads the per-domain
results, and repeats until its queue is empty. If the agent restarts
mid-command, the server re-serves the unfinished command. All command traffic
uses the same HMAC authentication as heartbeats.

## Automatic updates

The agent is versioned (`AGENT_VERSION`) and updates itself over the air. When
the fleet's target release (registered by an operator in the Site Sentinel
backoffice) differs from a node's running version, the next heartbeat response
carries the new artifact's URL and SHA-256. The agent then:

1. downloads the artifact (https only),
2. verifies its SHA-256 against the operator-registered digest,
3. byte-compiles it as a sanity check,
4. atomically replaces itself and exits — systemd restarts it on the new
   version.

A failed attempt for a given version is retried at most every 30 minutes.
Releases are cut by tagging this repository (e.g. `v0.3.0`) and registering
the tag's raw file URL in the backoffice, which pins the hash at registration
time — changing the file behind a URL later cannot reach the fleet.

## Development

```sh
python3 -m unittest test_agent -v
```

The parsing and signing logic is kept in pure functions tested against captured
`mmcli -J` fixtures; the tests run on any OS, no Pi or modem required.

## Note

This repository contains the device-side agent only. The Site Sentinel
backend (registration service, fleet dashboard) is not part of this repo.
