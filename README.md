# ReconX

A fast, multithreaded TCP port scanner written in Python — built as a portfolio project to explore network scanning fundamentals: raw sockets, concurrency, service fingerprinting, and CLI tool design.

Inspired by tools like `nmap` and `rustscan`, but built from scratch to understand the underlying mechanics rather than as a replacement for them.

## Features

- Multithreaded TCP connect scanning (fast, configurable thread count)
- Custom port ranges: single ports, ranges, or comma-separated lists (`22,80,1000-2000`)
- Common service name mapping (22 → SSH, 80 → HTTP, etc.)
- Optional banner grabbing (`-b`) to read service responses from open ports
- Live scan progress indicator
- Export results to JSON or CSV (`-o results.json`)
- Colored terminal output
- Installs as a global command (`reconx <target>`), just like `nmap`

## Installation

```bash
git clone https://github.com/<your-username>/reconx.git
cd reconx
chmod +x install.sh
./install.sh
```

This copies the script to `/usr/local/bin/reconx`, so it's available system-wide.

## Usage

```bash
reconx <target> -p <ports> [options]
```

### Examples

```bash
# Scan the top 1000 ports (default)
reconx 192.168.1.1

# Scan specific ports
reconx example.com -p 22,80,443

# Scan a full range with more threads and banner grabbing
reconx 10.0.0.5 -p 1-65535 -t 200 -b

# Save results to a file
reconx 192.168.1.1 -p 1-1000 -o results.json
```

### Options

| Flag | Description |
|------|-------------|
| `-p, --ports` | Ports to scan (default: `1-1000`) |
| `-t, --threads` | Number of concurrent threads (default: `100`) |
| `--timeout` | Per-port connection timeout in seconds (default: `0.5`) |
| `-b, --banner` | Attempt to grab service banners from open ports |
| `-o, --output` | Save results to `.json` or `.csv` |
| `--no-banner-art` | Suppress the startup ASCII banner |

## How it works

ReconX uses Python's `socket` module to attempt a TCP connection (`connect()`) to each target port. A successful connection means the port is open. Work is distributed across a thread pool via a `Queue`, so hundreds of ports can be checked concurrently instead of one at a time — this is what makes it fast on large port ranges.

When banner grabbing is enabled, ReconX reads a short response from the open socket, which can reveal service names/versions (useful for basic fingerprinting).

## Legal / Ethical Use

Only scan systems you own or have explicit permission to test. Unauthorized scanning of networks you don't control may be illegal depending on your jurisdiction.

## Author

Frostcy — B.E. Computer Science, focused on penetration testing / offensive security.
