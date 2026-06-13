# Toralizer

A lightweight SOCKS4a client that proxies traffic through the Tor network.
Supports hostnames, onion addresses, and interactive bidirectional relay.

## Install Tor

```sh
sudo apt install tor && sudo systemctl start tor
```

## Compilation

```sh
gcc toralizer.c -o toralizer
# clang toralizer.c -o toralizer
```

## Usage

```sh
./toralizer <target hostname/onion> <target port>
```

**Examples:**

```sh
# Connect to a clearnet host
./toralizer check.torproject.org 80

# Connect to an onion service
./toralizer facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion 80
```

Once connected, you're in interactive relay mode — type to send data,
receive responses in real time (similar to netcat over Tor).

## What was fixed (from the original)

The original code had a bug in the SOCKS4 request structure: the `struct socks_request`
used a fixed `userid[8]` buffer, but the username "toralizer" is 9 characters long.
`strncpy` truncated it to 8 bytes **without a null terminator**, sending a malformed
packet that Tor couldn't parse — resulting in the `Status code: 0x00` error.

The upgraded version:
- Uses **SOCKS4a** (not SOCKS4) — Tor resolves hostnames server-side, preventing DNS leaks
- Dynamically builds the handshake packet with proper null termination
- Supports **onion addresses** and any hostname, not just IPs
- Adds **interactive relay mode** via `select()` for bidirectional communication
