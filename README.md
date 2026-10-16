# dflive

Companion for running suspect systems, part of the dfnix tool suite. It runs
from the field-kit stick, installs nothing and writes nothing to the suspect's
disks.

This repository holds:

- **`dflive`**: the companion, with `keys`, `mem`, `state` and `send`.
- **`dfstream`**: the dfstream/1 protocol, also used by `dfnet stream` on dfnix.

Planned: `status` (scene record), macOS `state`, and `dfkit`, which
writes and verifies the kit sticks on dfnix.

The checklists in dfnix (`docs/playbooks/live-*.md`) give the order at a scene:
keys first, then memory, then volatile state, then live volumes.

## `dflive keys`

Captures encryption state and key material while the volumes are unlocked:

- **Linux:** every LUKS header area is copied raw from the device (LUKS1 up to the
  payload offset, LUKS2 up to the first data segment), so it works as a detached
  header later. dflive also records the dm-crypt mappings with
  `dmsetup table --showkeys` (hex keys for LUKS1 and plain dm-crypt) and ZFS key
  status. It notes when LUKS2 keeps its keys in the kernel keyring: then memory
  and a live image of the unlocked device are the only way in.
- **Windows:** `manage-bde -status` and the protectors of every volume (recovery
  passwords).
- **macOS:** FileVault and APFS state (`fdesetup`, `diskutil apfs`).

```text
dflive keys -o /mnt/out/case/02-keys.json.age --recipient age1...   (the examiner's age public key)
```

The document is encrypted to the recipient before it is written, so the key
material never lies in plain text on the stick. `--plaintext` writes it
unencrypted when no examiner key is at hand.

## `dflive mem`

Dumps physical memory with the kit's tool, AVML on Linux and WinPmem on
Windows, and writes `FILE.json` next to the dump. The record holds the tool and
its SHA-256, the exact command, start and end (memory changes while it is read),
the exit code, and the dump's size and SHA-256. Apple silicon and current Intel
Macs have no reliable tool; dflive refuses there, as the checklist says.

```text
dflive mem -o /mnt/target/physmem.lime --compress
```

## `dflive state`

Records the volatile state with dflive's own code, not through the suspect's
possibly tampered `ps`, `netstat`, `who`, `tasklist` or `query user`:

- **Linux** (from `/proc`, sysfs, utmp and getifaddrs): processes with command
  lines, start times, owners and the SHA-256 of their executables (opened
  `O_NOATIME`); TCP and UDP sockets with their owning processes; interfaces and
  addresses, routes, the ARP cache and DNS configuration; mounts, swap, loaded
  modules and logged-in users.
- **Windows** (through the Windows API): processes with command lines, start
  times, owners (SID and account) and image SHA-256; TCP and UDP endpoints with
  their owning processes; adapters with addresses, gateways and DNS servers;
  routes and the neighbour cache; logon sessions (console and RDP, with client
  name and address); running services and drivers with their processes; loaded
  kernel images; OS version, time zone and boot time. The record also notes
  whether NTFS updates last-access times, because hashing reads every image.

```text
dflive state -o /mnt/out/case/04-state.json
dflive.exe state -o E:\case\04-state.json
```

## `dflive send`

Streams a disk, a volume, a file or stdin to dfnix over an authenticated,
encrypted connection:

```text
dfnix:    dfnet stream --bind 10.0.0.1 -o /media/target/case01/live -C "VG 12345/26" -E live01 -e "KHK Muster"
          [*] Pairing code: 482 913 0576

suspect:  dflive send /dev/nvme0n1 --to 10.0.0.1:9998 --code "482 913 0576"
          dflive send '\\.\PhysicalDrive0' --to 10.0.0.1:9998          (asks for the code)
```

- **Pairing.** dfnet shows a one-time 10-digit code and the examiner types it on
  the suspect system. Both sides run SPAKE2 on it, so no one on the network
  learns the code or can take part. A wrong code fails without revealing
  anything, and after three failed attempts dfnet shows a new code.
- **Encryption.** Every frame is ChaCha20-Poly1305 with keys derived from the
  pairing (HKDF-SHA256 over the handshake). A changed, replayed or reordered
  frame ends the session.
- **Hashes at both ends.** dflive hashes what it reads, and dfnet hashes what
  it stores. A stream counts only when the sender's end record arrived and byte
  counts and SHA-256 match. Each file is written as `*.incomplete` and renamed only
  then, so an interrupted stream never looks complete.
- **Read errors.** On a disk or volume, an unreadable sector is replaced by
  zeros and listed (offset, length), so every later byte keeps its offset; the
  receiver records the list and exits 7. `--stop-on-error` ends the stream at
  the first error instead.
- **Records.** dfnet writes a dfcore collection (manifest, items, footprint,
  audit anchors), which `dfcollect verify` checks. `--log FILE` makes dflive
  append its own record, for example to the kit's output partition.

Exit codes: 0 complete, 4 failed (no connection, wrong code), 5 hashes differ,
6 incomplete.

## Building

```bash
cargo build --release -p dflive
nix build                              # this system
nix build .#dflive-static              # Linux x86_64, static (for the kit)
nix build .#dflive-aarch64-static      # Linux aarch64, static
nix build .#dflive-windows             # dflive.exe, system DLLs only
```

Tests: `cargo test`; `nix build .#checks.x86_64-linux.live` (VM: LUKS1/LUKS2
keys, state, AVML), `.#checks.x86_64-linux.wine` (dflive.exe state and keys
under Wine); `nix-build tests/stream.nix` (two VMs with `dfnet stream`, needs
`../dfnet` and `../dfcore`).

## License

Dual-licensed under MIT and Apache-2.0.
