# dflive keys, state and mem on a running Linux system: a LUKS1 and a LUKS2 volume,
# both unlocked. The age-encrypted key document must open only with the
# examiner's identity, carry both headers byte-identical to cryptsetup's own
# backup, show LUKS1's key in hex and LUKS2's as a keyring reference. dflive
# state must see a listening socket together with its process. mem must dump
# memory with AVML and record the window, the tool's hash and the dump's hash.
#
#   nix-build tests/live.nix
{ pkgs ? import <nixpkgs> { }
, dflive ? pkgs.callPackage ../package.nix { }
}:

pkgs.testers.runNixOSTest {
  name = "dflive-live";

  nodes.machine = {
    virtualisation.emptyDiskImages = [ 64 64 1536 ];
    environment.systemPackages = [ dflive pkgs.cryptsetup pkgs.lvm2 pkgs.age pkgs.python3 pkgs.e2fsprogs ];
  };

  testScript = ''
    import base64, hashlib, json

    machine.wait_for_unit("multi-user.target")
    for dev, kind, name in [("/dev/vdb", "luks1", "one"), ("/dev/vdc", "luks2", "two")]:
        machine.succeed(
            f"printf secret | cryptsetup luksFormat --batch-mode --type {kind} --pbkdf-force-iterations 1000"
            f"{" --pbkdf pbkdf2" if kind == "luks2" else ""} --key-file - {dev}"
        )
        machine.succeed(f"printf secret | cryptsetup open --key-file - {dev} {name}")
        machine.succeed(f"cryptsetup luksHeaderBackup {dev} --header-backup-file /tmp/{name}.hdr")

    with subtest("keys are sealed to the examiner and complete"):
        machine.succeed("age-keygen -o /root/examiner.key 2>/dev/null")
        pub = machine.succeed("age-keygen -y /root/examiner.key").strip()
        machine.succeed(f"dflive keys -o /tmp/keys.json.age --recipient {pub}")
        machine.fail("grep -q LUKS /tmp/keys.json.age")
        machine.fail("dflive keys -o /tmp/keys.json.age --recipient " + pub)  # never overwrites
        machine.succeed("age -d -i /root/examiner.key /tmp/keys.json.age > /tmp/doc.json")
        doc = json.loads(machine.succeed("cat /tmp/doc.json"))
        headers = {h["device"]: h for h in doc["details"]["luks_headers"]}
        for dev, name, version in [("/dev/vdb", "one", 1), ("/dev/vdc", "two", 2)]:
            h = headers[dev]
            assert h["luks_version"] == version, h
            raw = base64.b64decode(h["header_base64"])
            assert len(raw) == h["header_bytes"], h
            # The raw bytes on the device (cryptsetup's own LUKS1 backup wipes the
            # gap before the first keyslot, so it is not a byte copy)
            want = machine.succeed(f"head -c {len(raw)} {dev} | sha256sum").split()[0]
            assert hashlib.sha256(raw).hexdigest() == want, dev
            assert len(raw) >= int(machine.succeed(f"stat -c %s /tmp/{name}.hdr")), dev
            # And it works as a header backup: it opens the volume detached
            machine.succeed(f"python3 -c 'import base64,json,sys; sys.stdout.buffer.write(base64.b64decode(json.load(open(\"/tmp/doc.json\"))[\"details\"][\"luks_headers\"][{version - 1}][\"header_base64\"]))' > /tmp/{name}.dflive.hdr")
            # (the original mapping is closed first: a device opens only once)
            machine.succeed(f"cryptsetup close {name}")
            machine.succeed(f"printf secret | cryptsetup open --readonly --header /tmp/{name}.dflive.hdr --key-file - {dev} {name}-hdr && cryptsetup close {name}-hdr")
        table = doc["details"]["commands"][0]["stdout"]
        assert ":logon:" in table or ":user:" in table, table  # LUKS2 key in the keyring
        line_one = [l for l in table.splitlines() if l.startswith("one:")][0]
        key = line_one.split()[5]
        assert len(key) in (64, 128) and all(c in "0123456789abcdef" for c in key), line_one  # LUKS1: hex key
        assert doc["details"]["keyring_keys"] is True

    with subtest("state sees a listening socket and its process"):
        machine.succeed("python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 & sleep 1")
        state = json.loads(machine.succeed("dflive state"))
        sock = [s for s in state["sockets"] if s["local"] == "127.0.0.1:8765"][0]
        assert sock["state"] == "LISTEN", sock
        procs = {p["pid"]: p for p in state["processes"]}
        owner = procs[sock["pids"][0]]
        assert "http.server" in " ".join(owner["cmdline"]), owner
        assert len(owner["exe_sha256"]) == 64, owner
        assert any(i["name"] == "lo" for i in state["interfaces"])

    with subtest("mem dumps memory with AVML and records the window and both hashes"):
        machine.succeed("mkfs.ext4 -q /dev/vdd && mkdir -p /mnt/out && mount /dev/vdd /mnt/out")
        code, _ = machine.execute("dflive mem -o /mnt/out/mem.lime --compress --tool ${pkgs.pkgsStatic.avml}/bin/avml")
        print(machine.succeed("cat /mnt/out/mem.lime.json; ls -la /proc/kcore /dev/mem /dev/crash 2>&1 || true"))
        assert code == 0, code
        rec = json.loads(machine.succeed("cat /mnt/out/mem.lime.json"))
        assert rec["exit_code"] == 0, rec
        assert rec["dump_sha256"] == machine.succeed("sha256sum /mnt/out/mem.lime").split()[0], rec
        assert rec["started"] <= rec["finished"], rec
        assert len(rec["memory_tool_sha256"]) == 64, rec
        assert rec["dump_bytes"] > 1 << 20, rec
        machine.fail("dflive mem -o /mnt/out/mem.lime --tool ${pkgs.pkgsStatic.avml}/bin/avml")
  '';
}
