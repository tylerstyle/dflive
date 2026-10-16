# dflive status, keys, state and mem on a running Linux system: a LUKS1 and a LUKS2 volume,
# both unlocked. The age-encrypted key document must open only with the
# examiner's identity, carry both headers byte-identical to cryptsetup's own
# backup, show LUKS1's key in hex and LUKS2's as a keyring reference. dflive
# state must see a listening socket together with its process. mem must dump
# memory with AVML and record the window, the tool's hash and the dump's hash.
# status must measure the clock against a reference, see both LUKS devices, a
# sync client and its folder; the footprint log (--log) must record every run,
# its children and files, and whether dflive matches the kit's manifest.
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
        machine.succeed("dflive mem -o /mnt/out/mem.lime --compress --tool ${pkgs.pkgsStatic.avml}/bin/avml --log /mnt/out/fp.jsonl")
        fp = json.loads(machine.succeed("tail -n 1 /mnt/out/fp.jsonl"))
        assert fp["action"] == "mem" and fp["exit_code"] == 0, fp
        assert fp["children"][0]["command"].endswith("acquire --compress /mnt/out/mem.lime"), fp["children"]
        assert fp["children"][0]["exit"] == 0, fp["children"]
        assert [w["path"] for w in fp["written"]] == ["/mnt/out/mem.lime", "/mnt/out/mem.lime.json"], fp["written"]
        rec = json.loads(machine.succeed("cat /mnt/out/mem.lime.json"))
        assert rec["exit_code"] == 0, rec
        assert rec["dump_sha256"] == machine.succeed("sha256sum /mnt/out/mem.lime").split()[0], rec
        assert rec["started"] <= rec["finished"], rec
        assert len(rec["memory_tool_sha256"]) == 64, rec
        assert rec["dump_bytes"] > 1 << 20, rec
        machine.fail("dflive mem -o /mnt/out/mem.lime --tool ${pkgs.pkgsStatic.avml}/bin/avml")

    with subtest("status measures the clock, sees LUKS, a sync client and its folder"):
        # (the keys subtest closed both mappings for its detached-header check)
        machine.succeed("printf secret | cryptsetup open --key-file - /dev/vdb one && printf secret | cryptsetup open --key-file - /dev/vdc two")
        # A process named like a sync client (a script's process takes the script's name)
        machine.succeed("printf '#!/bin/sh\\n${pkgs.coreutils}/bin/sleep 600\\n' > /tmp/dropbox && chmod +x /tmp/dropbox")
        machine.succeed("systemd-run --unit=fake-dropbox /tmp/dropbox && mkdir -p /root/Dropbox")
        machine.wait_until_succeeds("grep -l '^dropbox$' /proc/[0-9]*/comm")
        ref = machine.succeed("date -u -d '-60 seconds' +%Y-%m-%dT%H:%M:%SZ").strip()
        machine.succeed(f"dflive status --reference-time {ref} -o /tmp/status.json --log /tmp/fp.jsonl")
        st = json.loads(machine.succeed("cat /tmp/status.json"))
        assert 59 <= st["clock"]["offset_seconds"] <= 70, st["clock"]
        assert sorted(st["encryption"]["luks_devices"]) == ["vdb", "vdc"], st["encryption"]
        assert sorted(st["encryption"]["open_dm_crypt"]) == ["one", "two"], st["encryption"]
        assert st["system"]["elevated"] is True, st["system"]
        assert any(c["client"] == "Dropbox" for c in st["sync_clients"]), st["sync_clients"]
        assert {"profile": "/root", "path": "/root/Dropbox"} in st["sync_folders"], st["sync_folders"]
        vdb = [d for d in st["disks"] if d["name"] == "vdb"][0]
        assert vdb["luks_header"] and vdb["holders"], vdb
        machine.fail("dflive status --reference-time yesterday")

    with subtest("the footprint log checks dflive against the kit manifest"):
        machine.succeed(
            "mkdir -p /tmp/kit/dflive/x86_64 && cp $(readlink -f $(command -v dflive)) /tmp/kit/dflive/x86_64/dflive"
            " && cd /tmp/kit && sha256sum dflive/x86_64/dflive > KIT-MANIFEST.sha256"
            " && printf 'dfnix Field-Kit Stick v0 (9.9.9) - test\\n' > SOURCES.txt"
        )
        machine.succeed("/tmp/kit/dflive/x86_64/dflive state -o /tmp/state2.json --no-hash --log /tmp/fp.jsonl")
        fp = json.loads(machine.succeed("tail -n 1 /tmp/fp.jsonl"))
        kit = fp["self"]["kit"]
        assert kit["root"] == "/tmp/kit" and kit["version"] == "9.9.9", kit
        assert kit["dflive_path"] == "dflive/x86_64/dflive" and kit["dflive_matches_kit"] is True, kit
        assert fp["written"][0]["path"] == "/tmp/state2.json", fp
        machine.succeed("cd /tmp/kit && sed -i 's/^./0/' KIT-MANIFEST.sha256")
        machine.succeed("/tmp/kit/dflive/x86_64/dflive state -o /tmp/state3.json --no-hash --log /tmp/fp.jsonl")
        fp = json.loads(machine.succeed("tail -n 1 /tmp/fp.jsonl"))
        assert fp["self"]["kit"]["dflive_matches_kit"] is False, fp["self"]
        actions = [json.loads(l)["action"] for l in machine.succeed("cat /tmp/fp.jsonl").splitlines()]
        assert actions == ["status", "state", "state"], actions
  '';
}
