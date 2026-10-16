# dflive send -> dfnet stream between two machines: a disk with a run of
# unreadable sectors (device-mapper error target) arrives complete with the
# area zero-filled and listed; a wrong pairing code is refused and the right
# one still works; a sender killed mid-stream leaves an incomplete stream.
#
#   nix-build tests/stream.nix        (dfnet from ../dfnet, dfcore from ../dfcore)
{ pkgs ? import <nixpkgs> { }
, dflive ? pkgs.callPackage ../package.nix { }
, dfnet ? pkgs.callPackage ../../dfnet/package.nix { dfliveSrc = ../.; }
}:

pkgs.testers.runNixOSTest {
  name = "dflive-stream";

  nodes.receiver = {
    networking.firewall.enable = false;
    virtualisation.emptyDiskImages = [ 256 ];
    environment.systemPackages = [ dfnet pkgs.e2fsprogs ];
  };

  nodes.sender = {
    networking.firewall.enable = false;
    virtualisation.emptyDiskImages = [ 64 ];
    environment.systemPackages = [ dflive pkgs.lvm2 pkgs.python3 ];
  };

  testScript = ''
    import json

    def listen(out):
        receiver.succeed(
            f"systemd-run --unit=dfnet-{out} --remain-after-exit sh -c '"
            f"${dfnet}/bin/dfnet stream --bind {ip} --port 9998 -o /target/{out} -C CASE -E {out} -e tester"
            f" > /tmp/{out}.log 2>&1; echo exit=$? >> /tmp/{out}.log'"
        )
        receiver.wait_until_succeeds(f"grep -q 'Pairing code' /tmp/{out}.log")
        return receiver.succeed(
            f"grep -o 'Pairing code: [0-9 ]*' /tmp/{out}.log | sed 's/Pairing code: //'"
        ).strip()

    def finished(out):
        try:
            receiver.wait_until_succeeds(f"grep -q exit= /tmp/{out}.log", timeout=180)
        finally:
            print(receiver.execute(f"cat /tmp/{out}.log; systemctl status dfnet-{out} --no-pager; ps aux | grep [d]fnet")[1])
        return receiver.succeed(f"cat /tmp/{out}.log")

    def items(out):
        return [json.loads(l) for l in receiver.succeed(f"cat /target/{out}/items.jsonl").splitlines()]

    start_all()
    receiver.wait_for_unit("multi-user.target")
    sender.wait_for_unit("multi-user.target")
    receiver.succeed("mkfs.ext4 -q /dev/vdb && mkdir /target && mount /dev/vdb /target")
    ip = receiver.succeed("ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1").strip()
    to = f"{ip}:9998"

    # 64 MiB of a pattern; sectors 20480..20607 (64 KiB at 10 MiB) unreadable
    sender.succeed(
        "python3 -c \"import sys; b=bytes(range(256))*4096; [sys.stdout.buffer.write(b) for _ in range(64)]\" > /dev/vdb && sync"
    )
    size = int(sender.succeed("blockdev --getsz /dev/vdb").strip())
    sender.succeed(
        "dmsetup create flaky --table '"
        f"0 20480 linear /dev/vdb 0\n20480 128 error\n20608 {size - 20608} linear /dev/vdb 20608'"
    )
    want = sender.succeed(
        "python3 -c \"import hashlib; d=bytearray(open('/dev/vdb','rb').read()); d[20480*512:20608*512]=bytes(128*512);"
        " print(hashlib.sha256(d).hexdigest())\""
    ).strip()

    with subtest("a wrong code is refused, the right one streams the disk with the bad area zero-filled"):
        code = listen("disk")
        sender.fail(f"dflive send /dev/mapper/flaky --to {to} --code 0000000000")
        sender.succeed(f"dflive send /dev/mapper/flaky --to {to} --code '{code}' --log /tmp/dflive.jsonl")
        log = finished("disk")
        assert "exit=7" in log, log
        [item] = items("disk")
        assert item["status"] == "acquired", item
        assert item["hashes"]["sha256"] == want, (item, want)
        assert item["source_hash"]["matches"], item
        assert item["metadata"]["end"]["read_errors"] == [{"offset": 20480 * 512, "length": 128 * 512}], item
        footprint = receiver.succeed("cat /target/disk/footprint.jsonl")
        assert '"paired":false' in footprint and '"paired":true' in footprint, footprint
        log = json.loads(sender.succeed("cat /tmp/dflive.jsonl"))
        assert log["outcome"]["status"] == "complete", log

    with subtest("a sender stopped mid-stream leaves an incomplete stream"):
        code = listen("cut")
        sender.succeed("head -c 400000000 /dev/zero > /tmp/big")
        sender.succeed(f"(dflive send /tmp/big --to {to} --code '{code}' > /tmp/cut.out 2>&1 &) ; sleep 1; pkill -9 dflive")
        log = finished("cut")
        assert "exit=6" in log, log
        [item] = items("cut")
        assert item["status"] == "error", item
        assert item["stored_as"].endswith(".incomplete"), item
        receiver.fail("ls /target/cut/*.raw")
  '';
}
