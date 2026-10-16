# VM test for `dfkit write` and `dfkit verify`:
#   1. Refuses write-blocked (`blockdev --getro == 1`), system, partition, and unconfirmed disks.
#   2. Unblocks the target disk (`blockdev --setrw`), writes the field-kit image to a disk
#      larger than the image, verifies `KIT-OUT` (partition 4) grew to fill the disk,
#      verifies `KIT-ID.json` was written on `KIT-OUT`, and checks `fieldkit_write` in the
#      hash-chained dfcore audit log.
#   3. Runs `dfkit verify`: passes (exit 0) when all tool files on partitions 1–3 are intact.
#   4. Adds an allowlisted OS-noise file (`System Volume Information/WPSettings.dat`) on
#      `KIT-WIN` -> `dfkit verify` reports `[OS-ADDED]` and still exits 0.
#   5. Plants an unexpected file (`version.dll`) on `KIT-WIN` -> `dfkit verify` reports
#      `[UNEXPECTED] KIT-WIN: version.dll` and exits with code 5; removing `version.dll`
#      restores exit 0.
#   6. Modifies a tool file on `KIT-LNX` (mount rw, `chattr -i`, append) -> `dfkit verify`
#      reports `[CHANGED] KIT-LNX: live-linux.md` alongside `[OS-ADDED] KIT-WIN: System Volume Information/WPSettings.dat`,
#      exits with code 5, and records `fieldkit_verify` in the audit log.
#
#   nix-build tests/dfkit.nix
{ pkgs ? import <nixpkgs> { }
, dfkit ? pkgs.callPackage ../dfkit/package.nix { }
, fieldkit ? null
}:

let
  # When `fieldkit` is not passed in, build a compact 4-partition field-kit fixture
  # (NTFS + HFS+ + ext4 + exFAT, GPT bit 60 on 1..3, immutable/readonly file attributes,
  # and `dfnix.fieldkit.manifest/v0`) in a VM so `nix-build tests/dfkit.nix` runs standalone.
  fixtureFieldkit =
    if fieldkit != null then
      fieldkit
    else
      pkgs.vmTools.runInLinuxVM (
        pkgs.runCommand "dfkit-test-fieldkit-0.1.0"
          {
            memSize = 768;
            QEMU_OPTS = "-drive file=fieldkit.img,format=raw,if=virtio,cache=unsafe,werror=report";
            nativeBuildInputs = with pkgs; [
              gptfdisk
              util-linux
              ntfs3g
              hfsprogs
              e2fsprogs
              exfatprogs
              attr
              python3
            ];
            preVM = ''
              truncate -s 64M fieldkit.img
            '';
            postVM = ''
              mkdir -p "$out"
              mv fieldkit.img "$out/fieldkit.img"
              img_sha=$(sha256sum "$out/fieldkit.img" | awk '{print $1}')
              img_size=$(stat -c '%s' "$out/fieldkit.img")
              ${pkgs.python3}/bin/python3 - "$out/manifest.json" "$img_size" "$img_sha" <<'PY'
              import hashlib, json, sys
              out_path, img_size, img_sha = sys.argv[1:4]
              def h(b): return hashlib.sha256(b).hexdigest()
              win_b = b"windows-checklist\r\n"
              mac_b = b"macos-checklist\n"
              lnx_b = b"linux-checklist\n"
              uac_b = b"#!/bin/sh\necho UAC\n"
              manifest = {
                "schema": "dfnix.fieldkit.manifest/v0",
                "version": "0.1.0",
                "gpt_disk_guid": "44464E49-5800-4B49-5400-000000000000",
                "image": {
                  "file": "fieldkit.img",
                  "size": int(img_size),
                  "sha256": img_sha,
                },
                "partitions": [
                  {
                    "number": 1,
                    "label": "KIT-WIN",
                    "filesystem": "ntfs",
                    "gpt_type_code": "0700",
                    "gpt_type_guid": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
                    "gpt_partition_guid": "44464E49-5800-4B49-5400-000000000001",
                    "gpt_readonly_bit60": True,
                    "file_count": 1,
                    "symlink_count": 0,
                    "files": [
                      {"path": "live-windows.txt", "size": len(win_b), "sha256": h(win_b)}
                    ],
                    "symlinks": [],
                  },
                  {
                    "number": 2,
                    "label": "KIT-MAC",
                    "filesystem": "hfsplus",
                    "gpt_type_code": "AF00",
                    "gpt_type_guid": "48465300-0000-11AA-AA11-00306543ECAC",
                    "gpt_partition_guid": "44464E49-5800-4B49-5400-000000000002",
                    "gpt_readonly_bit60": True,
                    "file_count": 1,
                    "symlink_count": 0,
                    "files": [
                      {"path": "live-macos.md", "size": len(mac_b), "sha256": h(mac_b)}
                    ],
                    "symlinks": [],
                  },
                  {
                    "number": 3,
                    "label": "KIT-LNX",
                    "filesystem": "ext4",
                    "gpt_type_code": "8300",
                    "gpt_type_guid": "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                    "gpt_partition_guid": "44464E49-5800-4B49-5400-000000000003",
                    "gpt_readonly_bit60": True,
                    "file_count": 2,
                    "symlink_count": 1,
                    "files": [
                      {"path": "live-linux.md", "size": len(lnx_b), "sha256": h(lnx_b)},
                      {"path": "uac/uac", "size": len(uac_b), "sha256": h(uac_b)},
                    ],
                    "symlinks": [
                      {"path": "uac/run", "target": "uac"}
                    ],
                  },
                  {
                    "number": 4,
                    "label": "KIT-OUT",
                    "filesystem": "exfat",
                    "gpt_type_code": "0700",
                    "gpt_type_guid": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
                    "gpt_partition_guid": "44464E49-5800-4B49-5400-000000000004",
                    "gpt_readonly_bit60": False,
                    "file_count": 2,
                    "symlink_count": 0,
                    "files": [
                      {"path": ".fseventsd/no_log", "size": 0, "sha256": h(b"")},
                      {"path": ".metadata_never_index", "size": 0, "sha256": h(b"")},
                    ],
                    "symlinks": [],
                  },
                ],
              }
              with open(out_path, "w") as f:
                json.dump(manifest, f, indent=2)
              PY
            '';
          }
          ''
            set -euo pipefail
            sgdisk -Z /dev/vda
            sgdisk \
              --disk-guid=44464E49-5800-4B49-5400-000000000000 \
              -n 1:2048:+16M -t 1:0700 -c 1:KIT-WIN -u 1:44464E49-5800-4B49-5400-000000000001 \
              -n 2:0:+16M    -t 2:AF00 -c 2:KIT-MAC -u 2:44464E49-5800-4B49-5400-000000000002 \
              -n 3:0:+16M    -t 3:8300 -c 3:KIT-LNX -u 3:44464E49-5800-4B49-5400-000000000003 \
              -n 4:0:+12M    -t 4:0700 -c 4:KIT-OUT -u 4:44464E49-5800-4B49-5400-000000000004 \
              -A 1:set:60 -A 2:set:60 -A 3:set:60 \
              /dev/vda
            partx -u /dev/vda
            mkdir -p /mnt/p1 /mnt/p2 /mnt/p3 /mnt/p4

            mkfs.ntfs -F -Q -L KIT-WIN /dev/vda1
            ntfs-3g /dev/vda1 /mnt/p1
            printf 'windows-checklist\r\n' > /mnt/p1/live-windows.txt
            setfattr -v 0x00000001 -n system.ntfs_attrib_be /mnt/p1/live-windows.txt
            umount /mnt/p1

            mkfs.hfsplus -v KIT-MAC /dev/vda2
            mount -t hfsplus /dev/vda2 /mnt/p2
            printf 'macos-checklist\n' > /mnt/p2/live-macos.md
            chattr +i /mnt/p2/live-macos.md
            umount /mnt/p2

            mkfs.ext4 -F -L KIT-LNX /dev/vda3
            mount -t ext4 /dev/vda3 /mnt/p3
            mkdir -p /mnt/p3/uac
            printf 'linux-checklist\n' > /mnt/p3/live-linux.md
            printf '#!/bin/sh\necho UAC\n' > /mnt/p3/uac/uac
            chmod 0555 /mnt/p3/uac/uac
            ln -s uac /mnt/p3/uac/run
            chattr +i /mnt/p3/live-linux.md /mnt/p3/uac/uac
            umount /mnt/p3

            mkfs.exfat -L KIT-OUT -U 44464e49-5800-4b49-5400-000000000004 /dev/vda4
            mount -t exfat /dev/vda4 /mnt/p4
            mkdir -p /mnt/p4/.fseventsd
            : > /mnt/p4/.metadata_never_index
            : > /mnt/p4/.fseventsd/no_log
            umount /mnt/p4
            sync
            blockdev --flushbufs /dev/vda
          ''
      );
in
pkgs.testers.runNixOSTest {
  name = "dfkit-write-verify";

  nodes.machine = {
    virtualisation.memorySize = 2048;
    # 768 MiB virtual target stick (larger than both the 64 MiB fixture and the 612 MiB full fieldkit.img)
    virtualisation.emptyDiskImages = [ 768 ];
    boot.kernelModules = [ "hfsplus" "exfat" ];
    environment.systemPackages = with pkgs; [
      dfkit
      gptfdisk
      util-linux
      ntfs3g
      hfsprogs
      e2fsprogs
      exfatprogs
      python3
    ];
  };

  testScript = ''
    import json

    machine.wait_for_unit("multi-user.target")
    kit_dir = "${fixtureFieldkit}"
    orig_meta = json.loads(machine.succeed(f"cat {kit_dir}/manifest.json"))

    with subtest("refuses system disk, write-blocked disk, and wrong confirmation"):
        # System disk refused
        machine.fail(f"dfkit write {kit_dir} /dev/vda --confirm vda")
        # Write-block /dev/vdb (as dfnix does by default) -> must refuse until unblocked
        machine.succeed("blockdev --setro /dev/vdb")
        rc, out = machine.execute(f"dfkit write {kit_dir} /dev/vdb --confirm vdb 2>&1")
        assert rc == 2, f"expected refusal exit 2, got {rc}: {out}"
        assert "dfmount unblock" in out, out
        # Unblock /dev/vdb, but pass wrong --confirm name -> must refuse
        machine.succeed("blockdev --setrw /dev/vdb")
        rc, out = machine.execute(f"dfkit write {kit_dir} /dev/vdb --confirm wrongname 2>&1")
        assert rc == 2, f"expected refusal exit 2, got {rc}: {out}"

    with subtest("writes field-kit image, wipes and grows KIT-OUT, writes KIT-ID.json, and verifies read-back"):
        # Pre-populate the target stick with residual data from a "previous case" across 700 MiB
        machine.succeed("(yes PREVIOUS-CASE-DATA || true) | head -c 700M > /dev/vdb && sync && blockdev --flushbufs /dev/vdb")
        machine.succeed(f"dfkit write {kit_dir} /dev/vdb --confirm vdb")
        # Partition 4 (KIT-OUT) must have grown well beyond its initial size in fieldkit.img
        p4_bytes = int(machine.succeed("blockdev --getsize64 /dev/vdb4").strip())
        assert p4_bytes > 100 * 1024 * 1024, f"expected KIT-OUT > 100 MiB on 768 MiB disk, got {p4_bytes}"

        # Residual data from previous case must be completely wiped from KIT-OUT (/dev/vdb4)
        residual_hits = int(machine.succeed("grep -a -c PREVIOUS-CASE-DATA /dev/vdb4 || true").strip())
        assert residual_hits == 0, f"expected 0 occurrences of PREVIOUS-CASE-DATA on /dev/vdb4, got {residual_hits}"

        # Check KIT-ID.json on KIT-OUT
        machine.succeed("mkdir -p /mnt/kit-out && mount -t exfat -o ro /dev/vdb4 /mnt/kit-out")
        kit_id = json.loads(machine.succeed("cat /mnt/kit-out/KIT-ID.json"))
        machine.succeed("test -f /mnt/kit-out/.metadata_never_index && test -f /mnt/kit-out/.fseventsd/no_log")
        machine.succeed("umount /mnt/kit-out")
        assert kit_id["kit_version"] == orig_meta["version"], kit_id
        assert kit_id["image_sha256"] == orig_meta["image"]["sha256"], kit_id
        assert kit_id["kit_out_zeroed"] is True, kit_id

        # Check dfkit verify passes (exit 0)
        out = machine.succeed(f"dfkit verify /dev/vdb {kit_dir}")
        assert "Field-kit verification PASSED" in out, out
        assert "dfcollect files" in out, out

    with subtest("detects planted file and modified tool file, while tolerating allowlisted OS noise"):
        # 1. Add allowlisted OS noise on KIT-WIN (Partition 1, NTFS) -> exit 0, [OS-ADDED]
        machine.succeed("blockdev --setrw /dev/vdb /dev/vdb1 && mkdir -p /mnt/win && ntfs-3g /dev/vdb1 /mnt/win")
        machine.succeed("mkdir -p '/mnt/win/System Volume Information' && printf 'noise' > '/mnt/win/System Volume Information/WPSettings.dat'")
        machine.succeed("umount /mnt/win")

        out_noise_only = machine.succeed(f"dfkit verify /dev/vdb {kit_dir}")
        assert "[OS-ADDED] KIT-WIN: System Volume Information/WPSettings.dat" in out_noise_only, out_noise_only

        # 2. Plant an unexpected file on KIT-WIN (`version.dll`) -> exit 5, [UNEXPECTED]
        machine.succeed("blockdev --setrw /dev/vdb /dev/vdb1 && ntfs-3g /dev/vdb1 /mnt/win")
        machine.succeed("printf 'hijack' > /mnt/win/version.dll")
        machine.succeed("umount /mnt/win")

        rc, out_planted = machine.execute(f"dfkit verify /dev/vdb {kit_dir} 2>&1")
        assert rc == 5, f"expected exit 5 on planted file, got {rc}: {out_planted}"
        assert "[UNEXPECTED] KIT-WIN: version.dll" in out_planted, out_planted
        assert "[OS-ADDED] KIT-WIN: System Volume Information/WPSettings.dat" in out_planted, out_planted

        # Remove planted file -> verify returns to exit 0
        machine.succeed("blockdev --setrw /dev/vdb /dev/vdb1 && ntfs-3g /dev/vdb1 /mnt/win")
        machine.succeed("rm /mnt/win/version.dll")
        machine.succeed("umount /mnt/win")
        machine.succeed(f"dfkit verify /dev/vdb {kit_dir}")

        # 3. Modify a tool file on KIT-LNX (Partition 3, ext4: mount rw, chattr -i, append) -> exit 5, [CHANGED]
        machine.succeed("blockdev --setrw /dev/vdb /dev/vdb3 && mkdir -p /mnt/lnx && mount -t ext4 /dev/vdb3 /mnt/lnx")
        machine.succeed("chattr -i /mnt/lnx/live-linux.md && echo 'tampered' >> /mnt/lnx/live-linux.md")
        machine.succeed("umount /mnt/lnx")

        rc, out_tampered = machine.execute(f"dfkit verify /dev/vdb {kit_dir} 2>&1")
        assert rc == 5, f"expected exit 5 on tampered tool file, got {rc}: {out_tampered}"
        assert "[CHANGED] KIT-LNX: live-linux.md" in out_tampered, out_tampered
        assert "[OS-ADDED] KIT-WIN: System Volume Information/WPSettings.dat" in out_tampered, out_tampered

    with subtest("audit log contains fieldkit_write and fieldkit_verify records"):
        lines = [json.loads(l) for l in machine.succeed("cat /run/dfnix/audit.jsonl").splitlines() if l.strip()]
        actions = [(r["action"], r["outcome"]) for r in lines]
        assert ("fieldkit_write", "refused") in actions, actions
        assert ("fieldkit_write", "ok") in actions, actions
        assert ("fieldkit_verify", "ok") in actions, actions
        assert ("fieldkit_verify", "error") in actions, actions
        write_ok = [r for r in lines if r["action"] == "fieldkit_write" and r["outcome"] == "ok"][0]
        assert write_ok["details"]["kit_out_zeroed"] is True, write_ok
  '';
}
