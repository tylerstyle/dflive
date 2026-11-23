# dflive.exe (the mingw cross build) under Wine: state must list the running
# processes with command lines, owners and image hashes, and a TCP connection
# held by `dflive.exe send` together with that process; keys must record that
# manage-bde is missing instead of failing; status must measure the clock and
# list the volumes; the footprint log must record both runs.
#
#   nix-build tests/wine.nix
{ pkgs ? import <nixpkgs> { }
, dflive ? pkgs.pkgsCross.mingw-msvcrt-x86_64.callPackage ../package.nix { }
}:

pkgs.runCommand "dflive-wine"
{
  nativeBuildInputs = [ pkgs.wineWow64Packages.stable pkgs.socat pkgs.python3 ];
}
  ''
    export HOME=$PWD WINEPREFIX=$PWD/wine WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml="
    exe=${dflive}/bin/dflive.exe
    wine cmd /c ver

    head -c 1048576 /dev/urandom > src.bin
    # A receiver that accepts and never answers holds the sender's connection open
    timeout 120 socat -u TCP-LISTEN:39998,bind=127.0.0.1,reuseaddr OPEN:/dev/null &
    sleep 1
    timeout 110 wine $exe send "Z:$PWD/src.bin" --to 127.0.0.1:39998 --code "123 456 7890" &
    for _ in $(seq 120); do
      grep -q ' 0100007F:9C3E 01 ' /proc/net/tcp && break
      sleep 0.5
    done

    wine $exe state -o "Z:$PWD/state.json"
    ref=$(date -u -d '-30 seconds' +%Y-%m-%dT%H:%M:%SZ)
    wine $exe status --reference-time "$ref" -o "Z:$PWD/status.json" --log "Z:$PWD/fp.jsonl"
    wine $exe keys -o "Z:$PWD/keys.json" --plaintext --log "Z:$PWD/fp.jsonl"
    wineserver -k || true

    python3 - $exe <<'EOF'
    import hashlib, json, sys

    state = json.load(open("state.json"))
    procs = state["processes"]
    def ours(verb):
        return [p for p in procs if p["name"] == "dflive.exe" and f" {verb} " in (p.get("cmdline") or "")]
    sender, me = ours("send"), ours("state")
    assert len(sender) == 1 and len(me) == 1, procs
    want = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
    assert me[0]["exe_sha256"] == want, (me, want)
    assert me[0]["start"] and me[0]["user"], me
    assert any(p["name"] == "services.exe" for p in procs), procs

    conn = [s for s in state["sockets"] if s["remote"] == "127.0.0.1:39998"]
    assert len(conn) == 1, state["sockets"]
    assert conn[0]["proto"] == "tcp" and conn[0]["state"] == "ESTABLISHED", conn
    assert conn[0]["pids"] == [sender[0]["pid"]], (conn, sender)

    assert any("127.0.0.1/8" in i["addresses"] for i in state["interfaces"]), state["interfaces"]
    assert state["os"]["version"], state["os"]
    assert state["users"] and state["users"][0]["state"] == "active", state["users"]
    assert any(s["state"] == "running" and s["pid"] for s in state["services"]), state["services"]
    assert state["boot_time"] < state["collected_at"], state

    keys = json.load(open("keys.json"))
    assert keys["os"].startswith("windows"), keys
    assert keys["details"]["commands"][0].get("error"), keys
    status = json.load(open("status.json"))
    assert 29 <= status["clock"]["offset_seconds"] <= 90, status["clock"]
    assert status["system"]["os"]["version"], status["system"]
    roots = [d.get("root") for d in status["disks"]]
    assert "C:\\" in roots, status["disks"]
    assert status["encryption"]["manage_bde_status"].get("error"), status["encryption"]

    log = [json.loads(l) for l in open("fp.jsonl")]
    assert [r["action"] for r in log] == ["status", "keys"], log
    assert all(r["self"]["exe_sha256"] == want and r["self"]["kit"] is None for r in log), log
    assert log[0]["written"][0]["path"].endswith("status.json"), log[0]
    assert log[1]["children"][0]["command"] == "manage-bde -status", log[1]
    assert log[1]["children"][0]["error"], log[1]
    print("dflive.exe state, status, keys and the log under Wine: OK")
    EOF
    mkdir $out
    cp state.json keys.json status.json fp.jsonl $out/
  ''
