#!/usr/bin/env python3
"""Measure release-binary startup, healthz, and boot-policy latency.

Writes JSON to stdout. Does not invent samples. N=10 after the certificates
already exist, plus one cold start reported separately.
"""

import json
import os
import shutil
import ssl
import subprocess
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVER = os.path.join(ROOT, "target", "release", "sbm-server")
SIM = os.path.join(ROOT, "target", "release", "sbm-sim")
SECRET = "lab-bootstrap-secret"
PORT = "18543"
N = 10


def wait_health(ca, started, deadline):
    url = f"https://127.0.0.1:{PORT}/healthz"
    ctx = None
    while time.monotonic() < deadline:
        if ctx is None and os.path.isfile(ca):
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(ca)
        if ctx is not None:
            try:
                with urllib.request.urlopen(url, context=ctx, timeout=1) as response:
                    if response.status == 200:
                        return (time.monotonic() - started) * 1000
            except Exception:
                pass
        time.sleep(0.001)
    raise SystemExit("healthz did not return 200")


def start_server(data):
    env = os.environ.copy()
    env.update(
        {
            "SBM_DEV_BOOTSTRAP": "1",
            "SBM_BOOTSTRAP_SECRET": SECRET,
            "SBM_BIND": f"127.0.0.1:{PORT}",
            "SBM_DATA_DIR": data,
            "SBM_PUBLIC_ORIGIN": f"https://localhost:{PORT}",
            "SBM_RP_ID": "localhost",
            "SBM_LOG_FORMAT": "text",
        }
    )
    log = open(os.path.join(ROOT, "target", "measure-server.log"), "ab")
    return subprocess.Popen(
        [SERVER],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def timed_gets(url, ctx, count):
    samples = []
    for _ in range(count):
        started = time.monotonic()
        with urllib.request.urlopen(url, context=ctx, timeout=5) as response:
            response.read()
            if response.status != 200:
                raise SystemExit(f"{url} returned {response.status}")
        samples.append((time.monotonic() - started) * 1000)
    return samples


def summarize(samples):
    ordered = sorted(samples)
    def pct(p):
        index = round(p / 100 * (len(ordered) - 1))
        return ordered[index]
    return {
        "n": len(samples),
        "unit": "ms",
        "samples": [round(sample, 3) for sample in samples],
        "min": round(ordered[0], 3),
        "p50": round(pct(50), 3),
        "p95": round(pct(95), 3),
        "max": round(ordered[-1], 3),
    }


def main():
    if not os.path.isfile(SERVER) or not os.path.isfile(SIM):
        raise SystemExit("build the release binaries first: cargo build --release -p sbm-server -p sbm-sim")
    work = os.path.join(ROOT, "target", "measure")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    try:
        cold_dir = os.path.join(work, "cold")
        os.mkdir(cold_dir)
        cold_started = time.monotonic()
        cold = start_server(cold_dir)
        cold_ms = wait_health(os.path.join(cold_dir, "ca.cert.pem"), cold_started, cold_started + 30)
        stop(cold)

        warm_dir = os.path.join(work, "warm")
        shutil.copytree(cold_dir, warm_dir)
        warm = []
        for _ in range(N):
            started = time.monotonic()
            proc = start_server(warm_dir)
            warm.append(wait_health(os.path.join(warm_dir, "ca.cert.pem"), started, started + 30))
            stop(proc)

        started = time.monotonic()
        proc = start_server(warm_dir)
        ca = os.path.join(warm_dir, "ca.cert.pem")
        wait_health(ca, started, started + 30)
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(ca)
        health = timed_gets(f"https://127.0.0.1:{PORT}/healthz", ctx, N + 2)[2:]

        login = urllib.request.Request(
            f"https://127.0.0.1:{PORT}/v1/auth/dev-login",
            data=json.dumps({"secret": SECRET}).encode(),
            headers={"content-type": "application/json"},
        )
        with urllib.request.urlopen(login, context=ctx, timeout=5) as response:
            token = json.load(response)["token"]
        create = urllib.request.Request(
            f"https://127.0.0.1:{PORT}/v1/enrollment-tokens",
            data=b"{}",
            headers={"content-type": "application/json", "authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(create, context=ctx, timeout=5) as response:
            bundle = json.load(response)
        state = os.path.join(work, "device.sim.json")
        subprocess.check_call(
            [
                SIM, "enroll",
                "--server", f"https://127.0.0.1:{PORT}",
                "--token", bundle["token"],
                "--ca-pem", ca,
                "--fingerprint", bundle["ca_fingerprint_sha256"],
                "--hostname", "measure-vm",
                "--state", state,
            ],
            stdout=subprocess.DEVNULL,
        )
        identity = os.path.join(work, "identity.pem")
        with open(identity, "w") as handle:
            subprocess.check_call([SIM, "identity", "--state", state], stdout=handle)
        device_id = json.load(open(state))["device_id"]
        device_ctx = ssl.create_default_context()
        device_ctx.load_verify_locations(ca)
        device_ctx.load_cert_chain(identity)
        policy = timed_gets(
            f"https://127.0.0.1:{PORT}/v1/devices/{device_id}/boot-policy",
            device_ctx,
            N + 2,
        )[2:]
        stop(proc)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
    print(json.dumps({
        "binary": "target/release/sbm-server",
        "rustc": rustc,
        "port": PORT,
        "cold_start_to_healthz_ms": round(cold_ms, 3),
        "warm_start_to_healthz": summarize(warm),
        "healthz_request": summarize(health),
        "boot_policy_request": summarize(policy),
        "warmup_requests_dropped": 2,
        "startup_clock": "time.monotonic immediately before Popen until the first healthz 200; poll interval 1 ms",
        "percentile_index": "round(percent/100 * (n - 1)) on the sorted samples",
    }, indent=2))


if __name__ == "__main__":
    main()
