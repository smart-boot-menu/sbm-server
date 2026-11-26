#!/bin/sh
# Drive the dashboard in headless Chrome and write docs/screenshots.
set -eu
cd "$(dirname "$0")/.."
DATA="$(pwd)/target/capture-data"
STATE="$(pwd)/target/lab-vm.sim.json"
PORT=18443
SECRET="${SBM_BOOTSTRAP_SECRET:-lab-bootstrap-secret}"
rm -rf "$DATA" "$STATE"
mkdir -p "$DATA" docs/screenshots
export SBM_DEV_BOOTSTRAP=1
export SBM_BOOTSTRAP_SECRET="$SECRET"
export SBM_BIND="127.0.0.1:${PORT}"
export SBM_DATA_DIR="$DATA"
export SBM_PUBLIC_ORIGIN="https://localhost:${PORT}"
export SBM_RP_ID=localhost
./target/debug/sbm-server > target/capture.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
python3 - "$DATA/ca.cert.pem" "$PORT" "$SECRET" <<'PY'
import json, ssl, sys, time, urllib.request
ca, port, secret = sys.argv[1:]
ctx = ssl.create_default_context()
ctx.load_verify_locations(ca)
base = f"https://127.0.0.1:{port}"
deadline = time.monotonic() + 8
while True:
    try:
        with urllib.request.urlopen(base + "/healthz", context=ctx, timeout=1) as response:
            if response.status == 200:
                break
    except Exception:
        if time.monotonic() > deadline:
            raise SystemExit("server did not accept TLS")
        time.sleep(0.1)
login = urllib.request.Request(
    base + "/v1/auth/dev-login",
    data=json.dumps({"secret": secret}).encode(),
    headers={"content-type": "application/json"},
)
with urllib.request.urlopen(login, context=ctx, timeout=5) as response:
    token = json.load(response)["token"]
create = urllib.request.Request(
    base + "/v1/enrollment-tokens",
    data=b"{}",
    headers={"content-type": "application/json", "authorization": f"Bearer {token}"},
)
with urllib.request.urlopen(create, context=ctx, timeout=5) as response:
    json.dump(json.load(response), open("target/capture-bundle.json", "w"))
PY
ENROLL_TOKEN=$(python3 -c 'import json; print(json.load(open("target/capture-bundle.json"))["token"])')
FINGERPRINT=$(python3 -c 'import json; print(json.load(open("target/capture-bundle.json"))["ca_fingerprint_sha256"])')
./target/debug/sbm-sim enroll \
  --server "https://127.0.0.1:${PORT}" \
  --token "$ENROLL_TOKEN" \
  --ca-pem "$DATA/ca.cert.pem" \
  --fingerprint "$FINGERPRINT" \
  --hostname lab-vm \
  --state "$STATE"
./target/debug/sbm-sim once --state "$STATE" --mode uefi
DEVICE_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["device_id"])' "$STATE")
SBM_URL="https://localhost:${PORT}" \
SBM_BOOTSTRAP_SECRET="$SECRET" \
SBM_DEVICE_ID="$DEVICE_ID" \
SBM_STATE="$STATE" \
SBM_SIM="$(pwd)/target/debug/sbm-sim" \
node tools/capture.mjs
echo "screenshots written to docs/screenshots"
