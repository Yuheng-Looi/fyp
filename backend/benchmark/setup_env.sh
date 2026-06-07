#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y software-properties-common
add-apt-repository -y ppa:deadsnakes/ppa
apt-get update -y
apt-get install -y build-essential python3.11 python3.11-dev python3.11-distutils python3.11-lib2to3 python3.11-venv

if [[ ! -d "benchmarkenv" ]]; then
  python3.11 -m venv benchmarkenv
fi

./benchmarkenv/bin/pip install --upgrade pip setuptools wheel
./benchmarkenv/bin/pip install 'setuptools<58'
./benchmarkenv/bin/pip install --no-build-isolation ryu eventlet PyYAML

UNPINNED_REQUIREMENTS="$(mktemp)"
python3.11 - <<'REQ_PY' > "$UNPINNED_REQUIREMENTS"
from pathlib import Path
import re

requirements_path = Path.cwd().parent / "requirements.txt"
for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or line.startswith(("-", "--")):
        continue
    line = line.split("#", 1)[0].strip()
    package = re.split(r"\s*(?:===|==|~=|!=|<=|>=|<|>)\s*", line, maxsplit=1)[0].strip()
    normalized = package.lower().replace("_", "-")
    if normalized in {"setuptools", "ryu"}:
        continue
    if package:
        print(package)
REQ_PY
trap 'rm -f "$UNPINNED_REQUIREMENTS"' EXIT
./benchmarkenv/bin/pip install -r "$UNPINNED_REQUIREMENTS"
rm -f "$UNPINNED_REQUIREMENTS"
trap - EXIT

SITE_PACKAGES="$(./benchmarkenv/bin/python - <<'PY'
import site
print(site.getsitepackages()[0])
PY
)"

mkdir -p "$SITE_PACKAGES/oslo"
cat > "$SITE_PACKAGES/oslo/__init__.py" <<'PY'
from oslo_config import cfg  # noqa: F401
PY
cat > "$SITE_PACKAGES/oslo/config.py" <<'PY'
from oslo_config import cfg as cfg
PY

./benchmarkenv/bin/python -m lib2to3 -w -n "$SITE_PACKAGES/ryu"
grep -RIl "__builtin__" "$SITE_PACKAGES/ryu" | xargs -r sed -i 's/__builtin__/builtins/g'
grep -RIl "string.upper(" "$SITE_PACKAGES/ryu" | xargs -r sed -i 's/string.upper(/str.upper(/g'

Ryu_LLDP_FILE="$SITE_PACKAGES/ryu/lib/packet/lldp.py"
Ryu_ETHERNET_FILE="$SITE_PACKAGES/ryu/lib/packet/ethernet.py"
python3.11 - <<PY
from pathlib import Path

path = Path("$Ryu_LLDP_FILE")
text = path.read_text()
text = text.replace(
  "        return struct.pack('!HB', self.typelen, self.subtype) + self.chassis_id\n",
  "        chassis_id = self.chassis_id.encode('utf-8') if isinstance(self.chassis_id, str) else self.chassis_id\n"
  "        return struct.pack('!HB', self.typelen, self.subtype) + chassis_id\n",
)
text = text.replace(
  "        return struct.pack('!HB', self.typelen, self.subtype) + self.port_id\n",
  "        port_id = self.port_id.encode('utf-8') if isinstance(self.port_id, str) else self.port_id\n"
  "        return struct.pack('!HB', self.typelen, self.subtype) + port_id\n",
)
text = text.replace(
  "        return struct.pack('!H', self.typelen) + self.tlv_info\n",
  "        tlv_info = self.tlv_info.encode('utf-8') if isinstance(self.tlv_info, str) else self.tlv_info\n"
  "        return struct.pack('!H', self.typelen) + tlv_info\n",
  2,
)
path.write_text(text)

path = Path("$Ryu_ETHERNET_FILE")
text = path.read_text()
text = text.replace(
  "        return struct.pack(ethernet._PACK_STR, self.dst, self.src,\n                           self.ethertype)\n",
  "        dst = self.dst.encode('utf-8') if isinstance(self.dst, str) else self.dst\n"
  "        src = self.src.encode('utf-8') if isinstance(self.src, str) else self.src\n"
  "        return struct.pack(ethernet._PACK_STR, dst, src,\n                           self.ethertype)\n",
)
path.write_text(text)

path = Path("$SITE_PACKAGES/ryu/base/app_manager.py")
text = path.read_text()
text = text.replace(
  "            for ev_cls, list in list(i.observers.items()):\n"
  "                LOG.debug(\"  PROVIDES %s TO %s\" % (ev_cls.__name__, list))\n",
  "            for ev_cls, observers in list(i.observers.items()):\n"
  "                LOG.debug(\"  PROVIDES %s TO %s\" % (ev_cls.__name__, observers))\n",
)
path.write_text(text)
PY

echo "benchmarkenv provisioning complete."
if [[ -t 0 && -t 1 ]]; then
  # Activation cannot modify the parent terminal after this script exits, so
  # keep interactive runs inside an activated shell.
  set +u
  source "$SCRIPT_DIR/benchmarkenv/bin/activate"
  echo "benchmarkenv is active. Type 'exit' to leave this shell."
  exec "${SHELL:-/bin/bash}" -i
fi
