#!/usr/bin/env bash
# Collect Sysmon for Linux events into a file the harness can parse.
#
# Run this on the LAB VM (never a production host). Requires root.
#
#   sudo ./collect_sysmon.sh install        # install sysmon + config
#   sudo ./collect_sysmon.sh dump out.log    # export collected events
#
# The dump contains the raw <Event>...</Event> XML blobs that
# attack_llm_eval.normalize.sysmon_linux expects.
set -euo pipefail

cmd="${1:-help}"

install_sysmon() {
  echo "[+] Installing Sysmon for Linux"
  # Debian/Ubuntu via Microsoft package repo.
  if ! command -v sysmon >/dev/null 2>&1; then
    source /etc/os-release
    wget -q "https://packages.microsoft.com/config/${ID}/${VERSION_ID}/packages-microsoft-prod.deb" \
      -O /tmp/pmc.deb
    dpkg -i /tmp/pmc.deb
    apt-get update
    apt-get install -y sysmonforlinux
  fi
  # Minimal config: capture process, network, and file-create events.
  cat > /tmp/sysmon-linux.xml <<'XML'
<Sysmon schemaversion="4.81">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"></ProcessCreate>
    <NetworkConnect onmatch="exclude"></NetworkConnect>
    <FileCreate onmatch="exclude"></FileCreate>
    <ProcessTerminate onmatch="exclude"></ProcessTerminate>
  </EventFiltering>
</Sysmon>
XML
  sysmon -accepteula -i /tmp/sysmon-linux.xml
  echo "[+] Sysmon installed and running"
}

dump_events() {
  out="${1:-sysmon_events.log}"
  echo "[+] Dumping Sysmon events to ${out}"
  # Sysmon for Linux logs under the 'sysmon' syslog identifier via journald.
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -t sysmon -o cat --no-pager > "${out}" || true
  fi
  # Fallback: syslog file.
  if [ ! -s "${out}" ] && [ -f /var/log/syslog ]; then
    grep -a 'Linux-Sysmon\|<Event' /var/log/syslog > "${out}" || true
  fi
  n=$(grep -ac '<Event' "${out}" || true)
  echo "[+] wrote ${out} (${n} <Event> records)"
}

case "${cmd}" in
  install) install_sysmon ;;
  dump)    dump_events "${2:-sysmon_events.log}" ;;
  *) echo "usage: $0 {install|dump <outfile>}"; exit 1 ;;
esac
