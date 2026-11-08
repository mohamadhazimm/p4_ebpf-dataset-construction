#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${BASH_SOURCE[0]}" == "/home/csci/.corrected-pilot-setup.sh" ]]; then
    probe_dir="/home/csci/Downloads/pcap-interface-sequence-probe"
    source_probe="$probe_dir/interface_sequence_probe.sh"
    /usr/bin/tcpdump -d "udp and dst host 239.255.42.198 and dst port 65003" >/dev/null
    for suffix in 01 02 03; do
        install -m 755 "$source_probe" "$probe_dir/filtered_sequence_probe_$suffix.sh"
    done
    exit 0
fi

exit 0