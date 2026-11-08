#!/usr/bin/env bash
# Exit 0 (printing the path) once a new Proton Drive zip has finished downloading: newer than the
# reference file, no Chrome partial download left, size unchanged over three checks a minute apart,
# and its zip directory readable. Exit 3 after 14 hours.
REF="$1"; DIRS=(/home/ali/Desktop/Hazim/external-datasets /home/ali/Downloads)
deadline=$(( $(date +%s) + 14*3600 )); last=""; stable=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  partial=$(find "${DIRS[@]}" -maxdepth 1 -newer "$REF" \( -name '*.crdownload' -o -name '*.part' \) 2>/dev/null | head -1)
  cand=$(find "${DIRS[@]}" -maxdepth 1 -newer "$REF" -name '*.zip' -size +100M -printf '%T@ %s %p\n' 2>/dev/null | sort -n | tail -1)
  if [ -z "$partial" ] && [ -n "$cand" ]; then
    if [ "$cand" = "$last" ]; then stable=$((stable+1)); else stable=0; last="$cand"; fi
    if [ "$stable" -ge 2 ]; then
      path="${cand#* * }"
      if /usr/bin/python3 -I -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); print(len(z.infolist()), "members")' "$path"; then
        echo "DOWNLOAD_DONE $path"; exit 0
      fi
    fi
  else
    stable=0; last=""
  fi
  sleep 60
done
echo "TIMEOUT"; exit 3
