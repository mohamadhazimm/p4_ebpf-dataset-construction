#!/bin/bash
set -euo pipefail
[[ $EUID == 0 ]] || exit 2
exec /usr/bin/python3 - <<'PY'
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

def run(*command, check=True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if check and result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(command) + ': ' + result.stderr)
    return result

def write_new(path, content):
    with Path(path).open('x') as stream:
        stream.write(content)
    Path(path).chmod(0o644)

required = ['apt-daily.timer', 'apt-daily-upgrade.timer', 'apt-daily.service',
            'apt-daily-upgrade.service', 'unattended-upgrades.service', 'fwupd-refresh.timer',
            'motd-news.timer', 'update-notifier-download.timer', 'update-notifier-motd.timer', 'ua-timer.timer']
optional = ['packagekit.service', 'packagekit-offline-update.service']
installed = run('systemctl', 'list-unit-files', '--all', '--no-legend', '--no-pager').stdout
present = {line.split()[0] for line in installed.splitlines() if line.split()}
masked = required + [unit for unit in optional if unit in present]
run('systemctl', 'mask', '--now', *masked)
dump = run('apt-config', 'dump').stdout
keys = {'APT::Periodic::Enable', 'APT::Periodic::Update-Package-Lists', 'APT::Periodic::Download-Upgradeable-Packages',
        'APT::Periodic::Unattended-Upgrade', 'APT::Periodic::AutocleanInterval', 'APT::Periodic::Verbose',
        'APT::Periodic::RandomSleep', 'APT::Periodic::BackupArchiveInterval', 'APT::Periodic::MaxAge',
        'APT::Periodic::MinAge', 'APT::Periodic::MaxSize', 'APT::Periodic::CleanInterval'}
for line in dump.splitlines():
    match = re.fullmatch(r'(APT::Periodic::[^\s]+) "([^"]*)";', line)
    if match:
        keys.add(match.group(1))
apt_path = Path('/etc/apt/apt.conf.d/99-hazim-no-periodic')
write_new(apt_path, ''.join(key + ' "0";\n' for key in sorted(keys)))
effective = run('apt-config', 'dump').stdout
values = dict(re.findall(r'^(APT::Periodic::[^\s]+) "([^"]*)";$', effective, re.MULTILINE))
if not keys <= values.keys() or any(value != '0' for value in values.values()):
    raise RuntimeError('Effective APT::Periodic::* policy is not all zero')
snap = {'installed': bool(shutil.which('snap'))}
if snap['installed']:
    snap['hold_command'] = run('snap', 'refresh', '--hold=forever').stdout.strip()
    snap['effective_refresh_time'] = run('snap', 'refresh', '--time').stdout.strip()
    if not re.search(r'^hold:\s+forever\s*$', snap['effective_refresh_time'], re.MULTILINE):
        raise RuntimeError('Indefinite snap refresh hold not confirmed; finite holds are not final')
inherited = ['chrony.service', 'avahi-daemon.service', 'avahi-daemon.socket', 'cups-browsed.service', 'geoclue.service']
def state(unit):
    return {'enabled': run('systemctl', 'is-enabled', unit, check=False).stdout.strip(),
            'active': run('systemctl', 'is-active', unit, check=False).stdout.strip(),
            'show': run('systemctl', 'show', unit, '--property=LoadState,UnitFileState,ActiveState,SubState,Triggers,TriggeredBy',
                        check=False).stdout.strip()}
units = {unit: state(unit) for unit in masked + inherited + ['NetworkManager.service']}
if any(units[unit]['enabled'] != 'masked' or units[unit]['active'] == 'active' for unit in masked):
    raise RuntimeError('Required unit mask/inactivity not confirmed')
if units['chrony.service']['active'] == 'active' or any(units[unit]['active'] == 'active' for unit in inherited):
    raise RuntimeError('Inherited quiet-v1 service active')
nm = Path('/etc/NetworkManager/conf.d/99-hazim-quiet-ambient.conf')
if nm.read_text() != '[connectivity]\nenabled=false\n' or units['NetworkManager.service']['active'] != 'active':
    raise RuntimeError('Inherited NetworkManager policy differs')
receipt = {'policy': 'quiet-v2', 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           'masked_units': masked, 'optional_absent': [unit for unit in optional if unit not in present],
           'units': units, 'apt_periodic_effective': values, 'snap': snap,
           'list_timers_all': run('systemctl', 'list-timers', '--all', '--no-pager', '--output=json').stdout,
           'files': {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (apt_path, nm)}}
os.sync()
print(json.dumps(receipt, sort_keys=True))
PY