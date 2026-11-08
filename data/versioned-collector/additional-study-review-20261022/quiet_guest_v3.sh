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
snapd_units = [unit for unit in ('snapd.service', 'snapd.socket', 'snapd.seeded.service', 'snapd.snap-repair.timer',
                                  'snapd.snap-repair.service', 'snapd.autoimport.service') if unit in present]
if not {'snapd.service', 'snapd.socket'} <= set(snapd_units):
    raise RuntimeError('snapd service/socket not found; refusing to guess the store client')
run('systemctl', 'mask', '--now', *snapd_units)
# Headless: collection needs no desktop; the GNOME session is a source of boot-time chatter (WS-Discovery etc.).
run('systemctl', 'set-default', 'multi-user.target')
default_target = run('systemctl', 'get-default').stdout.strip()
if default_target != 'multi-user.target':
    raise RuntimeError('Default target not multi-user.target: ' + default_target)
dependencies = run('systemctl', 'list-dependencies', '--plain', '--no-pager', 'multi-user.target').stdout
pulled = {line.strip() for line in dependencies.splitlines()}
needed = ['virtualbox-guest-utils.service', 'NetworkManager.service']
missing = [unit for unit in needed if unit not in pulled]
if missing:
    raise RuntimeError('Headless boot would not start: ' + ', '.join(missing))
inherited = ['chrony.service', 'avahi-daemon.service', 'avahi-daemon.socket', 'cups-browsed.service', 'geoclue.service']
def state(unit):
    return {'enabled': run('systemctl', 'is-enabled', unit, check=False).stdout.strip(),
            'active': run('systemctl', 'is-active', unit, check=False).stdout.strip(),
            'show': run('systemctl', 'show', unit, '--property=LoadState,UnitFileState,ActiveState,SubState,Triggers,TriggeredBy',
                        check=False).stdout.strip()}
units = {unit: state(unit) for unit in masked + snapd_units + inherited + needed}
if any(units[unit]['enabled'] != 'masked' or units[unit]['active'] == 'active' for unit in masked + snapd_units):
    raise RuntimeError('Required unit mask/inactivity not confirmed')
if units['chrony.service']['active'] == 'active' or any(units[unit]['active'] == 'active' for unit in inherited):
    raise RuntimeError('Inherited quiet-v1 service active')
nm = Path('/etc/NetworkManager/conf.d/99-hazim-quiet-ambient.conf')
if nm.read_text() != '[connectivity]\nenabled=false\n' or units['NetworkManager.service']['active'] != 'active':
    raise RuntimeError('Inherited NetworkManager policy differs')
receipt = {'policy': 'quiet-v3', 'default_target': default_target,
           'headless_required_units': needed, 'snapd_masked_units': snapd_units, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           'masked_units': masked, 'optional_absent': [unit for unit in optional if unit not in present],
           'units': units, 'apt_periodic_effective': values,
           'list_timers_all': run('systemctl', 'list-timers', '--all', '--no-pager', '--output=json').stdout,
           'files': {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (apt_path, nm)}}
os.sync()
print(json.dumps(receipt, sort_keys=True))
PY