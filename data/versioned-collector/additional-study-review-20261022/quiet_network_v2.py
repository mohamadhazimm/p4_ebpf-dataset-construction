"""Build benign-only quiet-v2 controls and bind application receipts to captured bytes."""

import argparse
import csv
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

import collect_v19 as frozen

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'attribution_control.c'
SOURCE_SHA = '2b294343448f23cc918d0d04a86fd9005d67e90749147d62a884319f1a58883e'


def network_cases(binary_sha):
    result = []
    for repeat in (1, 2):
        token = 'final_net_r' + str(repeat)
        result.append({'sample': 'final-net-r' + str(repeat) + '.zip', 'label': 'benign',
            'mode': 'native_amd64_static', 'program': 'attribution-control', 'sha256': binary_sha,
            'network_control': {'token': token, 'repeat': repeat},
            'collection_arguments': ['net', token, str(repeat)],
            'http': [{'path': '/attribution-' + token}],
            'udp': [{'sport': 65200 + repeat,
                     'payloads': ['HAZIM_ATTR_' + token + '_' + str(index).zfill(3) for index in range(6)]}],
            'response_file': 'pilot-http-response.bin'})
    return result


def check_receipt(case, run_dir, parsed, bounds, metadata):
    import validate_quiet_v2 as traffic
    from scapy.layers.inet import UDP

    control = case['network_control']
    repeat, token = control['repeat'], control['token']
    frozen.require(repeat in (1, 2) and token == 'final_net_r' + str(repeat), 'Network control identity differs')
    frozen.require(case['collection_arguments'] == ['net', token, str(repeat)], 'Network arguments differ')
    frozen.require(case['http'] == [{'path': '/attribution-' + token}]
                   and case['udp'] == network_cases(case['sha256'])[repeat - 1]['udp'], 'Network declaration differs')
    with (run_dir / 'sample.stdout.log').open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    expected_events = ['start', 'tcp_connected', 'udp_bound'] + ['udp_sent'] * 6 + ['done']
    frozen.require([row['event'] for row in rows] == expected_events, 'Network event order/count differs')
    pids = {int(row['pid']) for row in rows}
    frozen.require(len(pids) == 1 and all(value > 0 for value in pids), 'Network PID differs')
    with (run_dir / 'exec_events.csv').open(newline='') as stream:
        execs = [row for row in csv.DictReader(stream) if row['event'] == 'exec_success'
                 and int(row['pid']) in pids
                 and ('filename=' + metadata['target_exec']['expected_path']) in row['detail'].split()]
    frozen.require(len(execs) == 1, 'Application PID does not match exact target exec')
    previous = (0, 0)
    for row in rows:
        clocks = (int(row['realtime_ns']), int(row['monotonic_ns']))
        frozen.require(all(current >= old for current, old in zip(clocks, previous)), 'Application clocks regress')
        frozen.require(any(start <= clocks[0] < end for start, end in bounds), 'Application receipt outside windows')
        previous = clocks
        event = row['event']
        protocol = 'tcp' if event == 'tcp_connected' else 'udp' if event in ('udp_bound', 'udp_sent') else 'none'
        local = 65100 + repeat if protocol == 'tcp' else 65200 + repeat if protocol == 'udp' else 0
        remote = 80 if protocol == 'tcp' else 65003 if protocol == 'udp' else 0
        frozen.require((row['protocol'], row['source_ip'], int(row['source_port']), row['destination_ip'],
                        int(row['destination_port'])) == (protocol, traffic.GUEST, local, traffic.SINK, remote),
                       'Application socket endpoint differs')
    frozen.require([row['value'] for row in rows if row['event'] == 'udp_sent'] == case['udp'][0]['payloads'],
                   'Application UDP markers differ')
    frozen.require(all(row['value'] == token for row in rows if row['event'] != 'udp_sent'), 'Application token differs')
    key, size = traffic.http_flow(parsed, case['http'][0], bounds)
    frozen.require((traffic.GUEST, 65100 + repeat) in key, 'HTTP source port differs')
    selected = [packet for packet in parsed if traffic.flow_key(packet) == key
                and any(start <= traffic.packet_ns(packet) < end for start, end in bounds)]
    saved = (run_dir / 'workspace' / case['response_file']).read_bytes()
    frozen.require(saved == traffic.tcp_bytes(selected, traffic.SINK), 'Saved HTTP bytes differ from capture')
    first, last = int(rows[0]['realtime_ns']), int(rows[-1]['realtime_ns'])
    for packet in parsed:
        address = traffic.direct_ip(packet)
        if address is not None and isinstance(address.payload, UDP) and int(address.payload.sport) == 65200 + repeat:
            frozen.require(first <= traffic.packet_ns(packet) <= last, 'UDP outside application lifetime')
    return {'pid': next(iter(pids)), 'http_body_bytes': size,
            'saved_response_sha256': hashlib.sha256(saved).hexdigest(), 'udp_datagrams': 6}


def prepare(destination):
    frozen.verify_production()
    frozen.require(frozen.digest(SOURCE) == SOURCE_SHA, 'Benign control source changed')
    frozen.require(frozen.digest(frozen.MATCHED / 'manifest.json') == frozen.MANIFEST_SHA256, 'Matched manifest changed')
    destination.mkdir(parents=True, exist_ok=False)
    binary = destination / 'attribution-control'
    command = ['cc', '-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', str(SOURCE), '-o', str(binary)]
    with (destination / 'build.log').open('x') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
    header = binary.read_bytes()[:64]
    frozen.require(header[:5] == b'\x7fELF\x02' and int.from_bytes(header[16:18], 'little') == 2
                   and int.from_bytes(header[18:20], 'little') == 62, 'Expected amd64 ET_EXEC')
    inspected = subprocess.run(['readelf', '-lW', '-dW', str(binary)], capture_output=True, text=True, check=True)
    frozen.require('INTERP' not in inspected.stdout and ' DYNAMIC ' not in inspected.stdout
                   and '(NEEDED)' not in inspected.stdout, 'Control is not static')
    source = frozen.load(frozen.MATCHED / 'manifest.json')
    selected = [case for case in frozen.select_cases(source) if case['label'] != 'malware']
    controls = network_cases(frozen.digest(binary))
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, 'w', compression=zipfile.ZIP_STORED) as archive:
        member = zipfile.ZipInfo('attribution-control', date_time=(2026, 10, 24, 0, 0, 0))
        member.external_attr = 0o100700 << 16
        archive.writestr(member, binary.read_bytes())
    transport = packed.getvalue()
    inherited = frozen.build_payload(selected)
    payload = destination / 'payload.tgz'
    with tarfile.open(fileobj=io.BytesIO(inherited), mode='r:gz') as old, tarfile.open(payload, 'w:gz') as archive:
        for member in old:
            frozen.safe_member(member)
            archive.addfile(member, old.extractfile(member) if member.isfile() else None)
        for case in controls:
            case['transport_sha256'] = hashlib.sha256(transport).hexdigest()
            for name, content in (('samples/' + case['sample'], transport),
                                  ('arguments/' + case['sample'] + '.json', json.dumps(case['collection_arguments']).encode())):
                member = tarfile.TarInfo(name)
                member.mode, member.size = 0o600, len(content)
                archive.addfile(member, io.BytesIO(content))
    cases = selected[:3] + selected[3:-3] + controls + selected[-3:]
    for position, case in enumerate(cases, 1):
        case['position'] = position
    frozen.require(len(cases) == 14 and all(case['label'] in ('benign', 'null') for case in cases), 'Benign-only budget differs')
    plan = {'cases': cases, 'guest_root': source['guest_root'], 'settings_required': {
        **source['settings_required'], 'telemetry_schema_version': frozen.SCHEMA,
        'malware_runner_sha256': frozen.PINNED['src/malware_runner.py']},
        'payload_sha256': frozen.digest(payload), 'binary_sha256': frozen.digest(binary),
        'source_sha256': SOURCE_SHA, 'builder_sha256': frozen.digest(__file__), 'build_command': command,
        'compiler_version': subprocess.run(['cc', '--version'], capture_output=True, text=True, check=True).stdout,
        'limitations': ['Two repeats of one diagnostic source are not independent software units',
                        'UDP send/capture is not UDP application acceptance', 'No host network workload executed'],
        'collection_ready': False, 'vm_operations': 0, 'model_fits': 0}
    frozen.save(destination / 'plan.json', plan)
    return plan


def self_test():
    with tempfile.TemporaryDirectory(prefix='hazim-quiet-network-test-') as directory:
        destination = Path(directory) / 'build'
        plan = prepare(destination)
        binary = destination / 'attribution-control'
        for repeat in (1, 2):
            subprocess.run([str(binary), 'file', 'local_check', str(repeat)], cwd=directory,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=5)
            frozen.require((Path(directory) / 'pilot-file.bin').read_bytes() == b'local_check\n' * 128,
                           'Benign host file outcome differs')
        rejected = subprocess.run([str(binary), 'net', 'final_net_r3', '3'], capture_output=True, timeout=5)
        frozen.require(rejected.returncode == 2, 'Unsupported repeat was accepted')
        with tarfile.open(destination / 'payload.tgz') as archive:
            names = archive.getnames()
            frozen.require(len(names) == len(set(names)), 'Duplicate payload members')
            for case in plan['cases']:
                frozen.require(hashlib.sha256(archive.extractfile('samples/' + case['sample']).read()).hexdigest()
                               == case['transport_sha256'], 'Transport hash differs')
    print('PASS actual static build, two local file outcomes, repeat3 rejection, fourteen benign-only transports; no VM/network workload')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--self-test', action='store_true')
    action.add_argument('--prepare', action='store_true')
    options = parser.parse_args()
    if options.self_test:
        self_test()
    else:
        output = ROOT / 'quiet-network-v2' / frozen.stamp()
        prepare(output)
        print(output)