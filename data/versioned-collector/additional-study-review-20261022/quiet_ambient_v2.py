"""Local quiet-v2 preparation and explicitly approved, one-attempt VM phases."""

import argparse
import ast
import base64
import fcntl
import hashlib
import json
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import collect_v19 as frozen
import quiet_network_v2 as network
import validate_quiet_v2 as traffic

ROOT = Path(__file__).resolve().parent
BASELINE_UUID = '7be3f5b4-ae96-419b-b9af-6a58ba6c5c3e'
ORIGINAL_UUID = '72de0a02-2e71-42b8-85e2-78c21d6b00f9'
POLICY = ROOT / 'quiet_guest_v2.sh'
BOOT_COUNT = 10
CAPTURE_SECONDS = 60
PREDECESSOR = {'configure': 'preflight', 'multiboot': 'configure', 'stage': 'multiboot',
               'dry-run': 'stage', 'benign': 'dry-run'}


def runtime_helper():
    module = frozen.helper()

    def bounded_vbox(*arguments, check=True, timeout=None):
        limit = 5 if arguments[:1] == ('controlvm',) and 'nictrace1' in arguments else 180
        if arguments[:1] == ('guestcontrol',) and '--timeout' in arguments:
            limit = min(limit, int(arguments[arguments.index('--timeout') + 1]) / 1000 + 5)
        if timeout is not None:
            limit = min(limit, timeout)
        return subprocess.run(['VBoxManage', *arguments], capture_output=True, text=True, check=check, timeout=limit)

    module.vbox = bounded_vbox
    return module


def control_script(marker):
    return """import base64,json,socket,time
from pathlib import Path
marker=%r
started=time.time_ns()
deadline=time.monotonic()+8
request=('GET '+marker+' HTTP/1.1\\r\\nHost: 10.0.0.1\\r\\nConnection: close\\r\\n\\r\\n').encode('ascii')
with socket.create_connection(('10.0.0.1',80),timeout=3) as connection:
    connection.sendall(request)
    response=bytearray()
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('HTTP absolute deadline')
        connection.settimeout(remaining)
        chunk=connection.recv(4096)
        if not chunk: break
        response.extend(chunk)
        if len(response)>65536: raise ValueError('HTTP response bound')
print(json.dumps({'path':marker,'started_wall_ns':started,'ended_wall_ns':time.time_ns(),
    'response_base64':base64.b64encode(response).decode('ascii'),
    'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'uptime_seconds':float(Path('/proc/uptime').read_text().split()[0])}))
""" % marker


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / 'protocol.json') == expected, 'Explicit protocol hash required')
    protocol = frozen.load(attempt / 'protocol.json')
    frozen.require(protocol['format'] == 'quiet-v2-multiboot-v1'
                   and protocol['boot_count'] == BOOT_COUNT and protocol['capture_seconds'] == CAPTURE_SECONDS
                   and protocol['production_hashes'] == frozen.PINNED, 'Protocol contract differs')
    frozen.verify_production()
    for name, checksum in protocol['source_hashes'].items():
        frozen.require(frozen.digest(name) == checksum, 'Frozen source changed: ' + name)
    for name, checksum in protocol['files'].items():
        frozen.require(frozen.digest(attempt / name) == checksum, 'Frozen prepared artifact changed: ' + name)
    return protocol


def freeze():
    frozen.verify_production()
    attempt = ROOT / 'quiet-ambient-v2' / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / 'controls')
    setup = frozen.setup_script(plan['guest_root'], (attempt / 'controls/payload.tgz').read_bytes())
    setup = setup.replace('18 frozen transports', '14 benign-only transports')
    subprocess.run(['bash', '-n'], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0])
    (attempt / 'setup_guest.sh').write_text(setup)
    (attempt / 'cases.txt').write_text(''.join(case['sample'] + '\n' for case in plan['cases']))
    sources = frozen.source_hashes()
    for name in (__file__, network.__file__, traffic.__file__, POLICY, ROOT / 'quiet_ambient.py',
                 ROOT / 'capture_liveness_v4.py', ROOT / 'export_original_sources.py'):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path)
             for path in attempt.rglob('*') if path.is_file()}
    protocol = {'format': 'quiet-v2-multiboot-v1', 'boot_count': BOOT_COUNT,
        'capture_seconds': CAPTURE_SECONDS, 'production_hashes': frozen.PINNED,
        'baseline': frozen.BASELINE, 'baseline_uuid': BASELINE_UUID, 'original_uuid': ORIGINAL_UUID,
        'new_snapshot': 'clean-final-quiet-v19-' + attempt.name,
        'staged_snapshot': 'clean-final-quiet-v19-payload-' + attempt.name,
        'guest_mac': traffic.GUEST_MAC, 'control_paths': ['/hazim-final/boot/' + attempt.name + '/' + str(index)
                                                       for index in range(1, BOOT_COUNT + 1)],
        'source_hashes': sources, 'files': files, 'approval': None, 'vm_steps_authorized': [],
        'collection_ready': False, 'retries': False, 'model_fits': 0, 'merge_with_v18': False,
        'future_batch_cases': plan['cases'],
        'criteria': ['Trace enabled before power-on; stop after sixty seconds from power-on request',
                     'Ten distinct boot IDs, each restored from the same policy child',
                     'One bounded numeric-Sink HTTP200 control per boot; exact saved response equals PCAP',
                     'All boot frames classified by strict allowlist; unexplained frames reject',
                     'Every case in the later benign batch must independently pass the strict validator'],
        'limitations': ['Hypervisor NIC tracing has no independent drop counter; not a completeness proof',
                        'Ten sixty-second boots do not exercise every later timer',
                        'Network controls repeat one diagnostic source; no independent software diversity claim',
                        'No VM phase, batch, malware, fit or merge is authorized by preparation']}
    frozen.save(attempt / 'protocol.json', protocol)
    print(json.dumps({'attempt': str(attempt), 'protocol_sha256': frozen.digest(attempt / 'protocol.json'),
                      'vm_steps_authorized': [], 'collection_ready': False}, indent=2))
    return attempt


def trace_state(info):
    frozen.require('nictrace1' in info and 'nictracefile1' in info, 'NIC trace state unavailable')
    return {key: info[key].strip('"') for key in ('nictrace1', 'nictracefile1')}


def preflight(module):
    before = frozen.preflight(module)
    frozen.require(before['baseline_uuid'] == BASELINE_UUID and before['original_uuid'] == ORIGINAL_UUID,
                   'Snapshot identity changed')
    info = before['states']['guest']
    mac = info.get('macaddress1', '').strip('"').lower()
    frozen.require(mac == traffic.GUEST_MAC.replace(':', ''), 'Actual guest MAC differs from policy pin')
    before['trace'] = trace_state(info)
    frozen.require(before['trace']['nictrace1'] == 'off', 'Existing NIC trace; do not disturb another capture')
    return before


def cleanup(module, destination, original_trace):
    errors = []
    try:
        if module.vm_info(module.VM)['VMState'] != '"poweroff"':
            module.vbox('controlvm', module.VM, 'poweroff')
        module.vbox('snapshot', module.VM, 'restore', module.ORIGINAL)
    except Exception as error:
        errors.append(type(error).__name__ + ': ' + str(error))
    try:
        module.vbox('modifyvm', module.VM, '--nictrace1', original_trace['nictrace1'],
                    '--nictracefile1', original_trace['nictracefile1'])
        states = frozen.state_check(module)
        frozen.require(frozen.snapshot_uuid(module, module.ORIGINAL) == ORIGINAL_UUID, 'Cleanup snapshot UUID differs')
        frozen.require(trace_state(states['guest']) == original_trace, 'NIC trace configuration not restored')
        frozen.save(destination / 'final_vm_state.json', states)
    except Exception as error:
        errors.append(type(error).__name__ + ': ' + str(error))
    frozen.require(not errors, 'Cleanup failed; user action required: ' + '; '.join(errors))


def configure(module, attempt, protocol, destination, auth, password_file):
    from quiet_ambient import Guest
    listing = module.vbox('snapshot', module.VM, 'list', '--machinereadable').stdout
    frozen.require('"' + protocol['new_snapshot'] + '"' not in listing, 'Quiet child already exists; no retry')
    guest = Guest(module, destination)
    guest.boot(frozen.BASELINE, 'configure-boot', auth)
    guest_root = '/home/' + module.GUEST_USER + '/hazim-quiet-v2-' + attempt.name
    guest.stage_credential(auth, password_file, guest_root)
    module.vbox('guestcontrol', module.VM, 'copyto', *auth, str(POLICY), guest_root + '/quiet_guest_v2.sh')
    response = guest.run(auth, '/bin/bash', '-c',
                         "sudo -S -p '' /bin/bash %s/quiet_guest_v2.sh < %s/.auth" % (guest_root, guest_root), timeout=300)
    (destination / 'policy.log').write_text(response.stdout + response.stderr)
    frozen.require(response.returncode == 0, 'Quiet-v2 policy failed; preserve failure, no retry')
    receipt = json.loads(response.stdout.strip().splitlines()[-1])
    frozen.require(receipt['policy'] == 'quiet-v2', 'Policy receipt differs')
    frozen.save(destination / 'policy-receipt.json', receipt)
    frozen.require(guest.run(auth, '/bin/rm', '-rf', '--', guest_root).returncode == 0, 'Setup removal failed')
    frozen.require(guest.run(auth, '/usr/bin/test', '-e', guest_root).returncode == 1, 'Setup/credential still present')
    frozen.require(guest.run(auth, '/bin/sync').returncode == 0, 'Guest sync failed')
    frozen.require(guest.poweroff(graceful=True) == 'graceful', 'Graceful shutdown failed; no snapshot created')
    module.vbox('snapshot', module.VM, 'take', protocol['new_snapshot'], '--description',
                'Quiet-v2 child of ' + BASELINE_UUID + '; policy receipt ' + frozen.digest(destination / 'policy-receipt.json'))
    return {'snapshot_uuid': frozen.snapshot_uuid(module, protocol['new_snapshot']),
            'policy_receipt_sha256': frozen.digest(destination / 'policy-receipt.json')}


def audit_boot(directory, marker):
    receipt = frozen.load(directory / 'control.json')
    trace = frozen.load(directory / 'trace.json')
    frozen.require(trace['enabled_before_start'] is True and trace['stop_returncode'] == 0,
                   'Capture was not enabled before power-on or did not stop successfully')
    duration = trace['stop_requested_ns'] - trace['power_requested_ns']
    frozen.require(CAPTURE_SECONDS * 1_000_000_000 <= duration <= (CAPTURE_SECONDS + 2) * 1_000_000_000,
                   'Boot trace interval differs from sixty-second contract')
    frozen.require(trace['stop_ended_ns'] - trace['stop_requested_ns'] <= 5_000_000_000,
                   'Trace stop command exceeded five seconds')
    frozen.require(receipt['path'] == marker and receipt['boot_id']
                   and 0 < receipt['uptime_seconds'] < CAPTURE_SECONDS, 'Boot control identity/lifetime differs')
    content = (directory / 'boot.pcap').read_bytes()
    parsed = traffic.packets(content)
    frozen.require(parsed, 'Empty boot capture')
    all_time = [(0, 2 ** 63 - 1)]
    classified = traffic.classify(parsed, all_time, http=[{'path': marker}])
    frozen.require(classified['accepted'], 'Unexplained boot traffic: ' + str(classified['reasons']))
    key, size = traffic.http_flow(parsed, {'path': marker}, all_time)
    selected = [packet for packet in parsed if traffic.flow_key(packet) == key]
    frozen.require(all(receipt['started_wall_ns'] - 1_000_000_000 <= traffic.packet_ns(packet)
                       <= receipt['ended_wall_ns'] + 1_000_000_000 for packet in selected),
                   'Marked HTTP stream outside application receipt')
    saved = base64.b64decode(receipt['response_base64'], validate=True)
    frozen.require(saved == traffic.tcp_bytes(selected, traffic.SINK), 'Boot saved response differs from capture')
    return {'status': 'accepted', 'boot_id': receipt['boot_id'], 'pcap_sha256': hashlib.sha256(content).hexdigest(),
            'pcap_frames': len(parsed), 'http_body_bytes': size, 'traffic': classified,
            'limitation': 'NIC trace has no independent drop counter and does not prove continuous completeness'}


def wait_boot_guest(module, auth, directory, deadline_ns):
    receipt = {'events': [], 'deadline_ns': deadline_ns, 'status': 'rejected'}
    try:
        commands = [('startvm', module.VM, '--type', 'headless')]
        for index in range(3):
            commands.append(('guestcontrol', module.VM, 'run', *auth, '--exe', '/bin/true',
                             '--wait-stdout', '--wait-stderr', '--timeout', '5000', '--'))
            while commands:
                command = commands.pop(0)
                remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
                frozen.require(remaining > 0, 'Boot readiness deadline exhausted')
                budget = min(5, remaining)
                try:
                    response = module.vbox(*command, check=False, timeout=budget)
                    code = response.returncode
                except subprocess.TimeoutExpired:
                    code = None
                receipt['events'].append({'operation': command[0], 'returncode': code,
                                          'ended_ns': time.monotonic_ns(), 'budget_seconds': budget})
                frozen.require(time.monotonic_ns() <= deadline_ns, 'Boot readiness command exceeded deadline')
                if command[0] == 'startvm':
                    frozen.require(code == 0, 'Boot power-on failed')
                elif code == 0:
                    receipt['status'] = 'accepted_authenticated_probe'
                    return
            if index < 2:
                budget = min(15, (deadline_ns - time.monotonic_ns()) / 1_000_000_000 - 5)
                if budget > 0:
                    try:
                        module.vbox('guestproperty', 'wait', module.VM, '/VirtualBox/GuestInfo/OS/LoggedInUsers',
                                    '--timeout', str(int(budget * 1000)), '--fail-on-timeout', check=False, timeout=budget)
                    except subprocess.TimeoutExpired:
                        pass
        raise ValueError('Three authenticated boot readiness probes failed; no retry')
    finally:
        frozen.save(directory / 'startup-readiness.json', receipt)


def boot_once(module, protocol, destination, index, auth):
    from quiet_ambient import Guest

    directory = destination / ('boot-%02d' % index)
    directory.mkdir()
    module.vbox('snapshot', module.VM, 'restore', protocol['new_snapshot'])
    module.isolated(module.VM)
    module.vbox('modifyvm', module.VM, '--nictracefile1', str(directory / 'boot.pcap'), '--nictrace1', 'on')
    trace = {'enabled_before_start': trace_state(module.vm_info(module.VM)) == {
        'nictrace1': 'on', 'nictracefile1': str(directory / 'boot.pcap')}}
    frozen.require(trace['enabled_before_start'], 'NIC trace configuration was not confirmed')
    finished = threading.Event()
    failures = []

    def stop_trace():
        try:
            trace['stop_requested_ns'] = time.monotonic_ns()
            stopped = module.vbox('controlvm', module.VM, 'nictrace1', 'off', check=False)
            trace['stop_returncode'] = stopped.returncode
            trace['stop_ended_ns'] = time.monotonic_ns()
        except Exception as error:
            failures.append(type(error).__name__ + ': ' + str(error))
        finally:
            finished.set()

    trace['power_requested_ns'] = time.monotonic_ns()
    timer = threading.Timer(CAPTURE_SECONDS, stop_trace)
    timer.start()
    try:
        wait_boot_guest(module, auth, directory, trace['power_requested_ns'] + 48_000_000_000)
        frozen.require(time.monotonic_ns() < trace['power_requested_ns'] + 48_000_000_000,
                       'No time for bounded positive control inside boot capture')
        guest = Guest(module, destination)
        response = guest.run(auth, '/usr/bin/python3', '-c', control_script(protocol['control_paths'][index - 1]), timeout=10)
        (directory / 'control.log').write_text(response.stdout + response.stderr)
        frozen.require(response.returncode == 0, 'Boot positive control failed')
        frozen.save(directory / 'control.json', json.loads(response.stdout.strip()))
        frozen.require(finished.wait(timeout=CAPTURE_SECONDS), 'Boot trace stop did not finish')
        frozen.require(not failures and trace.get('stop_returncode') == 0, 'Trace stop failed: ' + str(failures))
    finally:
        timer.cancel()
        timer.join(timeout=6)
        frozen.require(not timer.is_alive(), 'Trace stop thread did not finish; cleanup required')
        frozen.save(directory / 'trace.json', trace)
    module.vbox('controlvm', module.VM, 'poweroff')
    module.vbox('modifyvm', module.VM, '--nictrace1', 'off')
    result = audit_boot(directory, protocol['control_paths'][index - 1])
    frozen.save(directory / 'audit.json', result)
    return result


def multiboot(module, attempt, protocol, destination, auth):
    configured = frozen.load(attempt / 'phases/configure/result.json')
    frozen.require(frozen.snapshot_uuid(module, protocol['new_snapshot']) == configured['snapshot_uuid'],
                   'Quiet child UUID differs')
    results, ids = [], set()
    for index in range(1, BOOT_COUNT + 1):
        try:
            result = boot_once(module, protocol, destination, index, auth)
            frozen.require(result['boot_id'] not in ids, 'Repeated boot ID; not an independent boot')
        except BaseException as error:
            results.append({'status': 'excluded', 'position': index, 'technical_error': type(error).__name__ + ': ' + str(error)})
            frozen.save(destination / 'failed-prefix.json', results)
            raise
        ids.add(result['boot_id'])
        results.append(result)
    return {'boot_count': len(results), 'boot_ids': sorted(ids), 'all_boots_accepted': True,
            'collection_ready': False, 'next_gate': 'Separately approved installed-.19 staging, dry-run and benign batch'}


def audit_batch(attempt, protocol):
    plan = frozen.load(attempt / 'controls/plan.json')
    tools = frozen.validation_tools()
    rows = []
    for case in plan['cases']:
        result = traffic.audit_case(attempt / 'runs' / case['sample'], case, plan['settings_required'], tools)
        rows.append({'sample': case['sample'], 'label': case['label'], 'mode': case['mode'], **result})
    verdict = traffic.batch_environment(rows)
    frozen.require(len(rows) == 14 and sum(row['label'] == 'null' for row in rows) == 6, 'Batch case budget differs')
    report = {'results': rows, **verdict, 'protocol_sha256': frozen.digest(attempt / 'protocol.json'),
              'collection_ready': False, 'model_fits': 0, 'merged_cases': 0,
              'validator_sha256': frozen.digest(traffic.__file__),
              'status': 'saved_benign_batch_audited_not_final_environment'}
    frozen.save(attempt / ('batch-audit-' + frozen.stamp() + '.json'), report)
    return report


def batch_phase(module, attempt, protocol, destination, phase):
    configured = frozen.load(attempt / 'phases/configure/result.json')
    frozen.require(frozen.snapshot_uuid(module, protocol['new_snapshot']) == configured['snapshot_uuid'],
                   'Policy child UUID differs')
    plan = frozen.load(attempt / 'controls/plan.json')
    if phase == 'stage':
        listing = module.vbox('snapshot', module.VM, 'list', '--machinereadable').stdout
        frozen.require('"' + protocol['staged_snapshot'] + '"' not in listing, 'Payload child exists; no restage')
        command = ['bash', str(frozen.STUDY / 'scripts/stage_versioned_runner_snapshot.sh'),
            '--vm', module.VM, '--guest-user', module.GUEST_USER, '--baseline-snapshot', protocol['new_snapshot'],
            '--new-snapshot', protocol['staged_snapshot'], '--schema-version', frozen.SCHEMA,
            '--guest-setup', str(attempt / 'setup_guest.sh')]
    else:
        staged = frozen.load(attempt / 'phases/stage/result.json')
        frozen.require(frozen.snapshot_uuid(module, protocol['staged_snapshot']) == staged['snapshot_uuid'],
                       'Staged payload child UUID differs')
        frozen.require(not (attempt / ('dry-run' if phase == 'dry-run' else 'runs')).exists(), 'Output exists; no repeat')
        command = frozen.batch_command(module, attempt,
            {'guest_root': plan['guest_root'], 'new_snapshot': protocol['staged_snapshot']}, phase == 'dry-run')
    frozen.save(destination / 'command.json', command)
    frozen.run_logged(command, destination / 'command.log', 900 if phase == 'stage' else 5400)
    if phase == 'stage':
        return {'snapshot_uuid': frozen.snapshot_uuid(module, protocol['staged_snapshot'])}
    if phase == 'dry-run':
        return {'validated_transports': frozen.validate_dry_run(destination / 'command.log', plan)}
    report = audit_batch(attempt, protocol)
    frozen.require(report['all_cases_accepted'] and report['environment_valid'],
                   'Benign batch failed strict acceptance; preserve all exclusions, no retry')
    return {'all_cases_accepted': True, 'environment_valid': True, 'collection_ready': False,
            'next_gate': 'Independent final evidence review before final environment designation'}


def perform_phase(attempt, phase, expected, approval):
    frozen.require(approval and approval.strip(), 'Verbatim user approval required for every VM phase')
    protocol = verify_plan(attempt, expected)
    frozen.require(phase in ('preflight', *PREDECESSOR), 'Unknown phase')
    module = runtime_helper()
    with (Path(module.__file__).parent / 'readiness.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if phase in PREDECESSOR:
            prior = frozen.load(attempt / 'phases' / PREDECESSOR[phase] / 'result.json')
            frozen.require(prior['status'] == 'passed' and prior['protocol_sha256'] == expected, 'Previous phase not accepted')
        destination = attempt / 'phases' / phase
        destination.mkdir(parents=True, exist_ok=False)
        frozen.save(destination / 'authorization.json', {'phase': phase, 'approval': approval,
                    'protocol_sha256': expected, 'cleanup_authorized': phase != 'preflight', 'one_attempt_only': True})
        result = {'phase': phase, 'protocol_sha256': expected, 'status': 'failed_preserved', 'collection_ready': False}
        before, touched = None, False

        def interrupted(_signal, _frame):
            raise KeyboardInterrupt('Preserve failure and restore original TLS/off plus NIC trace state')

        previous_handler = signal.signal(signal.SIGTERM, interrupted)
        try:
            before = preflight(module)
            frozen.save(destination / 'initial_vm_state.json', before)
            if phase in ('stage', 'dry-run', 'benign'):
                touched = True
                result.update(batch_phase(module, attempt, protocol, destination, phase))
            elif phase != 'preflight':
                touched = True
                with tempfile.NamedTemporaryFile(mode='w', prefix='hazim-quiet-v2-auth-') as password:
                    Path(password.name).chmod(0o600)
                    password.write(module.credentials())
                    password.flush()
                    auth = ['--username', module.GUEST_USER, '--passwordfile', password.name]
                    if phase == 'configure':
                        result.update(configure(module, attempt, protocol, destination, auth, password.name))
                    else:
                        result.update(multiboot(module, attempt, protocol, destination, auth))
            verify_plan(attempt, expected)
            result['status'] = 'passed'
        except BaseException as error:
            result['error'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            try:
                if touched:
                    cleanup(module, destination, before['trace'])
            except BaseException as error:
                result.update(status='cleanup_failed_requires_user', cleanup_error=type(error).__name__ + ': ' + str(error))
                raise
            finally:
                frozen.save(destination / 'result.json', result)
                signal.signal(signal.SIGTERM, previous_handler)
        print(json.dumps(result, indent=2))


def self_test():
    ast.parse(control_script('/hazim-final/test'))
    subprocess.run(['bash', '-n', str(POLICY)], check=True)
    calls = []
    module = SimpleNamespace()
    def fake_boot(_module, _protocol, destination, index, _auth):
        calls.append(index)
        return {'boot_id': str(index), 'status': 'accepted'}
    with tempfile.TemporaryDirectory() as directory:
        attempt = Path(directory)
        (attempt / 'phases/configure').mkdir(parents=True)
        frozen.save(attempt / 'phases/configure/result.json', {'snapshot_uuid': 'child'})
        with patch.object(frozen, 'snapshot_uuid', return_value='child'), patch(__name__ + '.boot_once', side_effect=fake_boot):
            result = multiboot(module, attempt, {'new_snapshot': 'child'}, attempt, [])
            frozen.require(result['boot_count'] == 10 and calls == list(range(1, 11)), 'Ten-boot design differs')
        calls.clear()
        def fail_boot(*arguments):
            index = arguments[3]
            calls.append(index)
            if index == 3:
                raise ValueError('Injected boot contamination')
            return {'boot_id': str(index)}
        with patch.object(frozen, 'snapshot_uuid', return_value='child'), patch(__name__ + '.boot_once', side_effect=fail_boot):
            try:
                multiboot(module, attempt, {'new_snapshot': 'child'}, attempt, [])
                raise AssertionError('Contaminated boot accepted')
            except ValueError:
                frozen.require(calls == [1, 2, 3], 'Retry or later boot after failure')
    try:
        perform_phase(Path('/unused'), 'preflight', 'unused', '')
        raise AssertionError('VM phase without approval accepted')
    except ValueError as error:
        frozen.require('approval' in str(error), 'Unexpected missing-approval failure')
    print('PASS generated policy/control syntax, simulated ten boots, stop-first-failure and approval guard; no VM query')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--self-test', action='store_true')
    action.add_argument('--freeze-only', action='store_true')
    action.add_argument('--audit-batch', action='store_true')
    action.add_argument('--phase', choices=('preflight', *PREDECESSOR))
    parser.add_argument('--attempt', type=Path)
    parser.add_argument('--protocol-sha256')
    parser.add_argument('--approval')
    options = parser.parse_args()
    if options.self_test:
        self_test()
    elif options.freeze_only:
        freeze()
    elif options.audit_batch:
        frozen.require(options.attempt is not None, 'Frozen attempt required')
        protocol = verify_plan(options.attempt.resolve(), options.protocol_sha256)
        audit_batch(options.attempt.resolve(), protocol)
    else:
        frozen.require(options.attempt is not None, 'Frozen attempt required')
        perform_phase(options.attempt.resolve(), options.phase, options.protocol_sha256, options.approval)