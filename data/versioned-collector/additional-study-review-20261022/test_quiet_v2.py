"""Offline tests only; never configure the host or query a VM."""

import ast
import base64
import copy
import csv
import subprocess
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

import validate_quiet_v2 as audit


class TrafficTests(unittest.TestCase):
    def packet(self, payload, timestamp=150):
        packet = Ether(src=audit.GUEST_MAC, dst='00:11:22:33:44:55') / payload
        packet.time = Decimal(timestamp) / 1_000_000_000
        return packet

    def http(self, path='/hazim-final/test', timestamp=150):
        return [self.packet(IP(src=audit.GUEST, dst=audit.SINK) / TCP(sport=45000, dport=80, seq=100)
                            / ('GET ' + path + ' HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n').encode(), timestamp),
                self.packet(IP(src=audit.SINK, dst=audit.GUEST) / TCP(sport=80, dport=45000, seq=200)
                            / b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK', timestamp)]

    def test_marked_http_and_missing_wrong_outside_guards(self):
        declaration = [{'path': '/hazim-final/test'}]
        self.assertTrue(audit.classify(self.http(), [(100, 200)], http=declaration)['accepted'])
        for packets in ([], self.http('/wrong'), self.http(timestamp=250), self.http()[:1]):
            result = audit.classify(packets, [(100, 200)], http=declaration)
            self.assertFalse(result['accepted'])
            self.assertTrue(any(reason.startswith('declared_http_not_recovered:') for reason in result['reasons']))

    def test_exact_probe_tuple_time_and_payload(self):
        probe = [{'phase': 'pre', 'local_port': 40001, 'low_ns': 10, 'high_ns': 90}]
        good = self.packet(IP(src=audit.GUEST, dst=audit.SINK) / TCP(sport=40001, dport=80), 50)
        result = audit.classify([good], [(100, 200)], probe)
        self.assertEqual(result['frames'][0]['category'], 'capture_probe:pre')
        for source, timestamp, payload in ((audit.GUEST, 150, b''), ('10.0.0.12', 50, b''), (audit.GUEST, 50, b'bad')):
            packet = self.packet(IP(src=source, dst=audit.SINK) / TCP(sport=40001, dport=80) / payload, timestamp)
            self.assertEqual(audit.classify([packet], [(100, 200)], probe)['frames'][0]['category'], 'unexplained')

    def test_udp_markers_are_exact_and_counted(self):
        payloads = ['HAZIM_ATTR_final_1_%03d' % sequence for sequence in range(6)]
        declaration = [{'sport': 65201, 'payloads': payloads}]
        packets = [self.packet(IP(src=audit.GUEST, dst=audit.SINK) / UDP(sport=65201, dport=65003)
                               / payload.encode()) for payload in payloads]
        self.assertTrue(audit.classify(packets, [(100, 200)], udp=declaration)['accepted'])
        for altered in (packets[:-1], packets + packets[:1]):
            self.assertFalse(audit.classify(altered, [(100, 200)], udp=declaration)['accepted'])

    def test_self_announcement_is_mac_count_and_time_bound(self):
        def announcement(timestamp, mac=audit.GUEST_MAC, address=audit.GUEST):
            packet = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(
                hwsrc=mac, hwdst='00:00:00:00:00:00', psrc=address, pdst=address, op=1)
            packet.time = Decimal(timestamp) / 1_000_000_000
            return packet
        bounds = [(1, 10_000_000_000)]
        first = announcement(100)
        second = announcement(2_000_000_100)
        for selected in ([first], [first, second]):
            self.assertTrue(audit.classify(selected, bounds)['accepted'])
        for selected in ([announcement(100, '00:11:22:33:44:55')],
                         [announcement(100, address='10.0.0.12')],
                         [first, second, announcement(4_000_000_100)],
                         [first, announcement(1_000_000_100)],
                         [first, announcement(3_000_000_100)]):
            self.assertFalse(audit.classify(selected, bounds)['accepted'])
        self.assertFalse(audit.classify([first], bounds, guest_mac='00:11:22:33:44:55')['accepted'])

    def test_entire_case_pipeline_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            result = audit.audit_case(Path(directory), {}, {}, tools=(None, None, None, None))
        self.assertEqual(result['status'], 'excluded')
        self.assertIn('Missing or ambiguous metadata', result['technical_error'])
        for error in (ValueError('bad capture'), OSError('unreadable'), RuntimeError('bad probe')):
            with patch.object(audit, '_audit_case', side_effect=error):
                result = audit.audit_case(Path('/unused'), {}, {})
            self.assertEqual(result['status'], 'excluded')
            self.assertIn(str(error), result['technical_error'])
        with patch.object(audit, '_audit_case', side_effect=KeyboardInterrupt):
            self.assertRaises(KeyboardInterrupt, audit.audit_case, Path('/unused'), {}, {})

    def test_network_application_receipt_matches_capture(self):
        import quiet_network_v2 as network
        case = network.network_cases('0' * 64)[0]
        parsed = self.http(case['http'][0]['path'])
        parsed[0][TCP].sport = 65101
        parsed[1][TCP].dport = 65101
        fields = 'event,pid,protocol,source_ip,source_port,destination_ip,destination_port,value,realtime_ns,monotonic_ns'.split(',')
        events = [('start', 'none', 0, 0, 'final_net_r1'), ('tcp_connected', 'tcp', 65101, 80, 'final_net_r1'),
                  ('udp_bound', 'udp', 65201, 65003, 'final_net_r1')]
        events += [('udp_sent', 'udp', 65201, 65003, value) for value in case['udp'][0]['payloads']]
        events += [('done', 'none', 0, 0, 'final_net_r1')]
        rows = [dict(zip(fields, [event, 1234, protocol, audit.GUEST, local, audit.SINK, remote, value, 150, 50]))
                for event, protocol, local, remote, value in events]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'workspace').mkdir()
            response = root / 'workspace/pilot-http-response.bin'
            response.write_bytes(bytes(parsed[1][TCP].payload))
            (root / 'exec_events.csv').write_text('event,pid,detail\nexec_success,1234,filename=/target\n')
            def publish(selected):
                with (root / 'sample.stdout.log').open('w', newline='') as stream:
                    writer = csv.DictWriter(stream, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(selected)
            publish(rows)
            metadata = {'target_exec': {'expected_path': '/target'}}
            self.assertEqual(network.check_receipt(case, root, parsed, [(100, 200)], metadata)['pid'], 1234)
            for field, value in [('pid', 5678), ('source_port', 9), ('value', 'wrong'), ('realtime_ns', 250)]:
                altered = copy.deepcopy(rows)
                altered[1][field] = value
                publish(altered)
                with self.assertRaises(ValueError):
                    network.check_receipt(case, root, parsed, [(100, 200)], metadata)
            publish(rows)
            response.write_bytes(b'unrelated response')
            with self.assertRaises(ValueError):
                network.check_receipt(case, root, parsed, [(100, 200)], metadata)

    def test_historical_and_inherited_negative_gates(self):
        results = audit.historical_test()
        frozen = audit.frozen
        attempt = audit.ROOT / 'v19-small-collection/20261024T091843893614Z'
        protocol = frozen.load(attempt / 'protocol.json')
        case = next(case for case in protocol['cases'] if case['sample'].endswith('coreutils-ginstall.zip'))
        sample = attempt / 'runs' / case['sample']
        original = frozen.load(next(sample.glob('output/*/run.json')))
        tools = frozen.validation_tools()
        for field, value in [('collection_quality_status', 'rejected'), ('ebpf_lost_event_count', 1),
                             ('packet_capture_counter_discrepancy', 1), ('return_code', 2),
                             ('malware_runner_sha256', '0' * 64)]:
            altered = copy.deepcopy(original)
            altered[field] = value
            with self.subTest(field=field), patch.object(frozen, 'load', side_effect=lambda path:
                    altered if str(path).endswith('/run.json') else json_load(path)):
                result = audit.audit_case(sample, case, protocol['settings_required'], tools)
                self.assertEqual(result['status'], 'excluded')
                self.assertIn('technical_error', result)
                self.assertIn('traffic', result)
        self.assertFalse(audit.batch_environment(results)['environment_valid'])
        self.assertFalse(audit.batch_environment([{'label': 'null', 'sample': 'missing', 'status': 'excluded'}])['environment_valid'])

    def test_guest_policy_syntax_and_scope(self):
        script = audit.ROOT / 'quiet_guest_v2.sh'
        subprocess.run(['bash', '-n', str(script)], check=True)
        text = script.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        ast.parse(text)
        self.assertIn("'refresh', '--hold=forever'", text)
        self.assertIn("any(value != '0' for value in values.values())", text)
        self.assertNotIn('shell=True', text)

    def test_boot_audit_requires_control_and_rejects_all_residuals(self):
        import quiet_ambient_v2 as driver
        marker = '/hazim-final/test'
        parsed = self.http(marker)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit.frozen.save(root / 'control.json', {'path': marker, 'boot_id': 'fresh-boot', 'uptime_seconds': 20,
                'started_wall_ns': 100, 'ended_wall_ns': 200,
                'response_base64': base64.b64encode(bytes(parsed[1][TCP].payload)).decode()})
            trace = {'enabled_before_start': True, 'power_requested_ns': 1,
                     'stop_requested_ns': 60_000_000_001, 'stop_ended_ns': 60_000_000_002, 'stop_returncode': 0}
            audit.frozen.save(root / 'trace.json', trace)
            wrpcap(str(root / 'boot.pcap'), parsed, nano=True)
            self.assertEqual(driver.audit_boot(root, marker)['status'], 'accepted')
            with patch.object(audit.frozen, 'load', side_effect=lambda path:
                    {**trace, 'enabled_before_start': False} if path.name == 'trace.json' else json_load(path)):
                with self.assertRaises(ValueError):
                    driver.audit_boot(root, marker)
            for altered in (parsed[:1], parsed + [self.packet(IP(src=audit.GUEST, dst=audit.SINK)
                                                               / UDP(sport=40000, dport=53) / b'unknown', 10)]):
                wrpcap(str(root / 'boot.pcap'), altered, nano=True)
                with self.assertRaises(ValueError):
                    driver.audit_boot(root, marker)

    def test_driver_interruption_cleans_up_and_consumes_phase(self):
        import quiet_ambient_v2 as driver
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'phases/preflight').mkdir(parents=True)
            audit.frozen.save(root / 'phases/preflight/result.json', {'status': 'passed', 'protocol_sha256': 'pinned'})
            module = SimpleNamespace(__file__=str(root / 'helper.py'), GUEST_USER='csci', credentials=lambda: 'test-only')
            before = {'trace': {'nictrace1': 'off', 'nictracefile1': ''}}
            with patch.object(driver, 'verify_plan', return_value={}), patch.object(driver, 'runtime_helper', return_value=module), \
                    patch.object(driver, 'preflight', return_value=before), \
                    patch.object(driver, 'configure', side_effect=KeyboardInterrupt('injected')), \
                    patch.object(driver, 'cleanup') as cleanup:
                with self.assertRaises(KeyboardInterrupt):
                    driver.perform_phase(root, 'configure', 'pinned', 'Local simulated approval only')
                cleanup.assert_called_once_with(module, root / 'phases/configure', before['trace'])
                result = json_load(root / 'phases/configure/result.json')
                self.assertEqual(result['status'], 'failed_preserved')
                self.assertIn('KeyboardInterrupt', result['error'])
                with self.assertRaises(FileExistsError):
                    driver.perform_phase(root, 'configure', 'pinned', 'No repeated phase')

    def test_bounded_boot_startup_and_stop_first_failure(self):
        import quiet_ambient_v2 as driver
        driver.self_test()
        for succeeds in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                now = [0]
                calls = []
                def invoke(*command, **keywords):
                    calls.append(command[0])
                    now[0] += 1_000_000_000
                    return SimpleNamespace(returncode=0 if command[0] == 'startvm' or succeeds else 1)
                module = SimpleNamespace(VM='simulated-only', vbox=invoke)
                with patch.object(driver.time, 'monotonic_ns', side_effect=lambda: now[0]):
                    if succeeds:
                        driver.wait_boot_guest(module, [], root, 48_000_000_000)
                    else:
                        with self.assertRaises(ValueError):
                            driver.wait_boot_guest(module, [], root, 48_000_000_000)
                self.assertEqual(calls.count('startvm'), 1)
                self.assertEqual(calls.count('guestcontrol'), 1 if succeeds else 3)
                self.assertEqual(json_load(root / 'startup-readiness.json')['status'],
                                 'accepted_authenticated_probe' if succeeds else 'rejected')

    def test_boot_trace_brackets_start_and_stops_before_audit(self):
        import quiet_ambient_v2 as driver
        calls = []
        timer = SimpleNamespace(start=lambda: calls.append('timer_start'), cancel=lambda: None,
                                join=lambda timeout: None, is_alive=lambda: False)
        def make_timer(seconds, callback):
            self.assertEqual(seconds, 60)
            timer.callback = callback
            return timer
        def invoke(*command, **keywords):
            calls.append(command)
            return SimpleNamespace(returncode=0)
        def control(*arguments, **keywords):
            timer.callback()
            return SimpleNamespace(returncode=0, stdout='{}', stderr='')
        module = SimpleNamespace(VM='simulated-only', vbox=invoke, isolated=lambda name: {},
            vm_info=lambda name: {'nictrace1': '"on"', 'nictracefile1': '"' + str(root / 'boot-01/boot.pcap') + '"'})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(driver.threading, 'Timer', side_effect=make_timer), \
                    patch.object(driver.time, 'monotonic_ns', side_effect=[0, 1, 60_000_000_000, 60_000_000_001]), \
                    patch.object(driver, 'wait_boot_guest') as startup, \
                    patch('quiet_ambient.Guest', return_value=SimpleNamespace(run=control)), \
                    patch.object(driver, 'audit_boot', return_value={'status': 'accepted'}) as auditor:
                result = driver.boot_once(module, {'new_snapshot': 'child', 'control_paths': ['/hazim-final/test']}, root, 1, [])
            self.assertEqual(result['status'], 'accepted')
            startup.assert_called_once()
            auditor.assert_called_once()
            self.assertIn('--nictrace1', calls[1])
            self.assertEqual(calls[2], 'timer_start')
            self.assertEqual(calls[3], ('controlvm', 'simulated-only', 'nictrace1', 'off'))
            trace = json_load(root / 'boot-01/trace.json')
            self.assertEqual(trace['stop_requested_ns'] - trace['power_requested_ns'], 60_000_000_000)


def json_load(path):
    import json
    return json.loads(path.read_text())


if __name__ == '__main__':
    unittest.main()