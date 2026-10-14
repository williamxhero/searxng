# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline public-contract tests; no SearXNG imports or production state."""

import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import time
from unittest.mock import patch
import subprocess
import sys
import tempfile
import unittest


WORKSPACE = Path(__file__).resolve().parents[2]


class ImportTest(unittest.TestCase):
    def test_import_has_no_settings_network_or_storage_side_effects(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            script = '''
import importlib.abc
import pathlib
import socket
import sys
class NoSearx(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'searx' or fullname.startswith('searx.'):
            raise AssertionError('core imported SearXNG')
sys.meta_path.insert(0, NoSearx())
def denied(*args, **kwargs):
    raise AssertionError('core attempted network')
socket.socket = denied
import wag_protection
assert wag_protection.CONTRACT == 'wag.outbound.v2'
assert wag_protection.VERSION == 2
assert not list(pathlib.Path(sys.argv[1]).iterdir())
'''
            env = {**os.environ, 'PYTHONPATH': str(WORKSPACE), 'PYTHONDONTWRITEBYTECODE': '1'}
            child = subprocess.run(
                [sys.executable, '-S', '-c', script, root],
                cwd=root, env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def registry():
    return [
        {
            'engine': name, 'domestic': domestic, 'module': module,
            'capability': 'online_one_send',
            'source_digest': hashlib.sha256((WORKSPACE / f'searx/engines/{module}.py').read_bytes()).hexdigest(),
            'aliases': [name], 'profile': {'live_hold': False, 'settings': {
                'quark': {'quark_category': 'general'}, 'yandex': {'search_type': 'web'},
                'chinaso news': {'chinaso_news_source': 'all'}, 'bing': {},
            }[name]},
        }
        for name, domestic, module in [
            ('bing', False, 'bing'), ('chinaso news', True, 'chinaso'),
            ('quark', True, 'quark'), ('yandex', False, 'yandex'),
        ]
    ]


def fixture_manifest(root, engines):
    files = {
        str(path.relative_to(WORKSPACE)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [
            *sorted((WORKSPACE / 'wag_protection').glob('*.py')),
            *(WORKSPACE / f'searx/engines/{entry["module"]}.py' for entry in engines),
            WORKSPACE / 'searx/data/engine_traits.json',
            WORKSPACE / 'searx/engines/__init__.py',
            WORKSPACE / 'searx/settings.yml', WORKSPACE / 'searx/settings_defaults.py',
            WORKSPACE / 'searx/network/__init__.py', WORKSPACE / 'searx/network/client.py',
            WORKSPACE / 'searx/network/network.py', WORKSPACE / 'searx/network/protected.py',
            WORKSPACE / 'searx/search/__init__.py', WORKSPACE / 'searx/search/processors/abstract.py',
            WORKSPACE / 'searx/search/processors/online.py',
        ]
    }
    python = Path(sys.executable).resolve()
    manifest = {
        'schema': 'wag.protection-artifact.v2', 'contract': 'wag.outbound.v2', 'mode': 'synthetic',
        'fork_commit': '9fea41204fdfa7a5cfa15b0ebd12904c520478ce',
        'registry_digest': digest(engines), 'config_digest': 'a' * 64,
        'python_digest': hashlib.sha256(python.read_bytes()).hexdigest(),
        'module_root': str(WORKSPACE), 'python_executable': str(python), 'root': str(root),
        'shared_gid': os.getgid(), 'allowed_uids': sorted({0, os.getuid()}),
        'files': files, 'distributions': {}, 'wheels': {}, 'registry': engines,
    }
    manifest['artifact_digest'] = digest({key: manifest[key] for key in (
        'contract', 'fork_commit', 'files', 'distributions', 'wheels', 'registry_digest', 'python_digest',
    )})
    return manifest


class StoreTest(unittest.TestCase):
    def setUp(self):
        import wag_protection
        self.api = wag_protection
        self.parent = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.parent.cleanup)
        self.root = Path(self.parent.name) / 'synthetic-state'
        self.engines = registry()
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.now = {'wall': 10000.0, 'mono': 100.0, 'boot': self.boot}
        self.wall = patch('time.time', side_effect=lambda: self.now['wall'])
        self.mono = patch('time.monotonic', side_effect=lambda: self.now['mono'])
        self.wall.start()
        self.mono.start()
        self.addCleanup(self.wall.stop)
        self.addCleanup(self.mono.stop)
        self.api.initialize_fixture(self.root, registry=self.engines, clock=lambda: dict(self.now))
        self.manifest = fixture_manifest(self.root, self.engines)

    def open(self):
        return self.api.open_store(self.root, manifest=self.manifest, mode='synthetic')

    def test_malformed_recovery_audit_refuses_before_callbacks(self):
        mutations = [
            ('wall', -1.0), ('mono', float('inf')), ('decision', 'reset_budget'),
            ('new_boot', ''), ('old_checkpoint', '{"mono":100}'),
            ('old_poison_json', '{}'), ('old_poison_json', '[null]'),
        ]
        for number, (field, value) in enumerate(mutations):
            with self.subTest(field=field, value=value):
                root = Path(self.parent.name) / f'invalid-recovery-audit-{number}'
                self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
                manifest = fixture_manifest(root, self.engines)
                store = self.api.open_store(root, manifest=manifest, mode='synthetic')
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    db.execute('INSERT INTO recoveries VALUES (1,?,?,?,?,?,?,?)', (
                        'synthetic-test-authorization', canonical(self.now).decode(), '["clock_error"]',
                        self.boot, 10000.0, 100.0, 'clock_reanchor',
                    ))
                    db.execute(f'UPDATE recoveries SET {field}=?', (value,))
                calls = []
                reopened = self.api.open_store(root, manifest=manifest, mode='synthetic')
                outcome = store.run_engine('bing', caller='probe', deadline_mono=103.0,
                                           build=lambda: calls.append('build'),
                                           send=lambda context, request: calls.append('send'),
                                           parse=lambda response: calls.append('parse') or [])
                self.assertEqual((getattr(reopened, 'reason', None), getattr(outcome, 'reason', None), calls),
                                 ('schema_error', 'schema_error', []))

    def test_valid_recovery_audit_is_preserved_and_does_not_deny_normal_dispatch(self):
        old_checkpoint = '{"wall":9000.0, "mono":80.0, "boot":"synthetic-old-boot"}'
        old_poison = '["clock_error","legacy_reason","clock_error"]'
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            db.execute('INSERT INTO recoveries VALUES (1,?,?,?,?,?,?,?)', (
                'synthetic-test-authorization', old_checkpoint, old_poison,
                self.boot, 10000.0, 100.0, 'combined',
            ))
        self.assertEqual(self.attempt().outcome, 'empty')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT old_checkpoint,old_poison_json FROM recoveries').fetchall(),
                             [(old_checkpoint, old_poison)])
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [])
            self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 1)

    def test_unknown_attempt_column_refuses_before_callbacks(self):
        store = self.open()
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            db.execute('ALTER TABLE attempts ADD COLUMN unreviewed_schema TEXT')
        calls = []
        result = self.api.open_store(self.root, manifest=self.manifest, mode='synthetic')
        outcome = store.run_engine('bing', caller='probe', deadline_mono=self.now['mono'] + 3,
                                   build=lambda: calls.append('build'),
                                   send=lambda context, request: calls.append('send'),
                                   parse=lambda response: calls.append('parse') or [])
        self.assertEqual((getattr(result, 'reason', None), getattr(outcome, 'reason', None), calls),
                         ('schema_error', 'schema_error', []))

    def test_fixed_schema_rejects_changed_objects_types_constraints_and_indices(self):
        mutations = [
            'CREATE TABLE unreviewed (value TEXT)',
            'CREATE VIEW unreviewed AS SELECT * FROM attempts',
            'CREATE TRIGGER unreviewed AFTER INSERT ON attempts BEGIN DELETE FROM poison; END',
            'CREATE INDEX unreviewed ON attempts(stamp)',
            'DROP INDEX attempts_dispatch',
            'DROP INDEX attempts_engine_account; CREATE INDEX attempts_engine_account ON attempts(engine,account_mono)',
            'DROP TABLE poison; CREATE TABLE poison (reason BLOB NOT NULL)',
            'DROP TABLE poison; CREATE TABLE poison (reason TEXT)',
            'DROP TABLE pauses; CREATE TABLE pauses (engine TEXT PRIMARY KEY REFERENCES engine_identities(engine), '
            'strikes INTEGER NOT NULL, until REAL NOT NULL)',
            'DROP TABLE pauses; CREATE TABLE pauses (engine TEXT PRIMARY KEY, '
            'strikes INTEGER NOT NULL CHECK(strikes>=0), until REAL NOT NULL)',
            'DROP TABLE poison; CREATE TABLE poison (reason TEXT NOT NULL DEFAULT \'unknown\')',
        ]
        for number, sql in enumerate(mutations):
            with self.subTest(sql=sql):
                root = Path(self.parent.name) / f'mutated-{number}'
                self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
                manifest = fixture_manifest(root, self.engines)
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    db.executescript(sql)
                result = self.api.open_store(root, manifest=manifest, mode='synthetic')
                self.assertEqual(getattr(result, 'reason', None), 'schema_error')

    def test_build_failure_is_charged_durably_before_callback(self):
        def build():
            # A nested public read must see the parser/dispatch lock, not a permit.
            nested = self.open().public_snapshot(self.manifest['artifact_digest'], self.manifest['config_digest'])
            self.assertEqual(nested.reason, 'lock_busy')
            raise ValueError('synthetic request failure')

        store = self.open()
        for _ in range(6):
            result = store.run_engine('bing', caller='native_search', deadline_mono=103.0,
                                      build=build, send=lambda context, request: None, parse=lambda response: [])
            self.assertEqual(result.outcome, 'request_refused')
            self.assertEqual(result.reservations, 1)
        reopened = self.open()
        seventh = reopened.run_engine('bing', caller='native_search', deadline_mono=103.0,
                                     build=build, send=lambda context, request: None, parse=lambda response: [])
        self.assertEqual(seventh.reason, 'engine_rate')

    def attempt(self, engine='bing', *, build=lambda: None, parse=lambda response: [], send=lambda context, request: None):
        return self.open().run_engine(engine, caller='native_search', deadline_mono=self.now['mono'] + 3,
                                      build=build, send=send, parse=parse)

    def advance(self, seconds):
        self.now['wall'] += seconds
        self.now['mono'] += seconds

    def test_clock_poison_persists_even_when_wall_is_later_corrected(self):
        self.now['wall'] += 10
        self.assertEqual(self.attempt().reason, 'clock_error')
        self.now['wall'] -= 10
        self.assertEqual(self.attempt().reason, 'clock_error')

    def test_unknown_engine_and_deadline_refuse_before_callbacks(self):
        def forbidden():
            self.fail('refused attempt called build')
        self.assertEqual(self.attempt('unreviewed', build=forbidden).reason, 'capability_refused')
        result = self.open().run_engine('bing', caller='native_search', deadline_mono=self.now['mono'],
                                       build=forbidden, send=lambda context, request: None, parse=lambda response: [])
        self.assertEqual(result.reason, 'deadline_exceeded')

    def test_finished_accounting_keeps_delayed_failure_in_window(self):
        for _ in range(5):
            self.assertEqual(self.attempt().outcome, 'empty')
        def delayed():
            self.advance(60)
        last = self.attempt(build=delayed)
        self.assertEqual(last.outcome, 'timeout')
        self.assertEqual(last.elapsed_s, 60)
        # Five earlier rows expire, but the just-finished failure still costs one.
        for _ in range(5):
            self.assertEqual(self.attempt().outcome, 'empty')
        self.advance(59.999)
        self.assertEqual(self.attempt().reason, 'engine_rate')
        self.advance(0.001)
        self.assertEqual(self.attempt().outcome, 'empty')

    def test_domestic_thirty_thirtyfirst_and_exact_window_across_aliases(self):
        root = Path(self.parent.name) / 'domestic-matrix'
        base = next(entry for entry in self.engines if entry['engine'] == 'chinaso news')
        engines = []
        for number in range(6):
            name = f'fixture-domestic-{number}'
            engines.append({**base, 'engine': name, 'aliases': [name, f'{name}-alias']})
        self.api.initialize_fixture(root, registry=engines, clock=lambda: dict(self.now))
        manifest = fixture_manifest(root, engines)
        calls = []
        def attempt(name, caller='probe'):
            return self.api.open_store(root, manifest=manifest, mode='synthetic').run_engine(
                name, caller=caller, deadline_mono=self.now['mono'] + 3,
                build=lambda: calls.append(name), send=lambda context, request: None,
                parse=lambda response: [],
            )
        for number in range(5):
            for ordinal in range(6):
                name = f'fixture-domestic-{number}' + ('-alias' if ordinal % 2 else '')
                self.assertEqual(attempt(name, 'probe' if ordinal % 2 else 'native_search').outcome, 'empty')
        self.assertEqual(len(calls), 30)
        self.assertEqual(attempt('fixture-domestic-0-alias').reason, 'engine_rate')
        self.assertEqual(attempt('fixture-domestic-5-alias').reason, 'domestic_rate')
        self.assertEqual(len(calls), 30)
        self.advance(59.999)
        self.assertEqual(attempt('fixture-domestic-5').reason, 'domestic_rate')
        self.assertEqual(len(calls), 30)
        self.advance(0.001)
        self.assertEqual(attempt('fixture-domestic-5-alias').outcome, 'empty')
        self.assertEqual(len(calls), 31)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 31)
            self.assertEqual(db.execute('SELECT engine,stamp,account_mono FROM attempts ORDER BY attempt_id DESC LIMIT 1')
                             .fetchone(), ('fixture-domestic-5', 160.0, 160.0))

    def test_invalid_current_clock_persists_poison_before_any_callback(self):
        invalid = [
            ('wall', float('nan')), ('wall', float('inf')), ('wall', -1.0), ('wall', True),
            ('mono', float('nan')), ('mono', float('inf')), ('mono', -1.0), ('mono', True),
            ('wall', 9999.0), ('mono', 99.0), ('wall', 10002.001), ('mono', 102.001),
        ]
        for number, (field, value) in enumerate(invalid):
            with self.subTest(field=field, value=value):
                self.now.update(wall=10000.0, mono=100.0)
                root = Path(self.parent.name) / f'invalid-clock-{number}'
                self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
                manifest = fixture_manifest(root, self.engines)
                store = self.api.open_store(root, manifest=manifest, mode='synthetic')
                calls = []
                self.now[field] = value
                result = store.run_engine('bing', caller='probe', deadline_mono=103.0,
                                          build=lambda: calls.append('build'),
                                          send=lambda context, request: calls.append('send'),
                                          parse=lambda response: calls.append('parse') or [])
                self.assertEqual(getattr(result, 'reason', None), 'clock_error')
                self.assertEqual(calls, [])
                self.now.update(wall=10000.0, mono=100.0)
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [('clock_error',)])
                    self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 0)
                snapshot = self.api.open_store(root, manifest=manifest, mode='synthetic').public_snapshot(
                    manifest['artifact_digest'], manifest['config_digest'])
                self.assertEqual(snapshot.reason, 'clock_error')

    def test_changed_boot_poison_does_not_expire_or_refund_charge(self):
        self.assertEqual(self.attempt().outcome, 'empty')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            previous = dict(self.now, boot='synthetic-previous-boot')
            db.execute('UPDATE state SET checkpoint=?', (canonical(previous).decode(),))
        calls = []
        self.assertEqual(self.attempt('quark', build=lambda: calls.append('build')).reason, 'clock_error')
        self.assertEqual(calls, [])
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [('clock_error',)])
            self.assertEqual(db.execute('SELECT engine,outcome,account_mono FROM attempts').fetchall(),
                             [('bing', 'empty', 100.0)])
            # Repairing the raw checkpoint cannot silently clear the poison.
            db.execute('UPDATE state SET checkpoint=?', (canonical(self.now).decode(),))
        self.advance(3600)
        self.assertEqual(self.attempt('quark', build=lambda: calls.append('build')).reason, 'clock_error')
        self.assertEqual(calls, [])

    def test_parser_failure_and_empty_keep_captcha_strikes_across_reopen(self):
        def challenged(response):
            raise self.api.EngineFailure('captcha', suspension_s=900)
        for strikes, pause in [(1, 1800), (2, 3600), (3, 7200)]:
            result = self.attempt('quark', parse=challenged)
            self.assertEqual(result.outcome, 'captcha')
            self.assertEqual(self.attempt('quark').reason, 'cooldown')
            self.advance(pause)
            self.assertEqual(self.attempt('quark').outcome, 'empty')
            def broken(response):
                raise ValueError('synthetic parser error')
            self.assertEqual(self.attempt('quark', parse=broken).outcome, 'parser_error')
            with sqlite3.connect(self.root / 'ledger.sqlite') as db:
                self.assertEqual(db.execute('SELECT strikes FROM pauses WHERE engine=?', ('quark',)).fetchone()[0], strikes)
        self.assertEqual(self.attempt('quark', parse=lambda response: [{'title': 'synthetic'}]).outcome, 'ok')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM pauses').fetchone()[0], 0)

    def test_unfinished_row_blocks_other_engine_without_refund(self):
        self.assertEqual(self.attempt().outcome, 'empty')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            db.execute('UPDATE attempts SET outcome=NULL,finished_mono=NULL')
        self.assertEqual(self.attempt('yandex').reason, 'unfinished_attempt')
        self.advance(3600)
        self.assertEqual(self.attempt('yandex').reason, 'unfinished_attempt')

    def test_inherited_dispatch_refuses_without_writing_or_closing_reused_fd(self):
        script = '''
import json
import os
from pathlib import Path
import sys
import time
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('core child denied socket operation')
sys.addaudithook(deny_socket)
import wag_protection
root = Path(sys.argv[1])
manifest = json.loads(sys.argv[2])
time.time = lambda: 10000.0
time.monotonic = lambda: 100.0
owner = os.getpid()
store = wag_protection.open_store(root, manifest=manifest, mode='synthetic')
reused = None
def build():
    global reused
    child = os.fork()
    if child == 0:
        reused = os.open(os.devnull, os.O_RDONLY)
        return
    _, status = os.waitpid(child, 0)
    assert status == 0
result = store.run_engine('bing', caller='probe', deadline_mono=103.0,
                          build=build, send=lambda context, request: None, parse=lambda response: [])
if os.getpid() != owner:
    os.fstat(reused)
    fresh = wag_protection.open_store(root, manifest=manifest, mode='synthetic')
    print(json.dumps({'child_reason': getattr(result, 'reason', None),
                      'fresh_reason': getattr(fresh, 'reason', None), 'reused_fd_open': True}), flush=True)
    os._exit(0)
print(json.dumps({'parent_outcome': result.outcome}), flush=True)
'''
        process = subprocess.run(
            [sys.executable, '-S', '-c', script, str(self.root), json.dumps(self.manifest)],
            cwd=WORKSPACE, capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        records = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(records, [
            {'child_reason': 'capability_refused', 'fresh_reason': 'lock_busy', 'reused_fd_open': True},
            {'parent_outcome': 'empty'},
        ])
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT engine,outcome FROM attempts').fetchall(), [('bing', 'empty')])
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [])

    def test_owner_death_does_not_leave_flock_in_forked_child(self):
        script = '''
import json
import os
from pathlib import Path
import sys
import time
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('core child denied socket operation')
sys.addaudithook(deny_socket)
import wag_protection
root = Path(sys.argv[1])
manifest = json.loads(sys.argv[2])
time.time = lambda: 10000.0
time.monotonic = lambda: 100.0
store = wag_protection.open_store(root, manifest=manifest, mode='synthetic')
def build():
    child = os.fork()
    if child == 0:
        os.read(0, 1)
        os._exit(0)
    print(child, flush=True)
    os.read(0, 1)
store.run_engine('bing', caller='probe', deadline_mono=103.0,
                 build=build, send=lambda context, request: None, parse=lambda response: [])
'''
        process = subprocess.Popen(
            [sys.executable, '-S', '-c', script, str(self.root), json.dumps(self.manifest)],
            cwd=WORKSPACE, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        child = None
        try:
            import select
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'owner never entered build')
            child = int(process.stdout.readline())
            self.assertEqual(getattr(self.open(), 'reason', None), 'lock_busy')
            process.kill()
            process.wait(timeout=5)
            # Child still exists and has not been told to exit. The old lock FD
            # must already be revoked, while the parent's committed NULL survives.
            os.kill(child, 0)
            self.assertNotEqual(getattr(self.open(), 'reason', None), 'lock_busy')
            calls = []
            self.assertEqual(self.attempt('quark', build=lambda: calls.append('build')).reason,
                             'unfinished_attempt')
            self.assertEqual(calls, [])
            with sqlite3.connect(self.root / 'ledger.sqlite') as db:
                self.assertEqual(db.execute('SELECT engine,outcome FROM attempts').fetchall(), [('bing', None)])
        finally:
            if child is not None:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_release_receipt_unlocks_before_one_ingress_and_cannot_replay(self):
        store = self.open()
        release_id = '1' * 32
        artifact, config = self.manifest['artifact_digest'], self.manifest['config_digest']
        receipt = store.claim_release(release_id, artifact, config, self.now['mono'] + 10)
        calls = []
        def operation():
            calls.append('operation')
            self.assertEqual(self.open().consume_release_ingress(release_id, artifact, config), True)
            self.assertEqual(self.open().consume_release_ingress(release_id, artifact, config).reason, 'release_consumed')
            return {
                'version': 2, 'release_id': release_id, 'artifact_digest': artifact, 'config_digest': config,
                'checked_at': '1970-01-01T02:46:40+00:00', 'age_s': 0,
                'search': {'status': 'passed', 'result_count': 2, 'responsive_engine_count': 2,
                           'protection_status': 'complete', 'quality_evidence_digest': 'b' * 64, 'reason': None},
                'egress': {'status': 'passed', 'reason': None},
            }
        evidence = store.run_release_check(receipt, operation)
        self.assertEqual(evidence['search']['status'], 'passed')
        self.assertEqual(store.run_release_check(receipt, operation).reason, 'release_consumed')
        self.assertEqual(self.open().claim_release(release_id, artifact, config, self.now['mono'] + 10).reason, 'release_consumed')
        self.assertEqual(calls, ['operation'])
        self.assertEqual(self.open().public_snapshot(artifact, config)['age_s'], 0)
        self.advance(60.001)
        self.assertEqual(self.open().public_snapshot(artifact, config).reason, 'evidence_unknown')

    def test_release_operation_crash_consumes_claim_permanently(self):
        store = self.open()
        artifact, config = self.manifest['artifact_digest'], self.manifest['config_digest']
        release_id = '2' * 32
        receipt = store.claim_release(release_id, artifact, config, self.now['mono'] + 10)
        def operation():
            self.assertEqual(self.open().consume_release_ingress(release_id, artifact, config), True)
            raise ValueError('synthetic operation failure')
        self.assertEqual(store.run_release_check(receipt, operation).reason, 'evidence_unknown')
        self.assertEqual(self.open().consume_release_ingress(release_id, artifact, config).reason, 'release_consumed')
        self.assertEqual(self.open().public_snapshot(artifact, config).reason, 'evidence_unknown')
        self.assertEqual(self.open().consume_release_ingress('3' * 32, artifact, config).reason, 'release_consumed')

    def test_missing_store_never_creates_state(self):
        root = Path(self.parent.name) / 'missing'
        manifest = {**self.manifest, 'root': str(root)}
        result = self.api.open_store(root, manifest=manifest, mode='synthetic')
        self.assertEqual(result.reason, 'identity_error')
        self.assertFalse(root.exists())

    def test_raw_enabled_is_strict_before_coercion(self):
        self.assertEqual(self.api.validate_settings({'enabled': False}), {'enabled': False})
        for value in ['false', 'true', 0, 1, None, [], {}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.api.validate_settings({'enabled': value})
        with self.assertRaises(ValueError):
            self.api.validate_settings({'enabled': False, 'enable': True})

    def test_manifest_unknown_field_and_shadow_file_refuse_before_build(self):
        for manifest in [
            {**self.manifest, 'surprise': True},
            {**self.manifest, 'files': {**self.manifest['files'], '../shadow.py': 'b' * 64}},
            {**self.manifest, 'python_digest': '0' * 64},
        ]:
            with self.subTest(manifest=list(manifest)):
                self.assertEqual(self.api.open_store(self.root, manifest=manifest, mode='synthetic').reason,
                                 'provenance_error')


if __name__ == '__main__':
    unittest.main()
