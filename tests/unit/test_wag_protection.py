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

    def legacy_fixture(self, name='legacy-state', *, unfinished=False, poison=()):
        root = Path(self.parent.name) / name
        root.mkdir(mode=0o700)
        identity = b'1' * 32  # Disposable synthetic token, never a copied live identity.
        for path, data in [(root / 'identity', identity), (Path(str(root) + '.identity'), identity),
                           (root / 'lock', b''), (root / 'ledger.sqlite', b'')]:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as file:
                file.write(data)
        checkpoint = json.dumps({'wall': 10000.0, 'mono': 8073000.0, 'boot': self.boot})
        self.now.update(wall=10001.0, mono=8073001.0)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            # Original probe source lines522–527; no v2 DDL or production copy.
            db.execute('CREATE TABLE state (id TEXT, root TEXT, checkpoint TEXT)')
            db.execute('CREATE TABLE attempts (engine TEXT, domestic INTEGER, stamp REAL, outcome TEXT)')
            db.execute('CREATE TABLE pauses (engine TEXT PRIMARY KEY, strikes INTEGER, until REAL)')
            db.execute('CREATE TABLE poison (reason TEXT)')
            db.execute('INSERT INTO state VALUES (?,?,?)', (identity.decode(), str(root), checkpoint))
            db.executemany('INSERT INTO attempts(rowid,engine,domestic,stamp,outcome) VALUES (?,?,?,?,?)', [
                (7, 'chinaso news', 1, 8072913.0, 'ok'),
                (19, 'chinaso news', 1, 8072914.25, 'ok'),
                (41, 'quark', 1, 8072915.728828768, 'captcha'),
            ])
            if unfinished:
                db.execute('INSERT INTO attempts(rowid,engine,domestic,stamp,outcome) VALUES (53,?,?,?,NULL)',
                           ('bing', 0, 8072999.0))
            db.execute('INSERT INTO pauses VALUES (?,?,?)', ('quark', 1, 8074715.728828768))
            db.executemany('INSERT INTO poison(reason) VALUES (?)', [(reason,) for reason in poison])
        return root, fixture_manifest(root, self.engines), checkpoint

    def test_migration_preserves_original_history_identity_and_is_idempotent(self):
        root, manifest, checkpoint = self.legacy_fixture()
        token = (root / 'identity').read_bytes()
        inode = (root / 'lock').stat().st_ino
        self.assertEqual(self.api.open_store(root, manifest=manifest, mode='synthetic').reason, 'schema_error')
        migrated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:stage6-migration')
        self.assertFalse(isinstance(migrated, self.api.Refusal))
        self.assertTrue((root / 'identity').read_bytes() == token)
        self.assertTrue(Path(str(root) + '.identity').read_bytes() == token)
        self.assertEqual((root / 'lock').stat().st_ino, inode)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            state = db.execute('SELECT id,root,checkpoint FROM state').fetchone()
            self.assertTrue(state[0].encode() == token)
            self.assertEqual(state[1:], (str(root), checkpoint))
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT registry_digest,migration_wall,migration_mono,migration_boot '
                                        'FROM contract_meta').fetchone(),
                             (manifest['registry_digest'], 10001.0, 8073001.0, self.boot))
            rows = db.execute('SELECT attempt_id,dispatch_id,engine,domestic,stamp,outcome,reserved_mono,finished_mono,'
                              'account_boot,account_mono,caller,phase,connection_attempted,http_attempted,elapsed,source '
                              'FROM attempts ORDER BY attempt_id').fetchall()
            self.assertEqual(rows, [
                (7, 'legacy:7', 'chinaso news', 1, 8072913.0, 'ok', None, 8072913.0,
                 self.boot, 8072913.0, 'legacy_probe', 'legacy', None, None, None, 'legacy'),
                (19, 'legacy:19', 'chinaso news', 1, 8072914.25, 'ok', None, 8072914.25,
                 self.boot, 8072914.25, 'legacy_probe', 'legacy', None, None, None, 'legacy'),
                (41, 'legacy:41', 'quark', 1, 8072915.728828768, 'captcha', None, 8072915.728828768,
                 self.boot, 8072915.728828768, 'legacy_probe', 'legacy', None, None, None, 'legacy'),
            ])
            self.assertEqual(db.execute('SELECT * FROM pauses').fetchall(), [('quark', 1, 8074715.728828768)])
        original_db = (root / 'ledger.sqlite').read_bytes()
        self.advance(17)
        repeated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:repeat-validation')
        self.assertFalse(isinstance(repeated, self.api.Refusal))
        self.assertTrue((root / 'ledger.sqlite').read_bytes() == original_db, 'v2 repeat rewrote durable state')
        calls = []
        outcome = repeated.run_engine('bing', caller='probe', deadline_mono=self.now['mono'] + 3,
                                      build=lambda: calls.append('build'), send=lambda context, request: None,
                                      parse=lambda response: [])
        self.assertEqual((outcome.outcome, calls), ('empty', ['build']))
        refused = repeated.run_engine('quark', caller='probe', deadline_mono=self.now['mono'] + 3,
                                      build=lambda: calls.append('quark'), send=lambda context, request: None,
                                      parse=lambda response: [])
        self.assertEqual((refused.reason, calls), ('cooldown', ['build']))

    def test_migration_keeps_null_poison_order_and_old_clock_without_recovery(self):
        for number, poison in enumerate([(), ('clock_error', 'legacy_reason', 'clock_error')]):
            with self.subTest(poison=poison):
                root, manifest, checkpoint = self.legacy_fixture(f'legacy-uncertain-{number}', unfinished=True,
                                                                poison=poison)
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    db.execute('UPDATE poison SET rowid=rowid+100')
                migrated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:retain-unknown')
                self.assertFalse(isinstance(migrated, self.api.Refusal))
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    self.assertEqual(db.execute('SELECT checkpoint FROM state').fetchone()[0], checkpoint)
                    self.assertEqual(db.execute('SELECT reason FROM poison ORDER BY rowid').fetchall(),
                                     [(reason,) for reason in poison])
                    self.assertEqual(db.execute('SELECT attempt_id,outcome,reserved_mono,finished_mono,account_boot,'
                                                'account_mono,connection_attempted,http_attempted,elapsed '
                                                'FROM attempts WHERE attempt_id=53').fetchone(),
                                     (53, None, None, None, self.boot, 8072999.0, None, None, None))
                calls = []
                result = migrated.run_engine('bing', caller='probe', deadline_mono=self.now['mono'] + 3,
                                             build=lambda: calls.append('build'), send=lambda context, request: None,
                                             parse=lambda response: [])
                self.assertEqual((result.reason, calls), ('clock_error' if poison else 'unfinished_attempt', []))
        root, manifest, checkpoint = self.legacy_fixture('legacy-old-boot')
        old = json.loads(checkpoint)
        old['boot'] = 'synthetic-old-boot'
        checkpoint = json.dumps(old)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            db.execute('UPDATE state SET checkpoint=?', (checkpoint,))
        migrated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:no-reanchor')
        self.assertFalse(isinstance(migrated, self.api.Refusal))
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT checkpoint FROM state').fetchone()[0], checkpoint)
            self.assertEqual(db.execute('SELECT DISTINCT account_boot FROM attempts').fetchall(), [('synthetic-old-boot',)])
        calls = []
        result = migrated.run_engine('bing', caller='probe', deadline_mono=self.now['mono'] + 3,
                                     build=lambda: calls.append('build'), send=lambda context, request: None,
                                     parse=lambda response: [])
        self.assertEqual((result.reason, calls), ('clock_error', []))

    def test_migration_rejects_unknown_schema_version_and_illegal_legacy_rows(self):
        mutations = [
            ('CREATE TABLE extra (value TEXT)', 'schema_error'),
            ('CREATE VIEW extra AS SELECT * FROM attempts', 'schema_error'),
            ('CREATE TRIGGER extra AFTER INSERT ON attempts BEGIN DELETE FROM poison; END', 'schema_error'),
            ('CREATE INDEX extra ON attempts(stamp)', 'schema_error'),
            ('ALTER TABLE attempts ADD COLUMN extra TEXT', 'schema_error'),
            ('DROP TABLE poison; CREATE TABLE poison (reason BLOB)', 'schema_error'),
            ('DROP TABLE poison; CREATE TABLE poison (reason TEXT NOT NULL)', 'schema_error'),
            ('PRAGMA user_version=1', 'schema_error'),
            ('PRAGMA user_version=3', 'schema_error'),
            ("UPDATE attempts SET engine='unknown_engine' WHERE rowid=7", 'schema_error'),
            ("UPDATE attempts SET outcome='invented_success' WHERE rowid=7", 'schema_error'),
            ('UPDATE attempts SET domestic=0 WHERE rowid=7', 'schema_error'),
            ('UPDATE attempts SET stamp=1e999 WHERE rowid=7', 'schema_error'),
            ('UPDATE attempts SET stamp=NULL WHERE rowid=7', 'schema_error'),
            ('UPDATE pauses SET strikes=-1', 'schema_error'),
            ('UPDATE pauses SET strikes=1.5', 'schema_error'),
            ('UPDATE pauses SET until=1e999', 'schema_error'),
            ('INSERT INTO poison VALUES (NULL)', 'schema_error'),
            ('INSERT INTO state SELECT * FROM state', 'identity_error'),
            ("UPDATE state SET root='/synthetic/wrong-root'", 'identity_error'),
            ("UPDATE state SET checkpoint='{}'", 'clock_error'),
        ]
        for number, (sql, reason) in enumerate(mutations):
            with self.subTest(sql=sql):
                root, manifest, _ = self.legacy_fixture(f'legacy-refused-{number}')
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    db.executescript(sql)
                before = (root / 'ledger.sqlite').read_bytes()
                result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:refusal-case')
                self.assertEqual(getattr(result, 'reason', None), reason)
                self.assertTrue((root / 'ledger.sqlite').read_bytes() == before, 'refusal changed legacy DB')

    def test_migration_authorization_manifest_modes_and_registry_digest_fail_closed(self):
        root, manifest, _ = self.legacy_fixture('legacy-authorization')
        before = (root / 'ledger.sqlite').read_bytes()
        for authorization in [None, False, 1, '', ' ', 'x' * 257, 'line\nreference', '\ud800']:
            with self.subTest(authorization_type=type(authorization).__name__):
                result = self.api.migrate_legacy(root, manifest=manifest, authorization=authorization)
                self.assertEqual(getattr(result, 'reason', None), 'capability_refused')
                self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
        for invalid in [{**manifest, 'mode': 'production'}, {**manifest, 'extra': True},
                        {**manifest, 'mode': 'unknown'}]:
            result = self.api.migrate_legacy(root, manifest=invalid, authorization='synthetic:invalid-manifest')
            self.assertEqual(getattr(result, 'reason', None), 'provenance_error')
        manifest_path = Path(self.parent.name) / 'synthetic-migration-artifact.json'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        migrated = self.api.migrate_legacy(root, manifest=manifest_path, authorization='synthetic:path-manifest')
        self.assertFalse(isinstance(migrated, self.api.Refusal))
        before = (root / 'ledger.sqlite').read_bytes()
        amended = json.loads(json.dumps(self.engines))
        amended[0]['profile']['live_hold'] = True
        changed = fixture_manifest(root, amended)
        result = self.api.migrate_legacy(root, manifest=changed, authorization='synthetic:wrong-v2-digest')
        self.assertEqual(getattr(result, 'reason', None), 'schema_error')
        self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)

    def test_migration_never_initializes_missing_or_repairs_corrupt_state(self):
        missing = Path(self.parent.name) / 'missing-legacy'
        manifest = fixture_manifest(missing, self.engines)
        result = self.api.migrate_legacy(missing, manifest=manifest, authorization='synthetic:missing-state')
        self.assertEqual(getattr(result, 'reason', None), 'identity_error')
        self.assertFalse(missing.exists())
        self.assertFalse(Path(str(missing) + '.identity').exists())
        root, manifest, _ = self.legacy_fixture('legacy-wrong-anchor')
        anchor = Path(str(root) + '.identity')
        token = (root / 'identity').read_bytes()
        anchor.write_bytes(b'2' * 32)  # Only this test's newly created synthetic anchor.
        before = (root / 'ledger.sqlite').read_bytes()
        result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:wrong-anchor')
        self.assertEqual(getattr(result, 'reason', None), 'identity_error')
        self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
        self.assertTrue((root / 'identity').read_bytes() == token)
        self.assertTrue(anchor.read_bytes() == b'2' * 32)
        root, manifest, _ = self.legacy_fixture('legacy-corrupt-db')
        token = (root / 'identity').read_bytes()
        with (root / 'ledger.sqlite').open('r+b') as file:
            file.write(b'synthetic-not-sqlite')
        before = (root / 'ledger.sqlite').read_bytes()
        result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:corrupt-db')
        self.assertEqual(getattr(result, 'reason', None), 'storage_error')
        self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
        self.assertTrue((root / 'identity').read_bytes() == token)
        self.assertTrue(Path(str(root) + '.identity').read_bytes() == token)

    def test_migration_uses_original_nonblocking_flock_across_processes(self):
        root, manifest, _ = self.legacy_fixture('legacy-locked')
        inode = (root / 'lock').stat().st_ino
        before = (root / 'ledger.sqlite').read_bytes()
        script = '''
import fcntl
import os
import sys
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('maintenance child denied socket operation')
sys.addaudithook(deny_socket)
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print('locked', flush=True)
os.read(0, 1)
os.close(fd)
'''
        process = subprocess.Popen([sys.executable, '-S', '-c', script, str(root / 'lock')],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            import select
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'lock owner did not start')
            self.assertEqual(process.stdout.readline().strip(), 'locked')
            result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:busy-lock')
            self.assertEqual(getattr(result, 'reason', None), 'lock_busy')
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
            self.assertEqual((root / 'lock').stat().st_ino, inode)
        finally:
            _, errors = process.communicate(input='x', timeout=5)
            self.assertEqual(process.returncode, 0, errors)
        result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:stopped-owner')
        self.assertFalse(isinstance(result, self.api.Refusal))
        self.assertEqual((root / 'lock').stat().st_ino, inode)

    def test_migration_real_commit_crash_and_sqlite_failure_are_atomic(self):
        # Instrument only the real SQLite driver boundary in a disposable child:
        # before/after super().commit(), or SQLite's own authorizer refusal.
        # No fake connection/SQL, product helper patch or simulated process death.
        script = '''
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('maintenance child denied socket operation')
sys.addaudithook(deny_socket)
import wag_protection
root = Path(sys.argv[1])
manifest = json.loads(sys.argv[2])
stage = sys.argv[3]
time.time = lambda: 10001.0
time.monotonic = lambda: 8073001.0
class ObservedConnection(sqlite3.Connection):
    def commit(self):
        if stage == 'before':
            print('before', flush=True)
            os.read(0, 1)
        super().commit()
        if stage == 'after':
            print('after', flush=True)
            os.read(0, 1)
original_connect = sqlite3.connect
def connect(database, *args, **kwargs):
    target = str(database).startswith('file:' + str(root / 'ledger.sqlite'))
    if target:
        kwargs['factory'] = ObservedConnection
    db = original_connect(database, *args, **kwargs)
    if target and stage == 'deny':
        def authorize(action, name, *unused):
            if action == sqlite3.SQLITE_DROP_TABLE and name == 'migration_state':
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        db.set_authorizer(authorize)
    return db
sqlite3.connect = connect
result = wag_protection.migrate_legacy(root, manifest=manifest, authorization='synthetic:atomicity-child')
print(json.dumps({'reason': getattr(result, 'reason', None)}), flush=True)
'''
        for stage in ('before', 'after', 'deny'):
            with self.subTest(stage=stage):
                root, manifest, checkpoint = self.legacy_fixture(f'legacy-atomic-{stage}', unfinished=True,
                                                                poison=('legacy_reason', 'clock_error', 'legacy_reason'))
                token = (root / 'identity').read_bytes()
                inode = (root / 'lock').stat().st_ino
                process = subprocess.Popen(
                    [sys.executable, '-S', '-c', script, str(root), json.dumps(manifest), stage],
                    cwd=WORKSPACE, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    import select
                    self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'migration boundary was not reached')
                    observed = process.stdout.readline().strip()
                    if stage == 'deny':
                        self.assertEqual(json.loads(observed), {'reason': 'storage_error'})
                        _, errors = process.communicate(timeout=5)
                        self.assertEqual(process.returncode, 0, errors)
                    else:
                        self.assertEqual(observed, stage)
                        # The true transaction is still held at this boundary.
                        self.assertEqual(self.api.open_store(root, manifest=manifest, mode='synthetic').reason, 'lock_busy')
                        process.kill()
                        process.wait(timeout=5)
                    # A real reopen performs SQLite hot-journal recovery after
                    # precommit death. It must never auto-initialize/migrate.
                    opened = self.api.open_store(root, manifest=manifest, mode='synthetic')
                    self.assertEqual(getattr(opened, 'reason', None), None if stage == 'after' else 'schema_error')
                    with sqlite3.connect(root / 'ledger.sqlite') as db:
                        self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2 if stage == 'after' else 0)
                        self.assertEqual(db.execute('SELECT checkpoint FROM state').fetchone()[0], checkpoint)
                        self.assertEqual(db.execute('SELECT reason FROM poison ORDER BY rowid').fetchall(),
                                         [('legacy_reason',), ('clock_error',), ('legacy_reason',)])
                        if stage == 'after':
                            self.assertEqual(db.execute('SELECT attempt_id,outcome FROM attempts ORDER BY attempt_id').fetchall(),
                                             [(7, 'ok'), (19, 'ok'), (41, 'captcha'), (53, None)])
                        else:
                            self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                                             .fetchall(), [('attempts',), ('pauses',), ('poison',), ('state',)])
                            self.assertEqual(db.execute('SELECT rowid,outcome FROM attempts ORDER BY rowid').fetchall(),
                                             [(7, 'ok'), (19, 'ok'), (41, 'captcha'), (53, None)])
                    self.assertTrue((root / 'identity').read_bytes() == token)
                    self.assertTrue(Path(str(root) + '.identity').read_bytes() == token)
                    self.assertEqual((root / 'lock').stat().st_ino, inode)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)

    def test_recovery_requires_real_sender_stop_and_atomically_preserves_audit_charge_and_pause(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        self.assertEqual(self.attempt().outcome, 'empty')
        store = self.open()
        store.claim_release('3' * 32, self.manifest['artifact_digest'], self.manifest['config_digest'], 110.0)
        authorization = 'synthetic:stage9-physical-stop'
        with _SyntheticMaintenanceSession(self.root, manifest=self.manifest, authorization=authorization,
                                          decision='combined') as session:
            sender = session.start_sender('quark')
            old_checkpoint = canonical({'wall': 9000.0, 'mono': 80.0, 'boot': 'synthetic-old-boot'}).decode()
            with sqlite3.connect(self.root / 'ledger.sqlite') as db:
                db.row_factory = sqlite3.Row
                db.execute('UPDATE state SET checkpoint=?', (old_checkpoint,))
                db.executemany('INSERT INTO poison(rowid,reason) VALUES (?,?)', [
                    (5, 'unfinished_attempt'), (8, 'clock_error'), (9, 'clock_error'), (11, 'legacy_reason'),
                ])
                db.executemany('INSERT INTO pauses VALUES (?,?,?)', [('quark', 1, 1900.0), ('yandex', 1, 800.0)])
                old_attempts = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
                old_release = [tuple(row) for row in db.execute('SELECT * FROM release_checks')]
            proof = session.seal(clear_poison=(self.api.PoisonSelection(5, 'unfinished_attempt'),
                                              self.api.PoisonSelection(8, 'clock_error')))
            before = (self.root / 'ledger.sqlite').read_bytes()
            refused = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            self.assertEqual(refused.reason, 'evidence_unknown')
            self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)
            session.stop_sender(sender)
            result = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            self.assertIs(type(result), self.api.RecoveryResult)
            self.assertEqual((result.recovery_id, result.decision, result.terminated_count, result.reanchored_count),
                             (1, 'combined', 1, 2))
            after = (self.root / 'ledger.sqlite').read_bytes()
            self.assertEqual(self.api.recover(self.root, authorization=authorization,
                                             decision='combined', proof=proof).reason, 'capability_refused')
            self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), after)
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT authorization,old_checkpoint,old_poison_json,new_boot,wall,mono,decision '
                                        'FROM recoveries').fetchall(), [(authorization, old_checkpoint,
                                        '["unfinished_attempt","clock_error","clock_error","legacy_reason"]',
                                        self.boot, 10000.0, 100.0, 'combined')])
            audited = db.execute('SELECT attempt_id,old_row_json FROM recovery_attempts ORDER BY attempt_id').fetchall()
            self.assertEqual([json.loads(row[1]) for row in audited], old_attempts)
            self.assertEqual(db.execute('SELECT engine,old_strikes,old_until FROM recovery_pauses ORDER BY engine').fetchall(),
                             [('quark', 1, 1900.0), ('yandex', 1, 800.0)])
            self.assertEqual(db.execute('SELECT engine,stamp,outcome,finished_mono,elapsed,connection_attempted,'
                                        'http_attempted,account_boot,account_mono FROM attempts ORDER BY attempt_id').fetchall(), [
                ('bing', 100.0, 'empty', 100.0, 0.0, 0, 0, self.boot, 100.0),
                ('quark', 100.0, 'unknown_terminated', None, None, 0, 0, self.boot, 100.0),
            ])
            self.assertEqual(db.execute('SELECT * FROM pauses ORDER BY engine').fetchall(),
                             [('quark', 2, 3700.0), ('yandex', 1, 1900.0)])
            self.assertEqual(db.execute('SELECT rowid,reason FROM poison ORDER BY rowid').fetchall(),
                             [(9, 'clock_error'), (11, 'legacy_reason')])
            self.assertEqual(db.execute('SELECT * FROM release_checks').fetchall(), old_release)
        self.assertEqual(self.attempt('quark').reason, 'clock_error')

    def test_recovery_rejects_untyped_proof_production_and_seal_mutation_without_writes(self):
        before = (self.root / 'ledger.sqlite').read_bytes()
        for proof in (True, {}, 'proof', None):
            with self.subTest(proof_type=type(proof).__name__):
                result = self.api.recover(self.root, authorization='synthetic:invalid-proof',
                                          decision='combined', proof=proof)
                self.assertEqual(result.reason, 'capability_refused')
                self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)
        result = self.api.recover(Path('/var/lib/wag-route-probe'), authorization='production:looks-valid',
                                  decision='combined', proof={'synthetic': True})
        self.assertEqual(result.reason, 'evidence_unknown')
        self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)

    def test_recovery_rejects_missing_coverage_and_preserves_live_sender(self):
        import select
        from wag_protection.ledger import _SyntheticMaintenanceSession

        authorization = 'synthetic:stage10-coverage'
        with _SyntheticMaintenanceSession(self.root, manifest=self.manifest, authorization=authorization,
                                          decision='combined') as session:
            binding = session.start_sender('bing')
            pidfd = os.pidfd_open(binding.pid, 0)
            self.addCleanup(os.close, pidfd)
            with self.assertRaises(TypeError):
                self.api.MaintenanceCapability(authorization, 'combined', self.root, self.boot, 100.0, 200.0, (), session)
            proof = session.seal(clear_poison=())
            before = (self.root / 'ledger.sqlite').read_bytes()
            self.assertEqual(self.api.recover(self.root, authorization=authorization,
                                               decision='clock_reanchor', proof=proof).reason, 'capability_refused')
            self.assertEqual(self.api.recover(self.root, authorization=authorization,
                                               decision='combined', proof=proof).reason, 'evidence_unknown')
            self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)
            self.assertEqual(select.select([pidfd], [], [], 0)[0], [])
            session.stop_sender(binding)
            self.assertEqual(select.select([pidfd], [], [], 0)[0], [pidfd])
            with self.assertRaises(ChildProcessError):
                os.waitpid(binding.pid, os.WNOHANG)
            result = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            self.assertIs(type(result), self.api.RecoveryResult)
            self.assertEqual(result.terminated_count, 1)

        for timing in ('before_seal', 'after_seal'):
            with self.subTest(unregistered_null=timing):
                root = Path(self.parent.name) / f'missing-coverage-{timing}'
                self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
                manifest = fixture_manifest(root, self.engines)
                with _SyntheticMaintenanceSession(root, manifest=manifest, authorization=authorization,
                                                  decision='combined') as session:
                    binding = session.start_sender('bing')
                    pidfd = os.pidfd_open(binding.pid, 0)
                    self.addCleanup(os.close, pidfd)
                    if timing == 'after_seal':
                        proof = session.seal()
                    with sqlite3.connect(root / 'ledger.sqlite') as db:
                        # A valid NULL row from another dispatch is not covered by this sender's birth registration.
                        unregistered_id = db.execute(
                            'INSERT INTO attempts (dispatch_id,engine,domestic,stamp,outcome,reserved_mono,finished_mono,'
                            'account_boot,account_mono,caller,phase,connection_attempted,http_attempted,elapsed,source) '
                            'SELECT ?,engine,domestic,stamp,outcome,reserved_mono,finished_mono,account_boot,account_mono,'
                            'caller,phase,connection_attempted,http_attempted,elapsed,source FROM attempts WHERE attempt_id=?',
                            ('stage10-unregistered-dispatch', binding.attempt_ids[0]),
                        ).lastrowid
                    self.assertNotIn(unregistered_id, binding.attempt_ids)
                    before = (root / 'ledger.sqlite').read_bytes()
                    self.assertFalse(isinstance(self.api.open_store(root, manifest=manifest, mode='synthetic'),
                                                self.api.Refusal))
                    for stopped in (False, True):
                        if stopped:
                            session.stop_sender(binding)
                        if timing == 'before_seal':
                            with self.assertRaises(self.api.ProtectionError) as error:
                                session.seal()
                            self.assertEqual(error.exception.reason, 'evidence_unknown')
                        else:
                            self.assertEqual(self.api.recover(root, authorization=authorization,
                                                               decision='combined', proof=proof).reason, 'evidence_unknown')
                        self.assertEqual((root / 'ledger.sqlite').read_bytes(), before)
                        self.assertEqual(select.select([pidfd], [], [], 0)[0], [pidfd] if stopped else [])
                        with sqlite3.connect(root / 'ledger.sqlite') as db:
                            self.assertEqual(db.execute('SELECT count(*) FROM attempts WHERE outcome IS NULL').fetchone()[0], 2)
                            for table in ('recoveries', 'recovery_attempts', 'recovery_pauses'):
                                self.assertEqual(db.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0)

    def test_recovery_audit_failure_rolls_back_without_consuming_proof(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        authorization = 'synthetic:stage9-sql-fault'
        with _SyntheticMaintenanceSession(self.root, manifest=self.manifest, authorization=authorization,
                                          decision='combined') as session:
            binding = session.start_sender('quark')
            session.stop_sender(binding)
            proof = session.seal()
            before = (self.root / 'ledger.sqlite').read_bytes()
            with patch('wag_protection.ledger._commit', side_effect=sqlite3.OperationalError('synthetic commit fault')):
                result = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            self.assertEqual(result.reason, 'storage_error')
            self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)
            # Commit uncertainty consumes the proof; retry is refused rather than guessed.
            self.assertEqual(self.api.recover(self.root, authorization=authorization,
                                               decision='combined', proof=proof).reason, 'capability_refused')

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
