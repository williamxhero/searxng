# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite accounting under one nonblocking, process-owned Linux flock."""

import concurrent.futures
from contextlib import contextmanager
from contextvars import ContextVar
import errno
import fcntl
from importlib.metadata import PackageNotFoundError
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile
import threading
import time
from urllib.parse import quote

from .contract import (
    CALLERS, OUTCOMES, PHASES, REASONS, PRODUCTION_ROOT, VERSION,
    EngineFailure, EngineOutcome, ProtectionError, Refusal, canonical_json, canonical_path, finite,
    hex_value, json_digest, load_json, validate_evidence, validate_manifest, validate_registry,
)

SCHEMA = """
CREATE TABLE state (id TEXT PRIMARY KEY, root TEXT NOT NULL, checkpoint TEXT NOT NULL);
CREATE TABLE contract_meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL CHECK(version=2),
 registry_digest TEXT NOT NULL, migration_wall REAL NOT NULL, migration_mono REAL NOT NULL, migration_boot TEXT NOT NULL);
CREATE TABLE engine_identities (
 engine TEXT PRIMARY KEY, domestic INTEGER NOT NULL CHECK(domestic IN (0,1)), module TEXT NOT NULL,
 capability TEXT NOT NULL CHECK(capability='online_one_send'), source_digest TEXT NOT NULL, profile_json TEXT NOT NULL);
CREATE TABLE aliases (alias TEXT PRIMARY KEY, engine TEXT NOT NULL REFERENCES engine_identities(engine));
CREATE TABLE attempts (
 attempt_id INTEGER PRIMARY KEY, dispatch_id TEXT NOT NULL, engine TEXT NOT NULL REFERENCES engine_identities(engine),
 domestic INTEGER NOT NULL CHECK(domestic IN (0,1)), stamp REAL NOT NULL, outcome TEXT NULL,
 reserved_mono REAL NULL, finished_mono REAL NULL, account_boot TEXT NOT NULL, account_mono REAL NOT NULL,
 caller TEXT NOT NULL, phase TEXT NOT NULL,
 connection_attempted INTEGER NULL CHECK(connection_attempted IN (0,1)),
 http_attempted INTEGER NULL CHECK(http_attempted IN (0,1)), elapsed REAL NULL,
 source TEXT NOT NULL CHECK(source IN ('legacy','v2')));
CREATE INDEX attempts_engine_account ON attempts(engine,account_boot,account_mono);
CREATE INDEX attempts_domestic_account ON attempts(domestic,account_boot,account_mono);
CREATE INDEX attempts_dispatch ON attempts(dispatch_id);
CREATE TABLE pauses (
 engine TEXT PRIMARY KEY REFERENCES engine_identities(engine), strikes INTEGER NOT NULL CHECK(strikes>=0), until REAL NOT NULL);
CREATE TABLE poison (reason TEXT NOT NULL);
CREATE TABLE release_checks (
 release_id TEXT PRIMARY KEY, artifact_digest TEXT NOT NULL, config_digest TEXT NOT NULL, boot TEXT NOT NULL,
 claimed_mono REAL NOT NULL, deadline_mono REAL NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('claimed','complete','unknown')),
 ingress_used INTEGER NOT NULL CHECK(ingress_used IN (0,1)), finished_mono REAL NULL, evidence_json TEXT NULL);
CREATE TABLE recoveries (
 recovery_id INTEGER PRIMARY KEY, authorization TEXT NOT NULL, old_checkpoint TEXT NOT NULL,
 old_poison_json TEXT NOT NULL, new_boot TEXT NOT NULL, wall REAL NOT NULL, mono REAL NOT NULL, decision TEXT NOT NULL);
CREATE TABLE recovery_attempts (
 recovery_id INTEGER NOT NULL REFERENCES recoveries(recovery_id), attempt_id INTEGER NOT NULL REFERENCES attempts(attempt_id),
 old_row_json TEXT NOT NULL, PRIMARY KEY(recovery_id,attempt_id));
CREATE TABLE recovery_pauses (
 recovery_id INTEGER NOT NULL REFERENCES recoveries(recovery_id), engine TEXT NOT NULL REFERENCES engine_identities(engine),
 old_strikes INTEGER NULL, old_until REAL NULL, PRIMARY KEY(recovery_id,engine));
PRAGMA user_version=2;
"""
TABLES = frozenset((
    'state', 'contract_meta', 'engine_identities', 'aliases', 'attempts', 'pauses', 'poison',
    'release_checks', 'recoveries', 'recovery_attempts', 'recovery_pauses',
))
CURRENT_DISPATCH = ContextVar('wag_protection_dispatch', default=None)


def _clock():
    return {'wall': time.time(), 'mono': time.monotonic(),
            'boot': Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()}


def _valid_clock(clock):
    return (isinstance(clock, dict) and set(clock) == {'wall', 'mono', 'boot'}
            and finite(clock['wall']) and finite(clock['mono'])
            and isinstance(clock['boot'], str) and 0 < len(clock['boot']) <= 128)


def _clock_matches(previous, now):
    return (_valid_clock(previous) and _valid_clock(now) and previous['boot'] == now['boot']
            and now['wall'] >= previous['wall'] and now['mono'] >= previous['mono']
            and abs((now['wall'] - previous['wall']) - (now['mono'] - previous['mono'])) <= 2.0)


def _secure(path, manifest, directory=False):
    canonical_path(path)
    info = path.stat(follow_symlinks=False)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or (not directory and info.st_nlink != 1):
        raise ProtectionError('identity_error')
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid not in manifest['allowed_uids'] or info.st_gid != manifest['shared_gid']:
        raise ProtectionError('identity_error')
    if mode & 0o007 or (not directory and mode & 0o111) or not mode & 0o600:
        raise ProtectionError('identity_error')
    return info


def _commit(db, root):
    db.commit()
    # SQLite FULL protects the journal transaction; also persist directory entries.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _schema_signature(db):
    objects = tuple(tuple(row) for row in db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'
    ))
    tables = []
    for name in sorted(TABLES):
        columns = tuple(tuple(row) for row in db.execute(f'PRAGMA table_xinfo("{name}")'))
        foreign_keys = tuple(tuple(row) for row in db.execute(f'PRAGMA foreign_key_list("{name}")'))
        indices = []
        for row in db.execute(f'PRAGMA index_list("{name}")'):
            # PRAGMA enumeration order is not part of the durable contract.
            index = tuple(row)[1:]
            index_name = index[0].replace('"', '""')
            fields = tuple(tuple(field) for field in db.execute(f'PRAGMA index_xinfo("{index_name}")'))
            indices.append((index, fields))
        tables.append((name, columns, foreign_keys, tuple(sorted(indices))))
    return objects, tuple(tables)


def _validate_schema(db):
    # Compile only the reviewed v2 DDL. No on-disk creation or schema repair;
    # legacy schemas belong to the separately authorized migration API.
    reference = sqlite3.connect(':memory:')
    try:
        reference.executescript(SCHEMA)
        if db.execute('SELECT 1 FROM sqlite_temp_master LIMIT 1').fetchone() or (
            _schema_signature(db) != _schema_signature(reference)
        ):
            raise ProtectionError('schema_error')
    finally:
        reference.close()


def _insert_registry(db, registry):
    for entry in registry:
        db.execute('INSERT INTO engine_identities VALUES (?,?,?,?,?,?)', (
            entry['engine'], int(entry['domestic']), entry['module'], entry['capability'],
            entry['source_digest'], canonical_json(entry['profile']),
        ))
        db.executemany('INSERT INTO aliases VALUES (?,?)', [(alias, entry['engine']) for alias in entry['aliases']])


def initialize_fixture(root, *, registry, clock):
    """Create disposable synthetic state only, never a production identity."""
    root = canonical_path(root)
    temporary_root = canonical_path(tempfile.gettempdir())
    if (root == PRODUCTION_ROOT or PRODUCTION_ROOT in root.parents or root == temporary_root
            or temporary_root not in root.parents or root.exists() or Path(str(root) + '.identity').exists()):
        raise ValueError('fixture requires a new explicit disposable root')
    registry = validate_registry(registry)
    now = clock()
    if not _valid_clock(now):
        raise ValueError('invalid fixture clock')
    root.mkdir(mode=0o700)
    identity = secrets.token_hex(16).encode('ascii')
    for path, data in ((root / 'identity', identity), (Path(str(root) + '.identity'), identity), (root / 'lock', b'')):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    fd = os.open(root / 'ledger.sqlite', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    db = sqlite3.connect(root / 'ledger.sqlite', timeout=0)
    try:
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA foreign_keys=ON')
        db.executescript(SCHEMA)
        db.execute('INSERT INTO state VALUES (?,?,?)', (identity.decode('ascii'), str(root), canonical_json(now)))
        db.execute('INSERT INTO contract_meta VALUES (1,2,?,?,?,?)',
                   (json_digest(registry), now['wall'], now['mono'], now['boot']))
        _insert_registry(db, registry)
        _commit(db, root)
    finally:
        db.close()


class DispatchNotification:
    """One dispatch's cancellation notice; never contains a context, DB or FD."""

    def __init__(self):
        self._pid = os.getpid()
        self._worker = None
        self._lock = threading.Lock()
        self._cancelled = threading.Event()
        self._requested = threading.Event()
        self._result = None

    def _check_pid(self):
        if os.getpid() != self._pid:
            raise ProtectionError('capability_refused')

    def _bind(self):
        self._check_pid()
        with self._lock:
            if self._worker is not None:
                raise ProtectionError('capability_refused')
            self._worker = threading.get_ident()

    @property
    def cancelled(self):
        self._check_pid()
        return self._cancelled.is_set()

    @property
    def cancellation_requested(self):
        self._check_pid()
        return self._requested.is_set()

    def cancel(self):
        """Request stop, without claiming that the sender has stopped."""
        self._check_pid()
        with self._lock:
            if self._result is None:
                self._requested.set()

    def notify(self):
        self._check_pid()
        # This mutex only arbitrates notification/publication. Neither side
        # holds it during I/O or while waiting for the owning worker to stop.
        with self._lock:
            if self._result is None:
                self._cancelled.set()
            return self._result

    def _publish(self, result, *, unfinished=False):
        self._check_pid()
        if self._worker != threading.get_ident():
            raise ProtectionError('capability_refused')
        with self._lock:
            if not unfinished and (self.cancelled or (
                    self.cancellation_requested and getattr(result, 'outcome', None) != 'cancelled')):
                return False
            self._result = result
            return True


class Store:
    """A validated handle, not a cached admission or a transferable lock."""

    def __init__(self, root, manifest, mode):
        self.root = root
        self.manifest = manifest
        self.mode = mode
        self.pid = os.getpid()

    @contextmanager
    def _locked(self, *, readonly=False):
        if self.pid != os.getpid():
            raise ProtectionError('capability_refused')
        for path, directory in ((self.root, True), (self.root / 'lock', False),
                                (self.root / 'identity', False), (self.root / 'ledger.sqlite', False),
                                (Path(str(self.root) + '.identity'), False)):
            _secure(path, self.manifest, directory)
        for suffix in ('-journal', '-wal', '-shm'):
            path = Path(str(self.root / 'ledger.sqlite') + suffix)
            if path.exists() or path.is_symlink():
                _secure(path, self.manifest)
                if suffix != '-journal':
                    raise ProtectionError('schema_error')
        fd = os.open(self.root / 'lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        db = None
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EACCES):
                    raise ProtectionError('lock_busy') from None
                raise
            if os.fstat(fd).st_ino != (self.root / 'lock').stat().st_ino:
                raise ProtectionError('identity_error')
            uri = 'file:' + quote(str(self.root / 'ledger.sqlite')) + ('?mode=ro' if readonly else '?mode=rw')
            db = sqlite3.connect(uri, uri=True, timeout=0, check_same_thread=False)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            self._validate(db)
            yield db
        finally:
            if db is not None:
                db.close()
            os.close(fd)

    def _validate(self, db):
        if db.execute('PRAGMA journal_mode').fetchone()[0] != 'delete':
            raise ProtectionError('schema_error')
        if db.execute('PRAGMA user_version').fetchone()[0] != VERSION:
            raise ProtectionError('schema_error')
        _validate_schema(db)
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or db.execute('PRAGMA foreign_key_check').fetchone():
            raise ProtectionError('schema_error')
        states = db.execute('SELECT * FROM state').fetchall()
        if len(states) != 1:
            raise ProtectionError('identity_error')
        state = states[0]
        identity = (self.root / 'identity').read_bytes()
        anchor = Path(str(self.root) + '.identity').read_bytes()
        if (not hex_value(state['id'], 32) or identity != state['id'].encode('ascii') or anchor != identity
                or state['root'] != str(self.root)):
            raise ProtectionError('identity_error')
        if not _valid_clock(load_json(state['checkpoint'])):
            raise ProtectionError('clock_error')
        meta = db.execute('SELECT * FROM contract_meta').fetchall()
        if (len(meta) != 1 or meta[0]['singleton'] != 1 or meta[0]['version'] != VERSION
                or meta[0]['registry_digest'] != self.manifest['registry_digest']
                or not finite(meta[0]['migration_wall']) or not finite(meta[0]['migration_mono'])
                or not meta[0]['migration_boot']):
            raise ProtectionError('schema_error')
        expected = {entry['engine']: entry for entry in self.manifest['registry']}
        actual = db.execute('SELECT * FROM engine_identities').fetchall()
        if len(actual) != len(expected):
            raise ProtectionError('provenance_error')
        for entry in actual:
            approved = expected.get(entry['engine'])
            if approved is None or tuple(entry) != (
                approved['engine'], int(approved['domestic']), approved['module'], approved['capability'],
                approved['source_digest'], canonical_json(approved['profile']),
            ):
                raise ProtectionError('provenance_error')
        aliases = {alias: entry['engine'] for entry in expected.values() for alias in entry['aliases']}
        if dict(db.execute('SELECT alias,engine FROM aliases').fetchall()) != aliases:
            raise ProtectionError('provenance_error')
        for row in db.execute('SELECT * FROM attempts'):
            if (not isinstance(row['dispatch_id'], str) or not 1 <= len(row['dispatch_id']) <= 80
                    or row['domestic'] not in (0, 1) or row['domestic'] != int(expected[row['engine']]['domestic'])
                    or not finite(row['stamp']) or not finite(row['account_mono']) or not row['account_boot']
                    or row['caller'] not in CALLERS or row['phase'] not in PHASES
                    or row['source'] not in ('legacy', 'v2')
                    or (row['outcome'] is not None and row['outcome'] not in OUTCOMES)):
                raise ProtectionError('schema_error')
            for name in ('reserved_mono', 'finished_mono', 'elapsed'):
                if row[name] is not None and not finite(row[name]):
                    raise ProtectionError('schema_error')
            for name in ('connection_attempted', 'http_attempted'):
                if row[name] is not None and (type(row[name]) is not int or row[name] not in (0, 1)):
                    raise ProtectionError('schema_error')
            if row['source'] == 'v2' and row['reserved_mono'] is None:
                raise ProtectionError('schema_error')
        for row in db.execute('SELECT * FROM pauses'):
            if type(row['strikes']) is not int or row['strikes'] < 0 or not finite(row['until']):
                raise ProtectionError('schema_error')

    def _admit(self, db, now, *, dispatch_id=None, engine=None, deadline=None, persist_clock=True):
        checkpoint = load_json(db.execute('SELECT checkpoint FROM state').fetchone()[0])
        if not _clock_matches(checkpoint, now):
            if persist_clock:
                db.execute('INSERT INTO poison VALUES (?)', ('clock_error',))
                _commit(db, self.root)
            raise ProtectionError('clock_error')
        poison = db.execute('SELECT reason FROM poison ORDER BY rowid LIMIT 1').fetchone()
        if poison:
            raise ProtectionError(poison[0] if poison[0] in REASONS else 'storage_error')
        unfinished = db.execute('SELECT dispatch_id FROM attempts WHERE outcome IS NULL').fetchall()
        if any(row[0] != dispatch_id for row in unfinished):
            raise ProtectionError('unfinished_attempt')
        if deadline is not None and (not finite(deadline) or now['mono'] >= deadline):
            raise ProtectionError('deadline_exceeded')
        if engine is None:
            return
        if engine['profile']['live_hold']:
            raise ProtectionError('operator_hold')
        pause = db.execute('SELECT until FROM pauses WHERE engine=?', (engine['engine'],)).fetchone()
        if pause and now['mono'] < pause[0]:
            raise ProtectionError('cooldown')
        args = (engine['engine'], now['boot'], now['mono'] - 60)
        if db.execute('SELECT count(*) FROM attempts WHERE engine=? AND account_boot=? AND account_mono>?', args).fetchone()[0] >= 6:
            raise ProtectionError('engine_rate')
        if engine['domestic'] and db.execute(
            'SELECT count(*) FROM attempts WHERE domestic=1 AND account_boot=? AND account_mono>?',
            (now['boot'], now['mono'] - 60),
        ).fetchone()[0] >= 30:
            raise ProtectionError('domestic_rate')

    def run_engine(self, engine_name, *, caller, deadline_mono, build, send, parse, observer=None):
        if observer is not None:
            if not isinstance(observer, DispatchNotification):
                return Refusal('capability_refused')
            try:
                observer._bind()
            except ProtectionError as error:
                return Refusal(error.reason)
        if caller not in CALLERS or caller == 'legacy_probe':
            return Refusal('capability_refused')
        context = None
        token = None
        try:
            with self._locked() as db:
                canonical = db.execute('SELECT engine FROM aliases WHERE alias=?', (engine_name,)).fetchone()
                if canonical is None:
                    return Refusal('capability_refused')
                entry = next(entry for entry in self.manifest['registry'] if entry['engine'] == canonical[0])
                now = _clock()
                self._admit(db, now, engine=entry, deadline=deadline_mono)
                context = Dispatch(self, db, entry, caller, deadline_mono, now, observer)
                context.reserve('engine_http')
                token = CURRENT_DISPATCH.set(context)
                outcome = 'request_refused'
                results = None
                result_count = None
                suspension_s = 0
                try:
                    context.phase = 'build'
                    request = build()
                    context.check_deadline()
                    outcome = 'error'
                    context.phase = 'send'
                    response = send(context, request)
                    context.check_deadline()
                    outcome = 'parser_error'
                    context.phase = 'parse'
                    results = parse(response)
                    context.check_deadline()
                    result_count = len(results) if results is not None else 0
                    outcome = 'ok' if result_count else 'empty'
                except EngineFailure as error:
                    outcome = error.outcome
                    suspension_s = error.suspension_s
                except ProtectionError as error:
                    outcome = {'deadline_exceeded': 'timeout', 'capability_refused': 'runtime_error'}.get(error.reason, error.reason)
                    if outcome not in OUTCOMES:
                        outcome = 'error'
                except Exception:  # callbacks may contain private request/response data
                    pass
                finished = _clock()
                if not _clock_matches(now, finished):
                    db.execute('INSERT INTO poison VALUES (?)', ('clock_error',))
                    _commit(db, self.root)
                    return Refusal('clock_error')
                if context.unfinished or (observer is not None and (
                        observer.cancelled or (observer.cancellation_requested and finished['mono'] >= deadline_mono))):
                    return context.finish_unfinished()
                db.execute('UPDATE attempts SET outcome=?,stamp=?,finished_mono=?,account_boot=?,account_mono=?,elapsed=? WHERE dispatch_id=?',
                           (outcome, finished['mono'], finished['mono'], finished['boot'], finished['mono'],
                            finished['mono'] - now['mono'], context.dispatch_id))
                if outcome in ('captcha', 'access_denied', 'rate_limited', 'challenge_unknown'):
                    previous = db.execute('SELECT strikes,until FROM pauses WHERE engine=?', (entry['engine'],)).fetchone()
                    strikes = (previous['strikes'] if previous else 0) + 1
                    until = max(previous['until'] if previous else 0,
                                finished['mono'] + max(suspension_s, 1800 * 2 ** min(strikes - 1, 16)))
                    db.execute('INSERT OR REPLACE INTO pauses VALUES (?,?,?)', (entry['engine'], strikes, until))
                elif outcome == 'ok' and result_count:
                    db.execute('DELETE FROM pauses WHERE engine=?', (entry['engine'],))
                db.execute('UPDATE state SET checkpoint=?', (canonical_json(finished),))
                _commit(db, self.root)
                result = EngineOutcome(entry['engine'], outcome, len(context.rows), context.connections, context.headers,
                                       result_count, finished['mono'] - now['mono'], finished['mono'] >= deadline_mono, results)
                if observer is not None and not observer._publish(result):
                    # Notification may arrive during the completion fsync. The
                    # worker still owns the flock and must persist uncertainty.
                    return context.finish_unfinished()
                return result
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError, StopIteration):
            return Refusal('schema_error')
        finally:
            if context is not None:
                context.active = False
            if token is not None:
                CURRENT_DISPATCH.reset(token)

    def _release_fingerprint(self, release_id, artifact_digest, config_digest):
        if (not hex_value(release_id, 32) or artifact_digest != self.manifest['artifact_digest']
                or config_digest != self.manifest['config_digest']):
            raise ProtectionError('release_consumed')

    def _release_row(self, db, release_id, artifact_digest, config_digest, now):
        self._release_fingerprint(release_id, artifact_digest, config_digest)
        self._admit(db, now)
        row = db.execute('SELECT * FROM release_checks WHERE release_id=?', (release_id,)).fetchone()
        if (row is None or row['artifact_digest'] != artifact_digest or row['config_digest'] != config_digest
                or row['boot'] != now['boot'] or now['mono'] >= row['deadline_mono']):
            raise ProtectionError('release_consumed')
        return row

    def claim_release(self, release_id, artifact_digest, config_digest, deadline_mono):
        try:
            with self._locked() as db:
                now = _clock()
                self._release_fingerprint(release_id, artifact_digest, config_digest)
                self._admit(db, now)
                if not finite(deadline_mono) or not now['mono'] < deadline_mono <= now['mono'] + 10:
                    return Refusal('deadline_exceeded')
                if db.execute('SELECT 1 FROM release_checks WHERE release_id=?', (release_id,)).fetchone():
                    return Refusal('release_consumed')
                db.execute('INSERT INTO release_checks VALUES (?,?,?,?,?,?,?,0,NULL,NULL)',
                           (release_id, artifact_digest, config_digest, now['boot'], now['mono'], deadline_mono, 'claimed'))
                db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
                _commit(db, self.root)
                return ReleaseReceipt(self, release_id, artifact_digest, config_digest)
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')

    def consume_release_ingress(self, release_id, artifact_digest, config_digest):
        try:
            with self._locked() as db:
                now = _clock()
                row = self._release_row(db, release_id, artifact_digest, config_digest, now)
                if row['state'] != 'unknown' or row['ingress_used'] != 0:
                    return Refusal('release_consumed')
                db.execute('UPDATE release_checks SET ingress_used=1 WHERE release_id=?', (release_id,))
                db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
                _commit(db, self.root)
                return True
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')

    def run_release_check(self, receipt, operation):
        if (not isinstance(receipt, ReleaseReceipt) or receipt.store is not self or receipt.consumed
                or receipt.pid != os.getpid() or receipt.thread != threading.get_ident()):
            return Refusal('release_consumed')
        receipt.consumed = True
        try:
            with self._locked() as db:
                row = self._release_row(db, receipt.release_id, receipt.artifact, receipt.config, _clock())
                if row['state'] != 'claimed' or row['ingress_used'] != 0:
                    return Refusal('release_consumed')
                db.execute('UPDATE release_checks SET state=? WHERE release_id=?', ('unknown', receipt.release_id))
                _commit(db, self.root)
            # The short claim lock MUST be released before any MCP/native operation.
            try:
                evidence = load_json(canonical_json(operation()))
                validate_evidence(evidence)
            except Exception:
                return Refusal('evidence_unknown')
            with self._locked() as db:
                now = _clock()
                row = self._release_row(db, receipt.release_id, receipt.artifact, receipt.config, now)
                if row['state'] != 'unknown' or row['ingress_used'] != 1 or evidence['age_s'] != 0:
                    return Refusal('evidence_unknown')
                if (evidence['release_id'] != receipt.release_id or evidence['artifact_digest'] != receipt.artifact
                        or evidence['config_digest'] != receipt.config):
                    return Refusal('provenance_error')
                db.execute('UPDATE release_checks SET state=?,finished_mono=?,evidence_json=? WHERE release_id=?',
                           ('complete', now['mono'], canonical_json(evidence), receipt.release_id))
                db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
                _commit(db, self.root)
                return evidence
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')

    def public_snapshot(self, artifact_digest, config_digest, *, max_age_s=60):
        try:
            with self._locked(readonly=True) as db:
                now = _clock()
                self._admit(db, now, persist_clock=False)
                if (artifact_digest != self.manifest['artifact_digest'] or config_digest != self.manifest['config_digest']
                        or not finite(max_age_s) or max_age_s > 60):
                    return Refusal('provenance_error')
                row = db.execute('''SELECT * FROM release_checks WHERE artifact_digest=? AND config_digest=?
                    ORDER BY claimed_mono DESC,rowid DESC LIMIT 1''', (artifact_digest, config_digest)).fetchone()
                if (row is None or row['state'] != 'complete' or row['ingress_used'] != 1
                        or row['boot'] != now['boot'] or row['finished_mono'] is None
                        or not 0 <= now['mono'] - row['finished_mono'] <= max_age_s or row['evidence_json'] is None):
                    return Refusal('evidence_unknown')
                evidence = validate_evidence(load_json(row['evidence_json']))
                if (evidence['release_id'] != row['release_id'] or evidence['artifact_digest'] != artifact_digest
                        or evidence['config_digest'] != config_digest):
                    return Refusal('provenance_error')
                evidence['age_s'] = now['mono'] - row['finished_mono']
                return evidence
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')


class ReleaseReceipt:
    """Only the claiming stack can consume this ephemeral execution receipt."""

    def __init__(self, store, release_id, artifact, config):
        self.store = store
        self.release_id = release_id
        self.artifact = artifact
        self.config = config
        self.pid = os.getpid()
        self.thread = threading.get_ident()
        self.consumed = False


class Dispatch:
    """Internal, stack-scoped adapter context; never a reusable admission token."""

    def __init__(self, store, db, entry, caller, deadline, started, observer=None):
        self.observer = observer
        self.store = store
        self.db = db
        self.entry = entry
        self.caller = caller
        self.deadline = deadline
        self.started = started
        self.pid = os.getpid()
        self.owner_thread = threading.get_ident()
        self.async_thread = None
        self.dispatch_id = secrets.token_hex(16)
        self.rows = []
        self.active = True
        self.unfinished = False
        self.phase = 'reserve'
        self.connections = 0
        self.headers = 0
        self.main_calls = 0
        self.armed_row = None
        self.proxy_connect = False

    def check_deadline(self):
        if (not self.active or self.pid != os.getpid() or CURRENT_DISPATCH.get() is not self
                or threading.get_ident() not in (self.owner_thread, self.async_thread)):
            raise ProtectionError('capability_refused')
        if (self.observer is not None and self.observer.cancelled) or time.monotonic() >= self.deadline:
            if self.observer is not None:
                self.unfinished = True
            raise ProtectionError('deadline_exceeded')
        if self.observer is not None and self.observer.cancellation_requested:
            raise EngineFailure('cancelled')

    def finish_unfinished(self):
        if threading.get_ident() != self.owner_thread or os.getpid() != self.pid:
            raise ProtectionError('capability_refused')
        self.unfinished = True
        self.db.execute('UPDATE attempts SET outcome=NULL,finished_mono=NULL,elapsed=NULL WHERE dispatch_id=?',
                        (self.dispatch_id,))
        self.db.execute('INSERT INTO poison VALUES (?)', ('unfinished_attempt',))
        _commit(self.db, self.store.root)
        result = Refusal('unfinished_attempt')
        if self.observer is not None:
            self.observer._publish(result, unfinished=True)
        return result

    def run_async(self, operation, loop):
        """Bind this one dispatch explicitly while the flock-owning thread waits."""
        self.check_deadline()
        if (threading.get_ident() != self.owner_thread or self.phase != 'send'
                or self.async_thread is not None or loop is None):
            raise ProtectionError('capability_refused')
        stopped = threading.Event()
        async def execute():
            token = CURRENT_DISPATCH.set(self)
            self.async_thread = threading.get_ident()
            try:
                self.check_deadline()
                return await operation()
            finally:
                self.async_thread = None
                CURRENT_DISPATCH.reset(token)
        future = concurrent.futures.Future()
        task = None
        def completed(done):
            try:
                if not future.done():
                    if done.cancelled():
                        future.set_exception(EngineFailure('cancelled'))
                    elif done.exception() is not None:
                        future.set_exception(done.exception())
                    else:
                        future.set_result(done.result())
            finally:
                stopped.set()
        def begin():
            nonlocal task
            if self.unfinished:
                stopped.set()
                return
            task = loop.create_task(execute())
            task.add_done_callback(completed)
        def cancel():
            if task is not None:
                task.cancel()
            else:
                stopped.set()
        loop.call_soon_threadsafe(begin)
        cancellation_sent = False
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                self.unfinished = True
                if not cancellation_sent:
                    loop.call_soon_threadsafe(cancel)
                # Only the task completion callback proves stop. An uncooperative
                # sender keeps the owning worker's flock until it actually exits.
                stopped.wait()
                raise EngineFailure('timeout') from None
            if (self.observer is not None and (
                    self.observer.cancellation_requested or self.observer.cancelled)) and not cancellation_sent:
                loop.call_soon_threadsafe(cancel)
                cancellation_sent = True
            try:
                return future.result(min(remaining, 0.02) if self.observer is not None else remaining)
            except concurrent.futures.TimeoutError:
                continue

    def reserve(self, phase):
        now = _clock()
        self.db.execute('BEGIN IMMEDIATE')
        self.store._admit(self.db, now, dispatch_id=self.dispatch_id, engine=self.entry, deadline=self.deadline)
        row = self.db.execute('''INSERT INTO attempts
            (dispatch_id,engine,domestic,stamp,outcome,reserved_mono,finished_mono,account_boot,account_mono,
             caller,phase,connection_attempted,http_attempted,elapsed,source)
            VALUES (?,?,?,?,NULL,?,NULL,?,?,?,?,0,0,NULL,'v2')''',
                              (self.dispatch_id, self.entry['engine'], int(self.entry['domestic']), now['mono'],
                               now['mono'], now['boot'], now['mono'], self.caller, phase))
        self.rows.append(row.lastrowid)
        self.db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
        _commit(self.db, self.store.root)


def open_store(root, *, manifest, mode):
    try:
        root = canonical_path(root)
        approved = validate_manifest(manifest, root, mode)
    except (OSError, ValueError, TypeError, KeyError, PackageNotFoundError):
        return Refusal('provenance_error')
    try:
        store = Store(root, approved, mode)
        with store._locked():
            pass
        return store
    except ProtectionError as error:
        return Refusal(error.reason)
    except FileNotFoundError:
        return Refusal('identity_error')
    except (OSError, sqlite3.Error):
        return Refusal('storage_error')
    except (ValueError, TypeError, KeyError):
        return Refusal('schema_error')
