# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real native transport/parser components, on explicit synthetic loopback state."""

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from tests.unit.test_wag_protection import fixture_manifest, registry, WORKSPACE


QUARK_RESULT = ('<script type="application/json" id="s-data-fixture" data-used-by="hydrate">'
                + json.dumps({'data': {'initialData': {'title': {'content': 'Synthetic source'},
                               'source': {'url': 'https://fixture.invalid/source'},
                               'summary': {'content': 'Offline parser result'}}}, 'extraData': {'sc': 'addition'}})
                + '</script>').encode()


BING_RESULT = b'<ol id="b_results"><li class="b_algo"><h2><a href="https://bing-fixture.invalid/source">Bing synthetic</a></h2><p>Offline source</p></li></ol>'
YANDEX_RESULT = b'<li class="serp-item"><h3 class="b-serp-item__title"><a class="b-serp-item__title-link" href="https://yandex-fixture.invalid/source"><span>Yandex synthetic</span></a></h3><div class="b-serp-item__content"><div class="b-serp-item__text">Offline source</div></div></li>'
CHINASO_RESULT = json.dumps({'data': {'data': [{'title': 'ChinaSo synthetic', 'url': 'https://chinaso-fixture.invalid/source', 'snippet': 'Offline source'}]}}).encode()
HOSTS = ('quark.sm.cn', 'www.chinaso.com', 'www.bing.com', 'yandex.com')


class CountedServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), FixtureHandler)
        self.accepts = 0
        self.headers = 0
        self.connect_headers = 0
        self.tunnel_port = None

    def get_request(self):
        connection = super().get_request()
        self.accepts += 1
        return connection


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.server.headers += 1
        host = self.headers.get('Host', '').split(':')[0]
        content = {'www.bing.com': BING_RESULT, 'www.chinaso.com': CHINASO_RESULT,
                   'yandex.com': YANDEX_RESULT}.get(host, QUARK_RESULT)
        self.send_response(200)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_CONNECT(self):
        self.server.connect_headers += 1
        if self.path.split(':')[0] not in HOSTS or self.server.tunnel_port is None:
            self.send_error(403)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.flush()
        upstream = socket.create_connection(('127.0.0.1', self.server.tunnel_port))
        try:
            while True:
                ready, _, _ = select.select([self.connection, upstream], [], [], 3)
                if not ready:
                    return
                for sender in ready:
                    data = sender.recv(65536)
                    if not data:
                        return
                    (upstream if sender is self.connection else self.connection).sendall(data)
        finally:
            upstream.close()
            self.close_connection = True

    def log_message(self, *args):
        pass


class ProtectedTransportTest(unittest.TestCase):
    def setUp(self):
        original_socket = socket.socket
        original_resolve = socket.getaddrinfo

        class OnlyLoopbackSocket(original_socket):
            def connect(inner, address):
                if isinstance(address, tuple) and not ipaddress.ip_address(address[0]).is_loopback:
                    raise AssertionError('nonloopback socket denied')
                return super().connect(address)

            def connect_ex(inner, address):
                if isinstance(address, tuple) and not ipaddress.ip_address(address[0]).is_loopback:
                    raise AssertionError('nonloopback socket denied')
                return super().connect_ex(address)

        def only_loopback_resolve(host, *args, **kwargs):
            if host in HOSTS and hasattr(self, 'tls_server'):
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                         ('127.0.0.1', self.tls_server.server_port))]
            if not ipaddress.ip_address(host).is_loopback:
                raise AssertionError('nonloopback DNS denied')
            return original_resolve(host, *args, **kwargs)

        for target, replacement in [('socket.socket', OnlyLoopbackSocket), ('socket.getaddrinfo', only_loopback_resolve)]:
            guard = patch(target, replacement)
            guard.start()
            self.addCleanup(guard.stop)
        settings = patch.dict(os.environ, {
            'SEARXNG_SETTINGS_PATH': str(WORKSPACE / 'tests/unit/settings/test_settings.yml'),
            'SEARXNG_DISABLE_ETC_SETTINGS': '1',
        })
        settings.start()
        self.addCleanup(settings.stop)
        self.parent = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.parent.cleanup)
        self.root = Path(self.parent.name) / 'native-synthetic'
        import wag_protection
        self.api = wag_protection
        self.api.initialize_fixture(self.root, registry=registry(), clock=lambda: {
            'wall': time.time(), 'mono': time.monotonic(),
            'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        })
        self.manifest = fixture_manifest(self.root, registry())
        self.store = self.api.open_store(self.root, manifest=self.manifest, mode='synthetic')
        self.server = CountedServer()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def tls_fixture(self):
        parent = Path(self.parent.name)
        cert, key = parent / 'synthetic-cert.pem', parent / 'synthetic-key.pem'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
            '-out', str(cert), '-days', '1', '-subj', '/CN=quark.sm.cn', '-addext',
            'subjectAltName=' + ','.join('DNS:' + name for name in HOSTS) + ',IP:127.0.0.1',
        ], capture_output=True, check=True)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        self.tls_server = CountedServer()
        self.tls_server.socket = server_context.wrap_socket(self.tls_server.socket, server_side=True)
        thread = threading.Thread(target=self.tls_server.serve_forever, daemon=True)
        thread.start()
        def stop():
            self.tls_server.shutdown()
            self.tls_server.server_close()
            thread.join()
        self.addCleanup(stop)
        return ssl.create_default_context(cafile=str(cert))

    def engine_request(self, name):
        from searx.engines import load_engine
        engines = {
            'quark': {'quark_category': 'general', 'categories': ['general']},
            'chinaso news': {'chinaso_news_source': 'all', 'categories': ['news']},
            'bing': {'language_support': True, 'categories': ['general']},
            'yandex': {'search_type': 'web', 'categories': ['general']},
        }
        module = next(entry['module'] for entry in registry() if entry['engine'] == name)
        engine = load_engine({'name': name, 'engine': module, **engines[name]})
        self.assertIsNotNone(engine)
        params = {'pageno': 1, 'time_range': None, 'searxng_locale': 'en-US', 'language': 'en-US',
                  'safesearch': 0, 'headers': {}, 'cookies': {}}
        engine.request('offline synthetic query', params)
        self.assertTrue(params['url'])
        return engine, params

    def parsed_request(self, name, *, verify, proxy=None):
        import httpx
        from searx.network.protected import GuardedTransport
        engine, params = self.engine_request(name)
        async def request():
            async with httpx.AsyncClient(transport=GuardedTransport(verify=verify, proxy=proxy), trust_env=False) as client:
                response = await client.get(params['url'], headers=params['headers'], cookies=params['cookies'],
                                            follow_redirects=False)
                response.search_params = params
                return response
        return self.store.run_engine(name, caller='native_search', deadline_mono=time.monotonic() + 3,
                                     build=lambda: params, send=lambda context, request_params: asyncio.run(request()),
                                     parse=engine.response)

    def test_native_search_two_engines_same_query_complete_nonempty(self):
        from copy import deepcopy
        import sqlite3
        from flask import Flask
        from searx import settings
        import searx.search
        from searx.network import THREADLOCAL
        from searx.network.network import NETWORKS, done
        from searx.search.models import EngineRef, SearchQuery
        from searx.network.protected import resolved_config_digest

        previous_networks = dict(NETWORKS)
        previous_thread_context = dict(THREADLOCAL.__dict__)
        def restore_network_context():
            NETWORKS.clear()
            NETWORKS.update(previous_networks)
            THREADLOCAL.__dict__.clear()
            THREADLOCAL.__dict__.update(previous_thread_context)
        self.addCleanup(restore_network_context)
        self.tls_fixture()
        engine_settings = [
            {'name': 'bing', 'engine': 'bing', 'categories': ['general'], 'shortcut': 'bi',
             'timeout': 3.0, 'language_support': True},
            {'name': 'quark', 'engine': 'quark', 'categories': ['general'], 'shortcut': 'qk',
             'timeout': 3.0, 'quark_category': 'general'},
        ]
        approved = registry()
        for entry in approved:
            configured = next((engine for engine in engine_settings if engine['name'] == entry['engine']), None)
            if configured:
                entry['profile']['settings'] = {key: value for key, value in configured.items()
                                                if key not in ('name', 'engine')}
        root = Path(self.parent.name) / 'same-query-native'
        self.api.initialize_fixture(root, registry=approved, clock=lambda: {
            'wall': time.time(), 'mono': time.monotonic(),
            'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        })
        outgoing = deepcopy(settings['outgoing'])
        outgoing.update({'verify': str(Path(self.parent.name) / 'synthetic-cert.pem'),
                         'proxies': {}, 'source_ips': [], 'using_tor_proxy': False,
                         'request_timeout': 3.0, 'max_request_timeout': 3.0})
        manifest = fixture_manifest(root, approved)
        manifest['config_digest'] = resolved_config_digest(engine_settings, outgoing)
        manifest_path = Path(self.parent.name) / 'native-artifact.json'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        outgoing['wag_protection'] = {'enabled': True, 'root': str(root), 'artifact_manifest': str(manifest_path)}
        config = patch.dict(settings, {'engines': engine_settings, 'outgoing': outgoing})
        config.start()
        self.addCleanup(config.stop)
        self.addCleanup(done)
        searx.search.initialize(engine_settings, enable_metrics=False)
        query = SearchQuery('offline synthetic query', [EngineRef('quark', 'general'), EngineRef('bing', 'general')],
                            'en-US', 0, 1, None, 3.0)
        search = searx.search.Search(query)
        with Flask('protected-native-test').test_request_context('/search'):
            container = search.search()
        summary = search.outbound_protection
        self.assertEqual(summary['status'], 'complete')
        self.assertEqual(search.actual_timeout, 3.0)
        self.assertLessEqual(time.monotonic() - search.start_time, 3.0)
        self.assertEqual([ref['engine'] for ref in summary['engines']], ['bing', 'quark'])
        for ref in summary['engines']:
            self.assertEqual((ref['status'], ref['outcome'], ref['result_count']), ('admitted', 'ok', 1))
            self.assertEqual((ref['reservations'], ref['connection_attempts'], ref['http_attempts']), (1, 1, 1))
            self.assertFalse(ref['deadline_exceeded'])
        results = container.get_ordered_results()
        self.assertEqual(len(results), 2)
        self.assertEqual({result['title'] for result in results}, {'Bing synthetic', 'Synthetic source'})
        self.assertEqual((self.tls_server.accepts, self.tls_server.headers), (2, 2))
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            rows = db.execute('SELECT engine,outcome,reserved_mono,finished_mono,connection_attempted,http_attempted '
                              'FROM attempts ORDER BY attempt_id').fetchall()
        self.assertEqual([row[:2] for row in rows], [('bing', 'ok'), ('quark', 'ok')])
        for _, _, reserved, finished, connections, headers in rows:
            self.assertGreaterEqual(reserved, search.start_time)
            self.assertLessEqual(finished, search.start_time + 3.0)
            self.assertEqual((connections, headers), (1, 1))

    def test_four_real_request_and_response_modules_direct_https_nonempty(self):
        trust = self.tls_fixture()
        for name in ('quark', 'chinaso news', 'bing', 'yandex'):
            with self.subTest(engine=name):
                result = self.parsed_request(name, verify=trust)
                self.assertEqual(result.outcome, 'ok')
                self.assertEqual(result.result_count, 1)
                self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (1, 1, 1))
        self.assertEqual((self.tls_server.accepts, self.tls_server.headers), (4, 4))

    def test_http_connect_origin_tls_has_two_charges_not_two_connections(self):
        trust = self.tls_fixture()
        self.server.tunnel_port = self.tls_server.server_port
        result = self.parsed_request('quark', verify=trust, proxy=f'http://127.0.0.1:{self.server.server_port}')
        self.assertEqual(result.outcome, 'ok')
        self.assertEqual(result.result_count, 1)
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (2, 1, 2))
        self.assertEqual((self.server.connect_headers, self.tls_server.headers), (1, 1))

    def test_https_proxy_connect_and_origin_tls_are_real_and_charged(self):
        import httpx
        trust = self.tls_fixture()
        self.server.tunnel_port = self.tls_server.server_port
        # Use another TLS fixture as the proxy, preserving its certificate verification.
        parent = Path(self.parent.name)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(parent / 'synthetic-cert.pem', parent / 'synthetic-key.pem')
        proxy_server = CountedServer()
        proxy_server.tunnel_port = self.tls_server.server_port
        proxy_server.socket = server_context.wrap_socket(proxy_server.socket, server_side=True)
        proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
        proxy_thread.start()
        def stop_proxy():
            proxy_server.shutdown()
            proxy_server.server_close()
            proxy_thread.join()
        self.addCleanup(stop_proxy)
        proxy = httpx.Proxy(f'https://127.0.0.1:{proxy_server.server_port}', ssl_context=trust)
        result = self.parsed_request('quark', verify=trust, proxy=proxy)
        self.assertEqual(result.outcome, 'ok')
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (2, 1, 2))
        self.assertEqual((proxy_server.connect_headers, self.tls_server.headers), (1, 1))

    def test_explicit_native_thread_to_async_bridge_keeps_parser_lock(self):
        import httpx
        from searx.engines import quark
        from searx.network.client import get_loop
        from searx.network.protected import GuardedTransport
        async def request():
            async with httpx.AsyncClient(transport=GuardedTransport(verify=True), trust_env=False) as client:
                return await client.get(f'http://127.0.0.1:{self.server.server_port}/')
        def parse(response):
            self.assertEqual(self.api.open_store(self.root, manifest=self.manifest, mode='synthetic').reason, 'lock_busy')
            return quark.response(response)
        result = self.store.run_engine('quark', caller='native_search', deadline_mono=time.monotonic() + 3,
                                       build=lambda: None, send=lambda context, request_params: context.run_async(request, get_loop()),
                                       parse=parse)
        self.assertEqual(result.outcome, 'ok')
        self.assertEqual(result.result_count, 1)
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (1, 1, 1))

    def test_missing_header_trace_refuses_before_socket_creation(self):
        import httpx
        from searx.engines import quark
        from searx.network.protected import GuardedTransport
        async def request():
            transport = GuardedTransport(verify=True)
            transport.trace = None
            async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
                return await client.get(f'http://127.0.0.1:{self.server.server_port}/')
        result = self.store.run_engine('quark', caller='native_search', deadline_mono=time.monotonic() + 3,
                                       build=lambda: None, send=lambda context, request_params: asyncio.run(request()),
                                       parse=quark.response)
        self.assertNotEqual(result.outcome, 'ok')
        self.assertEqual((self.server.accepts, self.server.headers), (0, 0))

    def test_raw_native_settings_reject_non_boolean_before_schema_coercion(self):
        from searx.settings_defaults import SCHEMA, apply_schema
        for raw in ['false', 'true', 0, 1, None]:
            with self.subTest(raw=raw):
                self.assertTrue(apply_schema({'wag_protection': {'enabled': raw}}, SCHEMA['outgoing'], ['outgoing']))

    def test_direct_http_charges_one_connect_and_header_and_real_quark_parser(self):
        import httpx
        from searx.engines import quark
        from searx.network.protected import GuardedTransport

        async def request():
            async with httpx.AsyncClient(transport=GuardedTransport(verify=True), trust_env=False) as client:
                return await client.get(f'http://127.0.0.1:{self.server.server_port}/', follow_redirects=False)

        result = self.store.run_engine('quark', caller='native_search', deadline_mono=time.monotonic() + 3,
                                       build=lambda: None, send=lambda context, request_params: asyncio.run(request()),
                                       parse=quark.response)
        self.assertEqual(result.outcome, 'ok')
        self.assertEqual(result.result_count, 1)
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (1, 1, 1))
        self.assertEqual((self.server.accepts, self.server.headers), (1, 1))
        self.assertEqual(result.results[0]['title'], 'Synthetic source')


if __name__ == '__main__':
    unittest.main()
