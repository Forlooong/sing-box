import copy
import contextlib
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sbmanager import cli, protocols, publication, server, state, subscription, system
from sbmanager.transaction import Transaction


class SubscriptionPublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.public, self.secret = state.create('site.example.com', 'sub.example.com', 'admin@example.com')
        node, credentials = protocols.parse_uri('hy2://fixture@site.example.com:443?sni=site.example.com#HY2')
        self.public['nodes'] = [node]
        self.public['rules']['enabled'] = False
        self.secret['nodes'][node['id']] = credentials
        self.runtime = state.logical_path(self.root, subscription.DIRECTORY + '/runtime.json')
        self.runtime.parent.mkdir(parents=True)
        self.runtime.write_bytes(subscription.render(self.public, self.secret)[subscription.DIRECTORY + '/runtime.json'])
        self.service = server.create_server(self.runtime, port=0)
        self.public['ports']['sub_http'] = self.service.server_port
        self.before = subscription.render(self.public, self.secret)[subscription.DIRECTORY + '/runtime.json']
        self.runtime.write_bytes(self.before)
        self.service.bundle = server.load_bundle(self.runtime)
        self.worker = threading.Thread(target=self.service.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.close)
        for name, data in ((state.STATE, self.public), (state.SECRETS, self.secret)):
            target = state.logical_path(self.root, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(state.encode(data))

    def close(self):
        self.service.shutdown()
        self.service.server_close()
        self.worker.join(3)

    def test_rejected_reload_rolls_back_instead_of_accepting_old_http_200(self):
        candidate = copy.deepcopy(self.public)
        candidate['subscription']['name'] = 'After'
        files = subscription.render(candidate, self.secret)
        def reject_reload(_):
            with patch.object(server, 'load_bundle', side_effect=OSError('injected read failure')):
                with self.assertRaises(OSError):
                    self.service.reload()
        real_path = state.logical_path
        with patch.object(system, 'run'), patch('sbmanager.probe.local_nodes'), \
             patch.object(system, 'logical_path', side_effect=lambda _, name: real_path(self.root, name)), \
             patch.object(system.time, 'monotonic', side_effect=[0, 0, 30]), \
             patch.object(system.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'generation|readiness'):
                Transaction(self.root).apply(files, activate=reject_reload,
                    health=lambda: system.health(candidate, self.secret),
                    restore_services=lambda _: self.service.reload())
        self.assertEqual(self.runtime.read_bytes(), self.before)
        journal = next((self.root / 'var/backups/sb/transactions').glob('*/journal.json'))
        self.assertEqual(json.loads(journal.read_bytes())['status'], 'rolled-back')
        self.assertEqual(self.service.bundle['generation'], json.loads(self.before)['generation'])

    def test_success_requires_candidate_generation(self):
        candidate = copy.deepcopy(self.public)
        candidate['subscription']['name'] = 'After'
        files = subscription.render(candidate, self.secret)
        real_path = state.logical_path
        with patch.object(system, 'run'), patch('sbmanager.probe.local_nodes'), \
             patch.object(system, 'logical_path', side_effect=lambda _, name: real_path(self.root, name)):
            identifier = Transaction(self.root).apply(files, activate=lambda _: self.service.reload(),
                health=lambda: system.health(candidate, self.secret))
        journal = self.root / 'var/backups/sb/transactions' / identifier / 'journal.json'
        self.assertEqual(json.loads(journal.read_bytes())['status'], 'committed')
        self.assertEqual(self.service.bundle['generation'], json.loads(files[subscription.DIRECTORY + '/runtime.json'])['generation'])

    def test_subscription_rename_publishes_while_proxy_is_down_without_touching_it(self):
        candidate = copy.deepcopy(self.public)
        candidate['subscription']['name'] = 'After'
        args = SimpleNamespace(root=self.root, offline=False, command='subscription', action='name')
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if 'sb-sing-box' in argv:
                raise RuntimeError('unrelated proxy is down')
            return ''
        def service_state(names):
            return {name: {'is-active': name != 'sb-sing-box', 'is-enabled': True} for name in names}
        with patch.object(system, 'validate_candidate') as full_validation, \
             patch.object(system, 'validate_subscription_candidate'), \
             patch.object(system, 'activate', side_effect=lambda _, record: self.service.reload()) as full_activation, \
             patch.object(system, 'activate_subscription', create=True, side_effect=lambda _, record: self.service.reload()), \
             patch.object(system, 'service_state', side_effect=service_state), \
             patch.object(system, 'restore_services'), patch.object(system, 'run', side_effect=run), \
             patch('sbmanager.probe.local_nodes') as proxy_probe:
            identifier = cli.publish(args, candidate, self.secret, label='subscription name')
        full_validation.assert_not_called()
        full_activation.assert_not_called()
        proxy_probe.assert_not_called()
        journal = json.loads((self.root / 'var/backups/sb/transactions' / identifier / 'journal.json').read_bytes())
        self.assertEqual(set(journal['services']), {'sb-subscription'})
        self.assertTrue(all(path in (state.STATE, state.SECRETS) or path.startswith(subscription.DIRECTORY + '/')
                            for path in journal['files']))
        self.assertFalse(any('sb-sing-box' in argv for argv in calls))

    def test_token_rotation_and_rollback_keep_old_url_revoked_with_proxy_down(self):
        old = self.secret['subscription_token']
        args = cli.parser().parse_args(['--root', str(self.root), 'subscription', 'rotate'])
        def run(argv, **kwargs):
            if 'sb-sing-box' in argv:
                raise RuntimeError('unrelated proxy is down')
            return ''
        stream = io.StringIO()
        with patch.object(system, 'validate_subscription_candidate'), \
             patch.object(system, 'activate_subscription', side_effect=lambda _, record: self.service.reload()), \
             patch.object(system, 'service_state', side_effect=lambda names: {name: {'is-active': True, 'is-enabled': True} for name in names}), \
             patch.object(system, 'restore_services'), patch.object(system, 'run', side_effect=run), \
             contextlib.redirect_stdout(stream):
            cli.execute(args)
        identifier = json.loads(stream.getvalue())['transaction']
        current = state.load(self.root)[1]['subscription_token']
        self.assertNotEqual(old, current)
        Transaction(self.root).rollback(identifier, restore_services=lambda _: self.service.reload())
        self.assertEqual(state.load(self.root)[1]['subscription_token'], current)
        for token, expected in ((old, 404), (current, 200)):
            connection = http.client.HTTPConnection('127.0.0.1', self.service.server_port, timeout=3)
            connection.request('GET', '/private/' + token, headers={'Host': 'sub.example.com'})
            response = connection.getresponse()
            self.assertEqual(response.status, expected)
            response.read()
            connection.close()

    def test_scope_stays_full_for_network_credentials_and_timer_changes(self):
        args = SimpleNamespace(root=self.root, command='subscription')
        self.assertTrue(publication.subscription_only(args, self.public, self.secret, {}))
        changes = [lambda s: s['ports'].update(sub_http=9876),
                   lambda s: s['domains'].update(site='other.example.com'),
                   lambda s: s['nodes'][0].update(port=8443),
                   lambda s: s['rules'].update(enabled=True)]
        for change in changes:
            candidate = copy.deepcopy(self.public)
            change(candidate)
            self.assertFalse(publication.subscription_only(args, candidate, self.secret, {}))
        credentials = copy.deepcopy(self.secret)
        credentials['nodes'][self.public['nodes'][0]['id']]['password'] = 'different'
        self.assertFalse(publication.subscription_only(args, self.public, credentials, {}))
        self.assertFalse(publication.subscription_only(args, self.public, self.secret, {'/etc/sb/certificates/site.example.com/fullchain.pem': b'new'}))


if __name__ == '__main__':
    unittest.main()
