"""Conservative boundaries for publishing subscription content independently."""
import copy

from . import state as registry, subscription


def subscription_only(args, state, secret, extra):
    if getattr(args, 'command', None) not in {'subscription', 'rules'} or extra:
        return False
    if not registry.logical_path(args.root, registry.STATE).exists():
        return False
    previous, credentials = registry.load(args.root)
    def infrastructure(value):
        value = copy.deepcopy(value)
        value.pop('subscription', None)
        value['rules'].pop('active_build', None)
        value['rules'].pop('channel', None)
        return value
    def node_secrets(value):
        return {key: item for key, item in value.items() if key != 'subscription_token'}
    # Domain/certificate/port/node changes and enabling the rule timer still
    # require the full stack. Only content, existing routes and tokens qualify.
    if infrastructure(previous) != infrastructure(state) or node_secrets(credentials) != node_secrets(secret):
        return False
    hosts = {state['domains']['subscription'], *state['domains']['subscription_aliases']}
    return all(route['host'] in hosts for route in subscription.routes(state, secret['subscription_token']))


def compile_subscription(state, secret, snapshot):
    registry.validate(state, secret)
    files = subscription.render(state, secret, snapshot)
    files[registry.STATE] = registry.encode(state)
    files[registry.SECRETS] = registry.encode(secret)
    return files
