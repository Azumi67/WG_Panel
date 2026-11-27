from models import db
from . import service as s
from .models import Audit, ManagementBot, Order
from .telegram_policy import FEATURES, SAFE_DEFAULTS, configured


def flags(values, keys):
    selected = set(values or ())
    return {key: key in selected for key in keys}


def differences(before, after):
    return {key: value for key, value in after.items() if before.get(key) != value}


def overrides(account):
    saved = s.setting('renewal_policy:'+str(account.id))
    if isinstance(saved, dict):
        return dict(saved)
    result = {}
    previous = (Order.query.filter_by(account_id=account.id, state='approved')
                .order_by(Order.reviewed_at.desc(), Order.id.desc()).first())
    original = previous.spec if previous else {}
    account_permissions = flags(account.spec.get('permissions'), s.PERMISSIONS)
    if 'permissions' in original:
        permissions = differences(flags(original['permissions'], s.PERMISSIONS), account_permissions)
        panel_override = original.get('panel_access') != account.spec.get('panel_access')
    else:
        edited = Audit.query.filter_by(action='account_permissions', details=str(account.id)).first()
        permissions = account_permissions if edited else {}
        panel_override = bool(edited)
    if permissions:
        result['permissions'] = permissions
    if panel_override:
        result['panel_access'] = bool(account.spec.get('panel_access'))
    current_limits = account.spec.get('operation_limits') or {}
    if 'operation_limits' in original:
        limits = differences(original['operation_limits'], current_limits)
    else:
        edited = Audit.query.filter_by(action='account_limits', details=str(account.id)).first()
        limits = current_limits if edited else {}
    if limits:
        result['operation_limits'] = limits
    current_network = s.setting('network_policy:'+str(account.id))
    if current_network is not None and current_network != account.spec.get('network_policy', {}):
        result['network_policy'] = current_network
    before = account.spec.get('telegram_access') or {}
    bot = db.session.get(ManagementBot, account.id)
    if bot:
        explicit = bool(bot.approved) != bool(before.get('approved'))
        if not explicit and 'approved' not in before:
            explicit = (Audit.query.filter_by(action='management_bot_approval',
                        details=f'Account {account.id}: {bool(bot.approved)}').first() is not None)
        if explicit:
            result['telegram_approved'] = bool(bot.approved)
    selected = s.setting('telegram_access:'+str(account.id))
    if selected is not None:
        changes = differences(flags(before.get('features', SAFE_DEFAULTS), FEATURES), flags(selected, FEATURES))
        if changes:
            result['telegram_features'] = changes
    return result


def remember(account, **changes):
    stored = overrides(account)
    for key, value in changes.items():
        if key in ('permissions', 'operation_limits', 'telegram_features'):
            if value:
                stored[key] = {**stored.get(key, {}), **value}
        else:
            stored[key] = value
    s.put('renewal_policy:'+str(account.id), stored)


def remember_workspace(account, selected, panel_access, limits=None):
    changed = {'permissions': differences(flags(account.spec.get('permissions'), s.PERMISSIONS), flags(selected, s.PERMISSIONS))}
    if panel_access != bool(account.spec.get('panel_access')):
        changed['panel_access'] = panel_access
    if limits is not None:
        from .limits import effective
        changed['operation_limits'] = differences(effective(account.spec), limits)
    remember(account, **changed)


def remember_telegram(account, bot, form):
    changes = {}
    approved = form.get('approved') == 'on'
    if approved != bool(bot and bot.approved):
        changes['telegram_approved'] = approved
    if form.get('telegram_features_present') == '1':
        changes['telegram_features'] = differences(flags(configured(account), FEATURES), flags(form.getlist('telegram_features'), FEATURES))
    remember(account, **changes)


def apply_purchase(account, snapshot):
    stored = overrides(account)
    s.put('renewal_policy:'+str(account.id), stored)
    spec = dict(snapshot)
    if 'permissions' in stored:
        permitted = {**flags(spec.get('permissions'), s.PERMISSIONS), **stored['permissions']}
        spec['permissions'] = [key for key in s.PERMISSIONS if permitted.get(key)]
    if 'panel_access' in stored:
        spec['panel_access'] = stored['panel_access']
    if 'operation_limits' in stored:
        spec['operation_limits'] = {**spec.get('operation_limits', {}), **stored['operation_limits']}
    if 'network_policy' in stored:
        spec['network_policy'] = stored['network_policy']
    if 'telegram_approved' in stored or 'telegram_features' in stored:
        policy = dict(spec.get('telegram_access') or {})
        current = db.session.get(ManagementBot, account.id)
        policy['approved'] = stored.get('telegram_approved', policy.get('approved', bool(current and current.approved)))
        inherited = policy['features'] if 'features' in policy else configured(account)
        selections = flags(inherited, FEATURES)
        selections.update(stored.get('telegram_features', {}))
        policy['features'] = [key for key in FEATURES if selections.get(key)]
        spec['telegram_access'] = policy
    return spec
