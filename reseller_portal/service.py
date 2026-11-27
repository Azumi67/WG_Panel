import base64
import hashlib
import json
import os
import re
import secrets
import fcntl
import time
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit, quote
from cryptography.fernet import Fernet
from flask import current_app
from werkzeug.security import generate_password_hash
from models import db, Peer, Subscription, SubscriptionPeer, InterfaceConfig, Node
from .models import Plan, Account, Ownership, Order, Setting, Audit, Notice, Throttle

GIB = 1024**3
PERMISSIONS = ('dashboard', 'peers', 'subscriptions', 'create', 'edit', 'bulk', 'delete', 'download', 'control_access', 'logs', 'rotate_link', 'network_options', 'choose_address', 'customer_unlimited', 'profiles', 'attach_existing', 'export', 'peer_template', 'portal_design', 'reset_data', 'reset_timer', 'manage_inbounds', 'backup', 'restore')

def now(): return datetime.utcnow()
def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def setting(key, default=None):
    row = next((item for item in db.session.new if isinstance(item, Setting) and item.key == key), None)
    if row is None:
        row = db.session.get(Setting, key)
    return row.value if row else default

def settings_many(keys):
    names=tuple(dict.fromkeys(str(k) for k in keys if k))
    if not names:return {}
    return {row.key:row.value for row in db.session.query(Setting).filter(Setting.key.in_(names)).all()}

def put(key, value):
    row = next((item for item in db.session.new if isinstance(item, Setting) and item.key == key), None)
    if row is not None:
        row.value = value
        return
    if db.engine.dialect.name == 'postgresql':

        from sqlalchemy.dialects.postgresql import insert as pg_insert
        statement = pg_insert(Setting).values(key=key, value=value)
        db.session.execute(statement.on_conflict_do_update(
            index_elements=[Setting.key], set_={'value': statement.excluded.value}))

        cached = db.session.identity_map.get(Setting.__mapper__.identity_key_from_primary_key((key,)))
        if cached is not None:
            db.session.expire(cached)
        return
    row = db.session.get(Setting, key)
    if row: row.value = value
    else: db.session.add(Setting(key=key, value=value))

def cipher():
    from panel_core.encryption_keys import reseller_cipher
    return reseller_cipher(current_app.config['SECRET_KEY'],
        os.environ.get('WG_RESELLER_ENCRYPTION_KEY'),
        os.environ.get('WG_RESELLER_PREVIOUS_KEYS'),
        os.environ.get('WG_RESELLER_LEGACY_SECRET'))

def encrypt(value): return cipher().encrypt(value.encode()).decode()
def decrypt(value): return cipher().decrypt(value.encode()).decode()

class WorkspaceLockTimeout(TimeoutError):
    pass


@contextmanager
def _operation_lock(filename, wait_seconds=5):
    os.makedirs(current_app.instance_path, exist_ok=True)
    path = os.path.join(current_app.instance_path, filename)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'a') as handle:
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise WorkspaceLockTimeout('Reseller operation busy')
                time.sleep(.05)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


@contextmanager
def _postgres_operation_lock(name, wait_seconds=5):
    from .network_locks import NetworkLockTimeout, _key, postgres_advisory_operation
    try:
        with postgres_advisory_operation(db.engine, [(_key(name), False)], wait_seconds):
            yield
    except NetworkLockTimeout as exc:
        raise WorkspaceLockTimeout('Reseller operation busy') from exc


def account_operation(account_id, wait_seconds=5):
    if account_id is None:
        return nullcontext()
    name = f'reseller-inventory-{int(account_id)}'
    if db.engine.dialect.name == 'postgresql':
        return _postgres_operation_lock(name, wait_seconds=wait_seconds)
    return _operation_lock(name + '.lock', wait_seconds=wait_seconds)


def _network_interface_ids(account_id, additional_interfaces=None, *, include_owned=True):


    if account_id is None:
        return None
    account = db.session.get(Account, int(account_id))
    if account is None:
        db.session.rollback()
        return None
    try:
        
        
        granted = (account.spec or {}).get('interfaces', []) if additional_interfaces is None else additional_interfaces
        if not isinstance(granted, (list, tuple, set)):
            return None
        interfaces = {int(interface_id) for interface_id in granted}
        if any(interface_id <= 0 for interface_id in interfaces):
            return None
        if not include_owned:
            return interfaces
        owned = (db.session.query(Peer.iface_id)
                 .join(Ownership, Ownership.peer_id == Peer.id)
                 .filter(Ownership.account_id == account.id,
                         Ownership.deleted.is_(False)).distinct().all())
        interfaces.update(int(interface_id) for interface_id, in owned)
        return interfaces
    except (TypeError, ValueError, OverflowError):
        return None
    finally:


        db.session.rollback()


@contextmanager
def network_operation(wait_seconds=5, account_id=None, additional_interfaces=None, *, include_owned=True):
    if db.engine.dialect.name == 'postgresql':
        from .network_locks import NetworkLockTimeout, postgres_network_operation
        from threading import current_thread
        interfaces = _network_interface_ids(account_id, additional_interfaces, include_owned=include_owned)
        if interfaces is None:
            raise ValueError('Cannot determine WireGuard interface scope.')
        started = time.monotonic()
        acquired = None
        try:
            with postgres_network_operation(db.engine, interface_ids=interfaces,
                                            wait_seconds=wait_seconds):
                acquired = time.monotonic()
                yield
        except NetworkLockTimeout as exc:
            raise WorkspaceLockTimeout(str(exc)) from exc
        finally:
            finished = time.monotonic()
            if acquired is not None and finished - started >= 2:
                current_app.logger.warning(
                    'Reseller network timing account=%s interfaces=%s source=%s wait_ms=%.0f hold_ms=%.0f',
                    account_id, sorted(interfaces) if interfaces else 'global', current_thread().name,
                    1000*(acquired-started), 1000*(finished-acquired))
    else:
        with _operation_lock('reseller-transaction.lock', wait_seconds=wait_seconds):
            yield


@contextmanager
def locked(account_id=None, wait_seconds=5, additional_interfaces=None):
    db.session.rollback()
    with account_operation(account_id, wait_seconds=wait_seconds), network_operation(wait_seconds=wait_seconds, account_id=account_id, additional_interfaces=additional_interfaces):
        try:
            yield
            db.session.commit()
        except BaseException:
            db.session.rollback()
            raise


def _target_interfaces(account_id, section, ids):
    from .management import target
    account = db.session.get(Account, account_id)
    if account is None:
        raise ValueError('Account unavailable.')
    return sorted({int(peer.iface_id) for rid in ids for peer in target(account, section, rid)[1]})


@contextmanager
def targeted_disable(account_id, section, ids, wait_seconds=1):
    db.session.rollback()
    with account_operation(account_id, wait_seconds=wait_seconds):
        try:
            interfaces = _target_interfaces(account_id, section, ids)
            with network_operation(wait_seconds=wait_seconds, account_id=account_id,
                                   additional_interfaces=interfaces, include_owned=False):
                if _target_interfaces(account_id, section, ids) != interfaces:
                    raise WorkspaceLockTimeout('Customer interface changed during the operation.')
                yield
                db.session.commit()
        except BaseException:
            db.session.rollback()
            raise


@contextmanager
def account_settings(account_id, wait_seconds=5):
    from .database import settings_transaction
    with settings_transaction(wait_seconds=wait_seconds):
        account = db.session.get(Account, account_id, with_for_update=True)
        if account is None:
            raise ValueError('Account unavailable.')
        yield account


def audit(actor, action, details):
    db.session.add(Audit(actor=str(actor)[:80], action=action, details=str(details)[:500]))

def throttle(key, limit, seconds):
    if db.engine.dialect.name == 'postgresql':

        from sqlalchemy import case
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        current = now()
        statement = pg_insert(Throttle).values(
            key=key, count=1, until=current + timedelta(seconds=seconds))
        result = db.session.execute(statement.on_conflict_do_update(
            index_elements=[Throttle.key],
            set_={
                'count': case((Throttle.until > current, Throttle.count + 1), else_=1),
                'until': case((Throttle.until > current, Throttle.until), else_=statement.excluded.until),
            },
        ).returning(Throttle.count)).scalar_one()
        return result <= limit
    row = db.session.get(Throttle, key)
    if not row:
        row = Throttle(key=key, count=0, until=now()+timedelta(seconds=seconds))
        db.session.add(row)
    if row.until <= now(): row.count, row.until = 0, now()+timedelta(seconds=seconds)
    row.count += 1
    return row.count <= limit

def integer(data, key, minimum, maximum):
    try: value = int(data.get(key, ''))
    except (ValueError, TypeError): raise ValueError(f'{key} must be a whole number.')
    if not minimum <= value <= maximum: raise ValueError(f'{key} must be between {minimum} and {maximum}.')
    return value

def validate_spec(data):
    from .limits import validate
    operation_limits=validate(data)
    try: price = Decimal(str(data.get('price', '')))
    except InvalidOperation: raise ValueError('Enter a valid price.')
    if not price.is_finite() or price <= 0 or price > Decimal('1000000000000') or price.as_tuple().exponent < -8:
        raise ValueError('Price must be positive with at most 8 decimal places.')
    currency = str(data.get('currency', '')).strip().upper()
    if not re.fullmatch(r'[A-Z0-9_-]{2,16}', currency): raise ValueError('Choose a currency, e.g. IRR, TOMAN, TRX or USDT_TRC20.')
    interfaces = sorted(set(int(x) for x in data.get('interfaces', [])))
    if not interfaces or any(db.session.get(InterfaceConfig, i) is None for i in interfaces):
        raise ValueError('Select at least one existing interface.')
    perms = sorted(set(data.get('permissions', [])) & set(PERMISSIONS))
    extras={}
    if data.get('plan_features_present')=='1':
        from .network_policy import validate as network_validate
        from .telegram_policy import FEATURES
        extras={'network_policy':network_validate(data),'telegram_access':{'approved':data.get('approved')=='on','features':[key for key in FEATURES if key in data.get('telegram_features',[])]}}
    return dict(**extras,operation_limits=operation_limits, price=str(price), currency=currency, days=integer(data,'days',1,3650),
                traffic_gib=integer(data,'traffic_gib',1,10000000), peers=integer(data,'peers',1,100000),
                subscriptions=integer(data,'subscriptions',0,100000), interfaces=interfaces,
                permissions=perms, panel_access=bool(data.get('panel_access')),
                payment_instructions=str(data.get('payment_instructions','')).strip()[:1500])

def base_url():
    url = setting('public_url', '').rstrip('/')
    p = urlsplit(url)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ('', '/'):
        raise ValueError('Configure the public HTTPS panel origin in reseller bot settings.')
    return url

def link(account): return base_url() + '/r/' + decrypt(account.link_enc)
def workspace_link(account):
    if account and account.state == 'active' and account.spec.get('panel_access'):
        try:
            return link(account)
        except ValueError:
            return None
    return None


def active(account):
    return account.state == 'active' and account.expires_at > now() and account.used_bytes < int(account.spec['traffic_gib'])*GIB

def require_active(account):
    if not active(account): raise ValueError('This account is suspended, expired, or out of traffic.')

def counts(account):
    from sqlalchemy import func
    peers,subscriptions=db.session.query(func.count(Ownership.id),func.count(func.distinct(Ownership.subscription_id))).filter(Ownership.account_id==account.id,Ownership.deleted.is_(False)).one()
    return int(peers),int(subscriptions)

def notify(account, key, body, telegram_id=None):
    from panel_core.telegram_notices import serialize
    dedupe = f'{account.id if account else 0}:{account.generation if account else 0}:{key}'
    notice = next((item for item in db.session.new if isinstance(item, Notice) and item.dedupe == dedupe), None)
    notice = notice or Notice.query.filter_by(dedupe=dedupe).first()
    if not notice:
        notice = Notice(account_id=account.id if account else None,
                        telegram_id=telegram_id or (account.telegram_id if account else None),
                        dedupe=dedupe, body_enc=encrypt(serialize(body)))
        db.session.add(notice)
    return notice

def setup(account):
    token = secrets.token_urlsafe(32)
    account.setup_hash = digest(token)
    account.setup_expires = now()+timedelta(hours=24)
    return base_url()+'/r/setup/'+token

def password_min():
    try: return max(8,min(64,int(setting('password_min_length',8))))
    except (TypeError,ValueError): return 8

def validate_password(password):
    minimum=password_min()
    if not minimum<=len(password)<=256:
        raise ValueError(f'Use a password of {minimum}–256 characters.')

def new_account(username, spec, telegram_id=None, password=None):
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,64}', username): raise ValueError('Username must be 3–64 letters, numbers, dots, hyphens or underscores.')
    if Account.query.filter_by(username=username).first(): raise ValueError('Username already exists.')
    if telegram_id and Account.query.filter_by(telegram_id=telegram_id).first(): raise ValueError('This Telegram account already has a reseller account. Use renewal.')
    if password: validate_password(password)
    base_url()
    token = secrets.token_urlsafe(32)
    acc = Account(username=username, telegram_id=telegram_id, spec=dict(spec), link_hash=digest(token), link_enc=encrypt(token), expires_at=now()+timedelta(days=spec['days']), password_hash=generate_password_hash(password) if password else None)
    db.session.add(acc); db.session.flush()
    apply_plan_defaults(acc,spec)
    return acc

def buyer_orders(telegram_id=None, account=None):
    from sqlalchemy import or_
    if account is None and telegram_id:
        account = Account.query.filter_by(telegram_id=telegram_id).first()
    if account is not None:
        owned = Order.account_id == account.id
        telegram_id = account.telegram_id
        if telegram_id:
            owned = or_(owned, (Order.account_id.is_(None)) & (Order.telegram_id == telegram_id))
        return Order.query.filter(owned)
    if not telegram_id:
        raise ValueError('An order requires an account or a private Telegram chat.')
    return Order.query.filter_by(account_id=None, telegram_id=telegram_id)


def order_buyer(order):
    if order.account_id is not None:
        return db.session.get(Account, order.account_id)
    return Account.query.filter_by(telegram_id=order.telegram_id).first() if order.telegram_id else None


def order_new(telegram_id, plan_id, *, account=None):
    if not telegram_id and account is None:
        raise ValueError('An order requires an account or a private Telegram chat.')
    if db.engine.dialect.name == 'sqlite':
        connection = db.session.connection()
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql('BEGIN IMMEDIATE')
    elif db.engine.dialect.name == 'postgresql':
        from sqlalchemy import text
        buyer = str(telegram_id or 'account:'+str(account.id))
        key = int.from_bytes(hashlib.sha256(('rp-order:'+buyer).encode()).digest()[:8], 'big', signed=True)
        db.session.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key':key})
    account = account or (Account.query.filter_by(telegram_id=telegram_id).first() if telegram_id else None)
    if account and account.state != 'active':
        raise ValueError('This account is suspended. Contact your administrator.')
    telegram_id = (account.telegram_id or '') if account else telegram_id
    plan = db.session.get(Plan, plan_id)
    if not plan or not plan.active: raise ValueError('Plan is unavailable.')
    if account and not telegram_id and not plan.spec.get('panel_access'):
        raise ValueError('This plan requires a linked Telegram account. Choose a plan with workspace access.')
    from .bot_ui import payment_problem
    problem = payment_problem(plan.spec)
    if problem: raise ValueError('Payment setup is incomplete: ' + problem)
    pending = buyer_orders(telegram_id, account).filter_by(state='pending').order_by(Order.id.desc()).first()
    if pending:


        if pending.plan_id != plan.id:
            raise ValueError('You already have a pending order for another plan. Open My orders to resume or cancel the unpaid order. If it is under review, contact support.')
        return pending
    budget = telegram_id or 'account:'+str(account.id)
    if not throttle('orders:'+budget, 5, 86400): raise ValueError('Daily purchase limit reached.')
    order = Order(telegram_id=telegram_id, account_id=account.id if account else None, plan_id=plan.id, spec={**plan.spec, 'plan_name': plan.name})
    db.session.add(order); db.session.flush()
    return order

def cancel_order(telegram_id, order_id, *, account=None):
    order = buyer_orders(telegram_id, account).filter_by(id=order_id).with_for_update().populate_existing().first()
    if order and order.state == 'cancelled':
        return order
    if not order or order.state != 'pending' or order.payment_ref:
        raise ValueError('Only an unpaid order awaiting its receipt can be cancelled.')
    order.state = 'cancelled'
    actor = 'reseller:'+str(account.id) if account else 'telegram:'+str(telegram_id)
    audit(actor, 'order_cancelled', f'order={order.id}')
    return order


def receipt(telegram_id, order_id, reference, *, account=None):
    order = buyer_orders(telegram_id, account).filter_by(id=order_id, state='pending').with_for_update().populate_existing().first()
    if not order: raise ValueError('Pending order not found.')
    reference = reference.strip()
    if reference.casefold() in ('paid', 'done', 'payment sent', 'واریز شد', 'پرداخت شد'):
        raise ValueError('Send the receipt photo or the transaction reference so the administrator can check the payment.')
    if not reference or len(reference) > 160 or not reference.isprintable():
        raise ValueError('Send a receipt photo or a single-line transaction reference of up to 160 characters.')
    if order.payment_ref:
        if order.payment_ref == reference:
            return
        raise ValueError('A receipt is already under review for this order.')
    fingerprint = digest(reference.lower())
    duplicate = Order.query.filter_by(reference_hash=fingerprint).first()
    if duplicate and duplicate.id != order.id: raise ValueError('This reference has already been submitted.')
    order.payment_ref, order.reference_hash = reference, fingerprint
    audit('reseller:'+str(account.id) if account else 'telegram:'+telegram_id, 'receipt_submitted', f'order={order.id}')

def approve(order_id, actor):
    order = db.session.get(Order, order_id)
    if not order or order.state != 'pending': raise ValueError('Order is no longer pending.')
    if not order.payment_ref: raise ValueError('A payment reference is required; independently verify the payment before approval.')
    from .models import PaymentVerification
    if not PaymentVerification.query.filter_by(order_id=order.id).first():
        raise ValueError('Settlement verification record is required before approval. Review payment independently.')
    account = order_buyer(order)
    is_renewal = account is not None
    if account is None and (order.account_id is not None or not order.telegram_id):
        raise ValueError('The account for this order is unavailable.')
    if account:
        if account.state=='deleted':raise ValueError('This reseller account was deleted.')
        pc, sc = counts(account)
        if pc > order.spec['peers'] or sc > order.spec['subscriptions']:
            raise ValueError('The new plan is smaller than current resource use; remove excess resources first.')
        excluded = (db.session.query(Ownership.id).join(Peer, Peer.id == Ownership.peer_id)
                    .filter(Ownership.account_id == account.id, Ownership.deleted.is_(False),
                            ~Peer.iface_id.in_(order.spec['interfaces'])).first())
        if excluded:
            raise ValueError('New plan excludes an interface used by existing peers.')
        if account.state == 'suspended': raise ValueError('Resolve the suspension before approving a renewal.')

        audit(actor, 'renewal_previous_period', f'account={account.id} bytes={account.used_bytes}')
        previous_expiry = account.expires_at
        from .renewal import apply_purchase
        previous_access = account.spec.get('panel_access')
        account.spec, account.used_bytes = apply_purchase(account, order.spec), 0
        account.expires_at = now()+timedelta(days=order.spec['days'])
        from .management import extend_plan_capped_customers
        extend_plan_capped_customers(account, previous_expiry)
        account.generation += 1
        if previous_access and not account.spec.get('panel_access'):
            account.session_version += 1
        apply_plan_defaults(account, account.spec)
    else:
        account = new_account('reseller_'+order.telegram_id, order.spec, order.telegram_id)
    order.state, order.account_id, order.reviewed_at, order.reviewer = 'approved', account.id, now(), str(actor)
    from .notices import account_notice
    password_url = setup(account) if workspace_link(account) and not account.password_hash else None
    message = account_notice(account, 'renewed' if is_renewal else 'approved', order=order, password_url=password_url)
    notify(account, 'approved:'+str(order.id), message)
    audit(actor, 'order_approved', f'order={order.id} account={account.id}')
    return account

def own_peer(account, peer_id):
    row = Ownership.query.filter_by(account_id=account.id, peer_id=peer_id, deleted=False).first()
    peer = db.session.get(Peer, peer_id) if row else None
    if not peer: raise ValueError('Peer not found.')
    return row, peer

def remote_counters(host, node_id, iface_name, timeout=5, *, node=None):
    try:
        if node is None:
            node = db.session.get(Node, node_id)
        path = '/api/peers?iface=' + quote(iface_name.split(':', 1)[-1], safe='')
        data = host['node_get'](node, path, timeout=timeout)
        if not isinstance(data, dict) or data.get('runtime_available') is False or not isinstance(data.get('peers'), list):
            return None
        return {p['public_key']: p for p in data['peers'] if isinstance(p, dict) and 'public_key' in p}
    except Exception:
        return None


def remote_baseline(account_id):
    return (db.session.query(InterfaceConfig.node_id, InterfaceConfig.name, Peer.public_key,
                             Peer.id, Peer.bytes_offset, Peer.used_bytes_total, Peer.status,
                             Ownership.observed_bytes, Ownership.blocked, Account.generation)
            .select_from(Ownership).join(Account, Account.id == Ownership.account_id)
            .join(Peer, Peer.id == Ownership.peer_id)
            .join(InterfaceConfig, InterfaceConfig.id == Peer.iface_id)
            .filter(Ownership.account_id == account_id, Ownership.deleted.is_(False),
                    InterfaceConfig.node_id.isnot(None)).order_by(Peer.id).all())


def prepare_remote_sample(account_id, host, budget=None):
    before = remote_baseline(account_id)
    from types import SimpleNamespace
    nodes = {n.id: SimpleNamespace(id=n.id, base_url=n.base_url, api_key=n.api_key)
             for n in Node.query.filter(Node.id.in_({row.node_id for row in before})).all()} if before else {}
    db.session.rollback()
    cache = {(row.node_id, row.name): None for row in before}
    deadline = time.monotonic() + budget if budget is not None else None
    for key in cache:
        timeout = min(5, deadline - time.monotonic()) if deadline is not None else 5
        if timeout <= 0:
            break
        if key[0] in nodes:
            cache[key] = remote_counters(host, *key, timeout=timeout, node=nodes[key[0]])
    db.session.rollback()
    return before, cache


def checked_remote_sample(account_id, prepared):
    before, cache = prepared
    if remote_baseline(account_id) != before:
        raise ValueError('Customer traffic changed during the check. Refresh the order and try again.')
    return cache


def local_runtime_snapshot(host, names):
    reader = host.get('_wg_checked_runtime_snapshot') or host['_wg_runtime_snapshot']
    return reader(names)


def local_baselines(account_id=None):
    query = (db.session.query(Ownership.account_id, Peer.id, Peer.public_key, InterfaceConfig.name,
             Peer.bytes_offset, Peer.used_bytes_total, Ownership.observed_bytes, Peer.status,
             Ownership.blocked, Account.generation)
             .select_from(Ownership).join(Account, Account.id == Ownership.account_id)
             .join(Peer, Peer.id == Ownership.peer_id).join(InterfaceConfig, InterfaceConfig.id == Peer.iface_id)
             .filter(Ownership.deleted.is_(False), InterfaceConfig.node_id.is_(None)))
    if account_id is not None:
        query = query.filter(Ownership.account_id == account_id)
    records = {}
    for aid, *peer in query:
        records.setdefault(aid, set()).add(tuple(peer))
    return records


def prepare_local_sample(host, account_id=None):
    if not callable(host.get('_wg_runtime_snapshot')):
        return None
    records = local_baselines(account_id)
    names = {peer[2] for peers in records.values() for peer in peers}
    db.session.rollback()
    return records, local_runtime_snapshot(host, names) if names else None


def sample(account, host, runtime_cache=None, peer_ids=None, local_snapshot=None, owned_rows=None):
    runtime_cache = runtime_cache if runtime_cache is not None else {}
    complete = True
    from sqlalchemy.orm import joinedload
    if owned_rows is None:
        query=Ownership.query.filter_by(account_id=account.id, deleted=False)
        if peer_ids is not None:query=query.filter(Ownership.peer_id.in_(peer_ids))
        rows=query.all()
        peers={p.id:p for p in Peer.query.options(joinedload(Peer.iface)).filter(Peer.id.in_([r.peer_id for r in rows if r.peer_id])).all()} if rows else {}
    else:
        rows = [row for row, peer in owned_rows]
        peers = {peer.id:peer for row, peer in owned_rows if peer}
    if not rows:
        return True
    pending={int(row.key.split(':',1)[1]) for row in Setting.query.filter(Setting.key.in_(['recovery_pending:'+str(pid) for pid in peers])).all() if row.value is True}
    if local_snapshot is None and callable(host.get('_wg_runtime_snapshot')):
        local_names={p.iface.name for p in peers.values() if p.id not in pending and p.iface and not p.iface.node_id}
        if local_names:
            local_snapshot = local_runtime_snapshot(host, local_names)
    snapshot = local_snapshot[0] if local_snapshot is not None else None
    unavailable = local_snapshot[2] if local_snapshot and len(local_snapshot) > 2 else ()
    for row in rows:
        peer = peers.get(row.peer_id)
        if not peer:
            row.deleted = True
            row.peer_id = None
            continue
        if peer.id in pending:continue
        if peer.iface.node_id:
            key = (peer.iface.node_id, peer.iface.name)
            if key not in runtime_cache:
                runtime_cache[key] = remote_counters(host, *key)
            snapshot_rows = runtime_cache[key]
            runtime = snapshot_rows.get(peer.public_key) if snapshot_rows is not None else None
            if runtime is None:
                if snapshot_rows is None or peer.status not in ('offline', 'blocked'):
                    complete = False
                    put('enforcement_error',f'Usage unavailable for node peer {peer.id}; counters preserved.')
                total = int(peer.used_bytes_total or 0)
            else:
                try:
                    live = int((Decimal(str(runtime.get('rx_mib',0)))+Decimal(str(runtime.get('tx_mib',0))))*1024*1024)
                    if live < 0: raise ValueError('Invalid counter')
                    total, _, _ = host['_accumulate_peer_usage'](peer,live)
                except (ValueError,TypeError,InvalidOperation):
                    complete = False
                    total = int(peer.used_bytes_total or 0)
                    put('enforcement_error',f'Invalid usage counter for peer {peer.id}; counters preserved.')
        else:
            if peer.iface.name in unavailable:
                if peer.status == 'online':
                    complete = False
                    put('enforcement_error', f'Usage unavailable for interface {peer.iface.name}.')
                continue
            if snapshot is None:total, _, _ = host['_accumulate_peer_usage'](peer)
            else:
                rx,tx=snapshot.get((peer.iface.name,peer.public_key),(0,0))
                total, _, _ = host['_accumulate_peer_usage'](peer,int(rx)+int(tx))
        delta = total if total < row.observed_bytes else total-row.observed_bytes
        account.used_bytes += delta
        row.observed_bytes = total
    return complete

def restore_plan_peer(account, row, peer, host):
    from .management import child_allowed
    if not row.blocked or not active(account) or not child_allowed(peer, account):
        return True
    try:
        activate = host.get('activate_reseller_peer') or host['reapply_peer_external']
        activate(peer)
        peer.status = 'online'
        row.blocked = False
        return True
    except Exception:
        put('enforcement_error', f'Unable to restore peer {peer.id}; retrying.')
        return False


def tick(host, account_ids=None, finish=True, runtime_cache=None, restore_queue=None, local_samples=None, import_audit=True):
    with db.session.no_autoflush:
        return _tick(host, account_ids, finish, runtime_cache, restore_queue, local_samples, import_audit)


def _tick(host, account_ids, finish, runtime_cache, restore_queue, local_samples, import_audit=True):
    from .request_guard import import_events
    if finish and import_audit:
        try:import_events()
        except TimeoutError:current_app.logger.warning('Login audit import deferred; quota enforcement continues.')
    if account_ids is None:put('enforcement_error',None)
    runtime_cache = {} if runtime_cache is None else runtime_cache
    healthy=True
    live_accounts=Account.query.filter(Account.state!='deleted')
    accounts=live_accounts.all() if account_ids is None else live_accounts.filter(Account.id.in_(account_ids)).all() if account_ids else []
    for account in accounts:
        from sqlalchemy.orm import joinedload
        owned_rows = (db.session.query(Ownership, Peer).outerjoin(Peer, Peer.id == Ownership.peer_id)
                      .options(joinedload(Peer.iface)).filter(Ownership.account_id == account.id,
                              Ownership.deleted.is_(False)).all())
        local_names = {p.iface.name for _, p in owned_rows if p and p.iface and not p.iface.node_id}
        local_snapshot = None
        if local_names and callable(host.get('_wg_runtime_snapshot')):
            observed = {(p.id, p.public_key, p.iface.name, p.bytes_offset, p.used_bytes_total, row.observed_bytes,
                         p.status, row.blocked, account.generation)
                        for row, p in owned_rows if p and p.iface and not p.iface.node_id}
            if local_samples and local_samples[0].get(account.id) == observed:
                local_snapshot = local_samples[1]
            else:
                local_snapshot = local_runtime_snapshot(host, local_names)
        if not sample(account, host, runtime_cache, local_snapshot=local_snapshot, owned_rows=owned_rows):
            healthy = False
        reason = 'suspended' if account.state != 'active' else ('expired' if account.expires_at <= now() else ('traffic_exhausted' if account.used_bytes >= account.spec['traffic_gib']*GIB else None))
        owned_rows = [(row, peer) for row, peer in owned_rows if peer is not None]
        for row, peer in owned_rows:
            if reason:
                if row.blocked and peer.status == 'offline' and peer.iface.node_id:
                    live = runtime_cache.get((peer.iface.node_id, peer.iface.name))
                    if live is not None and peer.public_key not in live:
                        continue
                was_enabled=peer.status=='online' or row.blocked
                if host['_disable_peer'](peer, 'reseller_'+reason): row.blocked = was_enabled
                else:
                    healthy=False
                    put('enforcement_error', f'Unable to disable peer {peer.id}; retrying.')
            elif row.blocked:
                if restore_queue is not None:
                    restore_queue.append(row.peer_id)
                elif not restore_plan_peer(account, row, peer, host):
                    healthy = False
        from .management import enforce_children, record_usage
        if owned_rows and enforce_children(account, host, owned_rows) is False:healthy=False
        record_usage(account,cleanup=False)
        from .presentation import peer_states
        live_peers = [peer for row, peer in owned_rows if not row.deleted]
        state_key = 'peer_states:' + str(account.id)
        current_states = {str(k): v for k, v in peer_states(
            live_peers, host, runtime_cache=runtime_cache,
            local_snapshot=local_snapshot).items()}
        previous = setting(state_key, {}) or {}
        if not isinstance(previous, dict):
            previous = {}
        try:
            age = (now() - datetime.fromisoformat(previous['at'])).total_seconds()
        except (KeyError, TypeError, ValueError):
            age = 120


        if previous.get('states') != current_states or age >= 60:
            put(state_key, {'at': now().isoformat(), 'states': current_states})
        from .plan_reminders import queue_current
        queue_current(account)
    if finish:
        put('monitor_heartbeat', now().isoformat())
    return healthy

class ProvisionCleanupRequired(RuntimeError):
    pass


PRECHECKED_USAGE = object()


@contextmanager
def provisioning(account_id, host, interface_ids=None, *, split_usage=False):
    db.session.rollback()
    remote = prepare_remote_sample(account_id, host, budget=8)
    local = prepare_local_sample(host, account_id)
    with account_operation(account_id):
        try:
            if split_usage and interface_ids and callable(host.get('_stage_reseller_peer')):
                with network_operation(account_id=account_id, additional_interfaces=[]):
                    if local is not None and local_baselines(account_id)!=local[0]:
                        raise WorkspaceLockTimeout('Usage snapshot changed; a fresh sample is required.')
                    if remote_baseline(account_id)!=remote[0]:
                        raise WorkspaceLockTimeout('Usage snapshot changed; a fresh sample is required.')
                    runtime = remote[1]
                    account = db.session.get(Account,account_id)
                    if account is None:
                        raise ValueError('Account unavailable.')
                    require_active(account)
                    heartbeat = setting('monitor_heartbeat')
                    if not heartbeat or (now()-datetime.fromisoformat(heartbeat)).total_seconds()>120:
                        raise ValueError('Usage monitor is offline. Ask the administrator to start the reseller worker.')
                    with db.session.no_autoflush:
                        if not sample(account,host,runtime_cache=runtime,local_snapshot=local[1] if local else None):
                            raise ValueError('Current node usage is unavailable. Retry after connectivity recovers.')
                    db.session.commit()
                with network_operation(account_id=account_id, additional_interfaces=interface_ids, include_owned=False):
                    yield PRECHECKED_USAGE
                    db.session.commit()
            else:
                with network_operation(account_id=account_id, additional_interfaces=interface_ids):
                    if local is not None and local_baselines(account_id)!=local[0]:
                        raise ValueError('Customer traffic changed. Review the request again.')
                    yield checked_remote_sample(account_id,remote), local[1] if local else None
                    db.session.commit()
        except BaseException:
            db.session.rollback()
            raise


def provision(account, iface_ids, name, subscription, host, options=None, count=1, existing_sub=None, on_created=None, usage_sample=None, on_external_start=None, on_external_rollback=None):
    require_active(account)
    heartbeat = setting('monitor_heartbeat')
    if not heartbeat or (now()-datetime.fromisoformat(heartbeat)).total_seconds()>120:
        raise ValueError('Usage monitor is offline. Ask the administrator to start the reseller worker.')
    if usage_sample is not PRECHECKED_USAGE:
        runtime,local=usage_sample or (None,None)
        with db.session.no_autoflush:
            if not sample(account,host,runtime_cache=runtime,local_snapshot=local):raise ValueError('Current node usage is unavailable. Retry after connectivity recovers.')
    require_active(account)
    iface_ids = sorted(set(int(i) for i in iface_ids))
    if not iface_ids or any(i not in account.spec['interfaces'] for i in iface_ids): raise ValueError('Interface is not permitted.')
    if not subscription and len(iface_ids)!=1: raise ValueError('Choose one interface for a peer.')
    from .limits import batch, effective
    batch(account,len(iface_ids)*count)
    pc, sc = counts(account)
    if pc+len(iface_ids)*count>account.spec['peers']: raise ValueError('Peer limit reached. Each subscription location counts as one peer.')
    if subscription and not existing_sub and sc+1>account.spec['subscriptions']: raise ValueError('Subscription limit reached.')
    name=name.strip()
    if not 1<=len(name)<=48 or any(ord(c)<32 for c in name): raise ValueError('Use a name of 1–48 printable characters.')
    if not 1<=count<=50 or (subscription and count!=1): raise ValueError('Choose 1–50 peers; one subscription at a time.')
    from .management import validate_options, apply_options
    values=validate_options(account, options if options is not None else {'name':name})
    aid=account.id
    sub_id=existing_sub.id if existing_sub is not None else None
    budget_key='resource_create:'+str(aid)
    limit=effective(account.spec)['create_per_minute']
    budget=db.session.get(Throttle,budget_key)
    if budget and budget.until>now() and budget.count>=limit:
        raise ValueError('Too many creation requests. Wait one minute and retry.')
    contacts=[]
    start_index=integer(options,'start_index',0,999999) if options and 'start_index' in options else 1
    for index in range(count):
        contact={}
        for source,dest in (('phone_numbers','phone_number'),('telegram_ids','telegram_id')):
            entries=(options or {}).get(source,[])
            if not isinstance(entries,list) or len(entries)>count:raise ValueError('Contact lists must have at most one entry per peer.')
            if index<len(entries):contact[dest]=entries[index]
        contacts.append(validate_options(account,{**(options or {}),'name':name,**contact}) if contact else values)
    from .network_policy import enforce_endpoint, get as network_policy
    policy=(account.generation,account.session_version,account.spec,network_policy(account))
    targets=[]
    for index,i in enumerate(iface_ids*count):
        iface=db.session.get(InterfaceConfig,i)
        if not iface: raise ValueError('Interface unavailable.')
        target={'scope':'node' if iface.node_id else 'local','iface_id':i,'iface':iface.name.split(':',1)[-1] if iface.node_id else iface.name,'node_id':iface.node_id,'server_cidr':iface.address,'listen_port':iface.listen_port,'public_key':iface.public_key}
        if options and options.get('address'):
            if 'choose_address' not in account.spec['permissions']:raise ValueError('Address selection is not permitted.')
            if count!=1 or subscription:raise ValueError('Choose an address for a single peer only.')
            from .management import requested_address
            target['peer_address']=requested_address(iface,options['address'])
        payload={'name':name if count==1 else f'{name[:40]}-{start_index+index:02}','allowed_ips':'0.0.0.0/0, ::/0','unlimited':True,'time_limit_days':0,'start_on_first_use':False}
        child_values=enforce_endpoint(account,iface,contacts[index] if not subscription else values,host)
        if child_values:
            payload.update({k:child_values[k] for k in ('allowed_ips','dns','mtu','persistent_keepalive','phone_number','telegram_id','endpoint','peer_endpoint')})
            if not subscription: payload.update({k:child_values[k] for k in ('data_limit_value','data_limit_unit','time_limit_days','start_on_first_use')},unlimited=False)
        targets.append((target,payload,child_values))
    db.session.commit()
    stage=host.get('_stage_reseller_peer')
    install=stage or host['_create_subscription_peer']
    compensation=host['PeerCreateCompensation']()
    from .database import settings_transaction
    from collections import defaultdict
    staged_addresses=defaultdict(list)
    peers=[]
    result=None
    commit_started=False
    identities=[]
    try:
        if on_external_start:on_external_start()
        for target,payload,child_values in targets:
            if stage:
                target['staged_addresses']=staged_addresses[target['iface_id']]
            peer=install(target,payload,compensation=compensation)
            staged_addresses[target['iface_id']].append(peer.address)
            peers.append(peer)
        with settings_transaction() if stage else nullcontext():
            current=db.session.get(Account,aid,with_for_update=True)
            if current is None:
                raise ValueError('Account unavailable.')
            require_active(current)
            if (current.generation,current.session_version,current.spec,network_policy(current))!=policy:
                raise ValueError('Your plan settings changed. Review the customer settings again.')
            pc,sc=counts(current)
            if pc+len(peers)>current.spec['peers'] or (subscription and not sub_id and sc+1>current.spec['subscriptions']):
                raise ValueError('The account has reached its customer limit.')
            if not throttle(budget_key,limit,60):
                raise ValueError('Too many creation requests. Wait one minute and retry.')
            sub=db.session.get(Subscription,sub_id) if sub_id is not None else None
            if sub_id is not None and not sub:
                raise ValueError('Subscription not found.')
            if subscription and not sub:
                sub=Subscription(name=name,token=secrets.token_urlsafe(32),unlimited=True,enabled=True)
                apply_options(sub,values,current)
                db.session.add(sub)
            for peer,(_,payload,child_values) in zip(peers,targets):
                if not subscription:
                    apply_options(peer,{**child_values,'name':payload['name']},current)
            db.session.add_all(peers)
            db.session.flush()
            for peer in peers:
                db.session.add(Ownership(account_id=aid,peer_id=peer.id,subscription_id=sub.id if sub else None,observed_bytes=0))
                if sub:db.session.add(SubscriptionPeer(subscription_id=sub.id,peer_id=peer.id,owned=True))
            result=dict(section='subscriptions' if sub else 'peers',ids=[sub.id] if sub else [p.id for p in peers])
            identities=[(p.id,p.public_key) for p in peers]
            audit('reseller:'+str(aid),'created_subscription' if sub else 'created_peer',name)
            if on_created:on_created(current,result)
            commit_started=True
            if not stage:db.session.commit()
        return result
    except BaseException:
        db.session.rollback()
        if commit_started:
            try:
                installed=db.session.query(Peer.id,Peer.public_key).join(Ownership,Ownership.peer_id==Peer.id).filter(
                    Ownership.account_id==aid,Ownership.deleted.is_(False),Peer.id.in_([pid for pid,_ in identities])).all()
            except Exception:
                raise ProvisionCleanupRequired('Unable to verify the database commit.') from None
            if set(installed)==set(identities):return result
            if installed:raise ProvisionCleanupRequired('Incomplete ownership record.') from None
        try:
            failures=compensation.rollback()
        except Exception:
            raise ProvisionCleanupRequired('Interface cleanup could not be confirmed.') from None
        if failures:
            raise ProvisionCleanupRequired('Interface cleanup needs administrator review.') from None
        if on_external_rollback:on_external_rollback()
        raise

def remove_many(account, peer_ids, host):
    ids=list(dict.fromkeys(peer_ids))
    for pid in ids:own_peer(account,pid)
    with db.session.no_autoflush:
        if ids and not sample(account,host,peer_ids=ids):raise ValueError('Usage is unavailable for the selected customers. Retry deletion after connectivity recovers.')
    db.session.commit()
    for pid in ids:
        remove(account,pid,host,sampled=True)
        db.session.commit()

def remove(account, peer_id, host, sampled=False):
    if not sampled:return remove_many(account,[peer_id],host)
    row, peer=own_peer(account, peer_id)
    sub_id=row.subscription_id
    if not setting('recovery_pending:'+str(peer.id),False):host['remove_peer_everywhere'](peer)
    else:SubscriptionPeer.query.filter_by(peer_id=peer.id).delete(synchronize_session=False)
    row.deleted=True
    from sqlalchemy import inspect
    if inspect(peer).persistent:db.session.delete(peer)
    db.session.flush()
    if sub_id and not Ownership.query.filter_by(subscription_id=sub_id,deleted=False).first():
        sub=db.session.get(Subscription,sub_id)
        if sub: db.session.delete(sub)
    audit('reseller:'+str(account.id),'deleted_peer',str(peer_id))


def may_enable(peer):
    row=Ownership.query.filter_by(peer_id=peer.id,deleted=False).first() if peer.id else None
    if row:
        acc=db.session.get(Account,row.account_id)
        if not acc or not active(acc): raise ValueError('Reseller plan does not permit activation.')


from sqlalchemy import event, select
@event.listens_for(Peer, 'before_delete')
def before_peer_delete(mapper, connection, peer):
    from .customer_recovery import ledger_key,stamp,DATES
    table=Ownership.__table__
    archived=connection.execute(select(table).where(table.c.peer_id==peer.id)).mappings().first()
    if archived:
        records=[(peer.public_key,{**{k:stamp(getattr(peer,k,None)) for k in DATES},'used_bytes_total':int(peer.used_bytes_total or 0)})]
        if archived['subscription_id']:
            sub=connection.execute(select(Subscription.__table__).where(Subscription.id==archived['subscription_id'])).mappings().first()
            if sub:records.append((sub['token'],{k:stamp(sub[k]) for k in DATES}))
        settings=Setting.__table__
        for identity,value in records:
            key=ledger_key(archived['account_id'],identity)
            prior=connection.execute(select(settings.c.value).where(settings.c.key==key)).scalar()
            if prior:
                value['used_bytes_total']=max(value.get('used_bytes_total',0),prior.get('used_bytes_total',0))
                for field in DATES:
                    if prior.get(field):value[field]=min(v for v in (prior[field],value.get(field)) if v)
                connection.execute(settings.update().where(settings.c.key==key).values(value=value))
            else:connection.execute(settings.insert().values(key=key,value=value))
    connection.execute(Setting.__table__.delete().where(Setting.key=='recovery_pending:'+str(peer.id)))
    row=connection.execute(select(table).where(table.c.peer_id==peer.id,table.c.deleted==False)).mappings().first()
    if row:
        delta=max(0,int(peer.used_bytes_total or 0)-int(row['observed_bytes']))
        account=Account.__table__
        connection.execute(account.update().where(account.c.id==row['account_id']).values(used_bytes=account.c.used_bytes+delta))
    connection.execute(table.update().where(table.c.peer_id==peer.id).values(deleted=True,peer_id=None))


def apply_plan_defaults(account,spec):
    from .models import ManagementBot
    from .telegram_policy import FEATURES
    if 'network_policy' in spec:
        put('network_policy:'+str(account.id),dict(spec['network_policy']))
    bot = db.session.get(ManagementBot, account.id)
    if 'telegram_access' in spec:
        policy = spec['telegram_access']
        put('telegram_access:'+str(account.id), [key for key in FEATURES if key in policy.get('features', ())])
        if bot is None:
            bot = ManagementBot(account_id=account.id)
            db.session.add(bot)
        bot.approved = bool(policy.get('approved'))
        if not bot.approved:
            bot.enabled = False
    if bot:
        bot.pending = None
        bot.revision = (bot.revision or 0) + 1
