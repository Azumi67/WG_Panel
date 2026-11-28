import secrets
from models import db, Peer, Subscription
from . import service as s
from .models import AccountSecurity, ManagementBot, Notice, Order, Ownership


def remove_account(account, host, transfer, actor):
    if s.buyer_orders(account=account).filter(Order.state=='pending', Order.payment_ref.isnot(None)).first():
        raise ValueError('Review this reseller’s submitted receipt in Purchases before deleting the account.')
    rows = Ownership.query.filter_by(account_id=account.id, deleted=False).all()
    if rows and not transfer:
        raise ValueError('Confirm the transfer of this reseller’s customers to the administrator.')
    if not s.active(account):
        for row in rows:
            peer = db.session.get(Peer, row.peer_id) if row.peer_id else None
            if peer and peer.status == 'online' and not host['_disable_peer'](peer, 'reseller_closed'):
                raise ValueError('Customer access could not be paused. The account is still present.')
        subscriptions = {row.subscription_id for row in rows if row.subscription_id}
        for sub in Subscription.query.filter(Subscription.id.in_(subscriptions)).all():
            sub.enabled = False
    for row in rows:
        row.deleted = True
        row.peer_id = None
        row.subscription_id = None
    for order in s.buyer_orders(account=account).all():
        order.account_id = account.id
        if order.state == 'pending':
            order.state, order.reviewed_at, order.reviewer = 'cancelled', s.now(), actor
    Notice.query.filter_by(account_id=account.id, sent_at=None).update({'telegram_id':None})
    for model in (ManagementBot, AccountSecurity):
        record = db.session.get(model, account.id)
        if record:
            db.session.delete(record)
    s.put('bot_reply:'+str(account.id), {})
    s.put('app_key:workspace:'+str(account.id), None)
    s.put('app_named:workspace:'+str(account.id), {})
    s.put('app_policy:workspace:'+str(account.id), None)
    s.put('app_limits:workspace:'+str(account.id), None)
    s.audit(actor, 'account_deleted', f'account={account.id} customers_transferred={len(rows)}')
    token = secrets.token_urlsafe(32)
    account.link_hash, account.link_enc = s.digest(token), s.encrypt(token)
    account.telegram_id = account.password_hash = account.setup_hash = account.setup_expires = None
    account.state, account.note = 'deleted', ''
    account.username = 'Deleted account '+str(account.id)
    account.session_version += 1
    account.spec = {**account.spec, 'permissions':[], 'panel_access':False}
