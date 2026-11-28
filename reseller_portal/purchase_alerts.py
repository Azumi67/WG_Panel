from datetime import timedelta
from panel_core.telegram_notices import card, telegram_body

from sqlalchemy import and_, or_
from models import db
from . import service as s
from .database import settings_transaction
from .telegram_text import isolated, number, persian_price, persian_time, rtl_lines
from .models import Account, AdminPurchaseDelivery, Order
from .bot_runtime_log import event as bot_event


def destinations(host):
    settings = host['_load_tg_settings']()
    if not settings['enabled'] or not settings.get('notify', {}).get('reseller_purchase', True):
        return '', set()
    token = settings.get('bot_token', '')
    if not token:
        return '', set()
    recipients = {str(row['id']) for row in host['_load_tg_admins']() if row.get('id') and not row.get('muted')}
    return token, recipients


def claim(order_id, chat_id, language='en'):
    with settings_transaction():
        order = Order.awaiting_review().filter(Order.id == order_id).with_for_update().first()
        if not order:
            return None
        delivery = db.session.get(AdminPurchaseDelivery, (order_id, chat_id))
        now = s.now()
        if delivery:
            if delivery.sent_at or delivery.next_attempt_at > now:
                return None
        else:
            delivery = AdminPurchaseDelivery(order_id=order_id, recipient=chat_id, attempts=0)
            db.session.add(delivery)
        delivery.attempts += 1
        delivery.next_attempt_at = now + timedelta(minutes=2)
        account = s.order_buyer(order)
        plan = order.spec.get('plan_name') or (f'پلن {order.plan_id}' if language == 'fa' else f'Plan {order.plan_id}')
        amount = f"{order.spec['price']} {order.spec['currency']}"
        buyer = account.username if account else order.telegram_id
        title = 'Renewal receipt awaiting review' if account else 'New plan receipt awaiting review'
        try:
            url = f'{s.base_url()}/resellers?tab=orders&order={order_id}'
        except ValueError:
            url = None
        fa = language=='fa'
        if fa:title = 'رسید تمدید در انتظار بررسی' if account else 'رسید خرید پلن در انتظار بررسی'
        from .regional import display
        fields=[('سفارش' if fa else 'Order', number(order_id) if fa else str(order_id)), ('خریدار' if fa else 'Buyer',isolated(buyer) if fa else buyer),
                ('پلن' if fa else 'Plan',plan), ('مبلغ' if fa else 'Amount',persian_price(order.spec['price'],order.spec['currency']) if fa else amount), ('زمان سفارش' if fa else 'Ordered',persian_time(order.created_at) if fa else display(order.created_at))]
        notice=card(title,fields,'' if url else ('سفارش را در بخش خریدها بررسی کنید.' if fa else 'Open Resellers → Purchases to review.'),
                    buttons=[('بررسی پرداخت' if fa else 'Review purchase',url)])
        if fa:notice['text'] = rtl_lines(notice['text'])
        payload = {'chat_id': chat_id, **telegram_body(notice), 'link_preview_options': {'is_disabled': True}}
        return payload


def deliver(host, send, stop=None):
    _, recipients = destinations(host)
    for chat_id in sorted(recipients):
        ids = (Order.awaiting_review().with_entities(Order.id).outerjoin(
            AdminPurchaseDelivery, and_(AdminPurchaseDelivery.order_id == Order.id, AdminPurchaseDelivery.recipient == chat_id))
            .filter(AdminPurchaseDelivery.sent_at.is_(None), or_(AdminPurchaseDelivery.order_id.is_(None),
                    AdminPurchaseDelivery.next_attempt_at <= s.now())).order_by(Order.id).limit(12).all())
        db.session.rollback()
        for (order_id,) in ids:
            if stop and stop.is_set():
                return
            token, current = destinations(host)
            if chat_id not in current:
                break
            payload = claim(order_id, chat_id,host['_load_tg_settings']().get('language','en'))
            if payload is None:
                continue
            try:
                send(token, 'sendMessage', payload)
            except RuntimeError as exc:
                bot_event('shop','WARNING','purchase_alert_retry',error=exc)
                with settings_transaction():
                    delivery = db.session.get(AdminPurchaseDelivery, (order_id, chat_id))
                    delivery.next_attempt_at = s.now() + timedelta(seconds=min(3600, 30 * 2 ** min(delivery.attempts, 7)))
                from flask import current_app
                current_app.logger.warning('Plan receipt alert for order %s could not be delivered. Retry scheduled.', order_id)
            else:
                with settings_transaction():
                    db.session.get(AdminPurchaseDelivery, (order_id, chat_id)).sent_at = s.now()


def run(app, host, stop):
    from .worker_supervision import pulse
    from .worker import telegram
    with app.app_context():
        while not stop.is_set():
            try:
                deliver(host, telegram, stop)
                pulse()
            except Exception as exc:
                bot_event('shop','ERROR','purchase_alert_cycle_failed',error=exc)
                db.session.rollback()
                app.logger.exception('Plan receipt notification cycle failed.')
            finally:
                db.session.remove()
            stop.wait(15)
