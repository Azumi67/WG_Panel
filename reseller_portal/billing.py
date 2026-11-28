import hashlib
import json
from flask import abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from models import db
from . import service as s
from .bot_ui import valid_payment
from .database import SettingsWriterBusy, settings_transaction
from .models import Account, HiddenOrder, Order, OrderReceipt, Plan
from .receipts import MAX_PHOTO, photo_response


def _current_account():
    account = db.session.get(Account, g.reseller.id, with_for_update=True)
    if not account or account.state != 'active' or not account.spec.get('panel_access') or account.session_version != session.get('rp_version'):
        abort(403)
    return account


def terms_key(plan):
    return s.digest(json.dumps([plan.name, plan.spec], sort_keys=True))


def uploaded_image(file):
    data = file.stream.read(MAX_PHOTO + 1)
    if len(data) > MAX_PHOTO:
        raise ValueError('Choose a receipt image no larger than 5 MB.')
    if len(data) >= 24 and data.startswith(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR') and data.endswith(b'IEND\xaeB\x60\x82'):
        mime = 'image/png'
    elif len(data) > 6 and data.startswith(b'\xff\xd8\xff') and data.endswith(b'\xff\xd9'):
        mime = 'image/jpeg'
    else:
        raise ValueError('Choose a PNG or JPEG receipt photo.')
    return data, mime


def register(bp, member):
    @bp.get('/r/billing')
    @member()
    def billing():
        account = g.reseller
        owned = s.buyer_orders(account=account)
        oid = request.args.get('order', type=int)
        selected = owned.filter_by(id=oid).first_or_404() if oid is not None else None
        pending = owned.filter_by(state='pending').order_by(Order.id.desc()).first()
        plan_page = Plan.query.filter_by(active=True).order_by(Plan.id.desc()).paginate(
            page=max(1, request.args.get('plans', 1, type=int)), per_page=8, error_out=False)
        hidden = HiddenOrder.query.filter(HiddenOrder.account_id == account.id, HiddenOrder.order_id == Order.id).exists()
        show_hidden = request.args.get('history') == 'hidden'
        history = owned.filter(hidden if show_hidden else ~hidden).order_by(Order.id.desc()).paginate(
            page=max(1, request.args.get('page', 1, type=int)), per_page=8, error_out=False)
        order = selected or pending
        latest = None
        if not account.spec.get('plan_name'):
            latest = next((item for item in history.items if item.state == 'approved'), None) if history.page == 1 else None
            if latest is None:
                latest = owned.filter_by(state='approved').order_by(Order.id.desc()).first()
        shown_orders = [item for item in [*history.items, order, latest] if item and not item.spec.get('plan_name')]
        plan_ids = {item.plan_id for item in shown_orders}
        names = dict(db.session.query(Plan.id, Plan.name).filter(Plan.id.in_(plan_ids)).all()) if plan_ids else {}
        def plan_name(item):
            return item.spec.get('plan_name') or names.get(item.plan_id) or 'Plan '+str(item.plan_id)
        current_name = account.spec.get('plan_name') or (plan_name(latest) if latest else 'Current plan')
        percent = min(100, max(0, round(100 * account.used_bytes / max(1, account.spec['traffic_gib'] * s.GIB), 1)))
        return render_template('reseller/billing.html', current_name=current_name, plan_name=plan_name, percent=percent, slots=s.counts(account), section='billing', reseller_mode=True, account=account,
                               usable=s.active(account), expired=account.expires_at <= s.now(), order=order, pending=pending, history=history,
                               plan_page=plan_page, valid_payment=valid_payment, terms_key=terms_key, show_hidden=show_hidden,
                               order_hidden=order and db.session.get(HiddenOrder,(account.id,order.id)) is not None,
                               has_hidden=show_hidden or bool(HiddenOrder.query.filter_by(account_id=account.id).first()),
                               photo=s.setting('receipt_photo:'+str(order.id)) if order else None,
                               HAS_NODES=False, HAS_SETTINGS=False)

    @bp.get('/r/billing/status')
    @member()
    def billing_status():
        account = g.reseller
        oid = request.args.get('order', type=int)
        order = s.buyer_orders(account=account).filter_by(id=oid).first_or_404() if oid is not None else None
        remaining = max(0, int((account.expires_at - s.now()).total_seconds() * 1000))
        response = jsonify(generation=account.generation, expired=remaining == 0,
                           remaining_ms=remaining, order_state=order.state if order else None)
        response.headers['Cache-Control'] = 'no-store'
        return response

    @bp.post('/r/billing/orders')
    @member()
    def billing_order():
        try:
            with settings_transaction():
                account = _current_account()
                plan = db.session.get(Plan, request.form.get('plan_id', type=int) or 0)
                if not plan or not plan.active:
                    raise ValueError('This plan is no longer available.')
                if request.form.get('terms') != terms_key(plan):
                    raise ValueError('The plan details changed. Review the current terms before ordering.')
                order = s.order_new(account.telegram_id, plan.id, account=account)
                oid = order.id
        except SettingsWriterBusy:
            message = 'Your order has not started. Try again here.'
            if request.accept_mimetypes.best == 'application/json':
                return jsonify(error=message,code='write_not_started'), 503, {'Retry-After':'1'}
            flash(message,'error')
            return redirect(url_for('reseller.billing'), code=303)
        except ValueError as exc:
            if request.accept_mimetypes.best == 'application/json':
                return jsonify(error=str(exc)),400
            flash(str(exc), 'error')
            return redirect(url_for('reseller.billing'), code=303)
        destination=url_for('reseller.billing',order=oid)
        if request.accept_mimetypes.best == 'application/json':
            return jsonify(location=destination+'#current-order')
        return redirect(destination,code=303)

    @bp.post('/r/billing/orders/<int:oid>/<any(receipt,cancel,hide,unhide):action>')
    @member()
    def billing_action(oid, action):
        s.buyer_orders(account=g.reseller).filter_by(id=oid).first_or_404()
        try:
            file = request.files.get('photo') if action == 'receipt' else None
            image = uploaded_image(file) if file and file.filename else None
            reference = request.form.get('reference', '').strip()
            if image and reference:
                raise ValueError('Send one receipt photo or one transaction reference.')
            if action == 'receipt' and not image and not reference:
                raise ValueError('Choose a receipt photo or enter a transaction reference.')
            if image:
                reference = 'upload:'+hashlib.sha256(image[0]).hexdigest()
                encrypted = s.cipher().encrypt(image[0])
            with settings_transaction():
                account = _current_account()
                order = s.buyer_orders(account=account).filter_by(id=oid).with_for_update().first_or_404()
                if action in ('hide','unhide'):
                    if order.state == 'pending':
                        raise ValueError('Finish or cancel this order before hiding it.')
                    row = db.session.get(HiddenOrder, (account.id, oid))
                    if action == 'hide' and row is None:
                        db.session.add(HiddenOrder(account_id=account.id, order_id=oid))
                    elif action == 'unhide' and row is not None:
                        db.session.delete(row)
                elif action == 'cancel':
                    s.cancel_order(account.telegram_id, oid, account=account)
                else:
                    had_proof = bool(order.payment_ref)
                    s.receipt(account.telegram_id, oid, reference, account=account)
                    if image and not had_proof:
                        db.session.add(OrderReceipt(order_id=oid, image_enc=encrypted, mime=image[1]))
                        s.put('receipt_photo:'+str(oid), {'source':'workspace', 'caption':request.form.get('caption','').strip()[:500]})
            message = {'cancel':'Order cancelled.', 'receipt':'Receipt submitted for review.',
                       'hide':'Order removed from your history.', 'unhide':'Order returned to your history.'}[action]
            flash(message, 'success')
            destination = url_for('reseller.billing', order=oid) if action == 'receipt' else url_for('reseller.billing')
            if request.accept_mimetypes.best == 'application/json':
                return jsonify(location=destination)
            return redirect(destination, code=303)
        except SettingsWriterBusy:
            if request.accept_mimetypes.best == 'application/json':
                return jsonify(error='Your change has not started. Try again here.', code='write_not_started'), 503, {'Retry-After':'1'}
            flash('Your change has not started. You can try again from this order.', 'error')
        except ValueError as exc:
            if request.accept_mimetypes.best == 'application/json':
                return jsonify(error=str(exc)), 400
            flash(str(exc), 'error')
        return redirect(url_for('reseller.billing', order=oid), code=303)

    @bp.get('/r/billing/orders/<int:oid>/receipt')
    @member()
    def billing_photo(oid):
        s.buyer_orders(account=g.reseller).filter_by(id=oid).first_or_404()
        if not s.setting('receipt_photo:'+str(oid)):
            abort(404)
        return photo_response(oid)
