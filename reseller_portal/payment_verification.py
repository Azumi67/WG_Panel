import re

from models import db
from . import service as s
from .models import PaymentVerification


METHODS = ('manual', 'bank', 'tron', 'other')


def record_verified(order, reviewer, method, reference):
    method = method or 'manual'
    if method not in METHODS:
        raise ValueError('Choose a listed review method.')
    if not order or order.state != 'pending' or not order.payment_ref:
        raise ValueError('A pending order with a submitted receipt is required.')
    if PaymentVerification.query.filter_by(order_id=order.id).first():
        raise ValueError('This order already has a payment verification record.')

    reference = str(reference or '').strip()
    if len(reference) > 160 or (reference and not reference.isprintable()):
        raise ValueError('Use a single line of up to 160 characters for the reference.')
    if method == 'tron' and reference:
        if not re.fullmatch(r'[0-9a-fA-F]{64}', reference):
            raise ValueError('Enter the full 64-character TRON transaction hash or leave the reference blank.')
        reference = reference.lower()
    if reference:
        fingerprint = s.digest('verified-payment:' + method + ':' + reference.lower())
        if PaymentVerification.query.filter_by(external_reference_hash=fingerprint).first():
            raise ValueError('This settlement reference was already used to approve another order.')
    else:
        fingerprint = s.digest('manual-review-order:' + str(order.id))

    record = PaymentVerification(
        order_id=order.id, reviewer=reviewer, method=method,
        external_reference=reference, external_reference_hash=fingerprint,
        amount=str(order.spec.get('price', '')), currency=str(order.spec.get('currency', '')),
    )
    db.session.add(record)
    db.session.flush()
    s.audit(reviewer, 'payment_verified_manual', f'order={order.id} method={method} verification={record.id}')
    return record
