from flask import abort
from models import db
from .models import InboxRead


def seen_ids(viewer):
    return db.session.query(InboxRead.item_id).filter_by(viewer=viewer)


def mark_seen(viewer, owned_ids, ids):
    if not isinstance(ids, list) or len(ids) > 50 or any(type(i) is not int or not 0 < i <= 2**63-1 for i in ids):
        abort(400)
    model_id = owned_ids.column_descriptions[0]['expr']
    new = owned_ids.filter(model_id.in_(ids), ~model_id.in_(seen_ids(viewer))).all()
    for ident, in new:
        db.session.add(InboxRead(viewer=viewer, item_id=ident))
