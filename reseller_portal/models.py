
from datetime import datetime
from models import db

class Plan(db.Model):
    __tablename__ = 'rp_plan'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    spec = db.Column(db.JSON, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)

    @classmethod
    def catalog(cls):
        return cls.query.filter(cls.spec['retired'].as_boolean().is_not(True))

class Account(db.Model):
    __tablename__ = 'rp_account'
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.String(32), unique=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    link_hash = db.Column(db.String(64), unique=True, nullable=False)
    link_enc = db.Column(db.Text, nullable=False)
    state = db.Column(db.String(20), default='active', nullable=False)
    spec = db.Column(db.JSON, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_bytes = db.Column(db.BigInteger, default=0, nullable=False)
    generation = db.Column(db.Integer, default=1, nullable=False)
    session_version = db.Column(db.Integer, default=1, nullable=False)
    setup_hash = db.Column(db.String(64))
    setup_expires = db.Column(db.DateTime)
    note = db.Column(db.String(500), default='')

class Ownership(db.Model):
    __tablename__ = 'rp_ownership'
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('rp_account.id'), nullable=False, index=True)
    peer_id = db.Column(db.Integer, unique=True)
    subscription_id = db.Column(db.Integer, index=True)
    observed_bytes = db.Column(db.BigInteger, default=0, nullable=False)
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    blocked = db.Column(db.Boolean, default=False, nullable=False)

class Order(db.Model):
    __tablename__ = 'rp_order'
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.String(32), nullable=False, index=True)
    plan_id = db.Column(db.Integer, nullable=False)
    spec = db.Column(db.JSON, nullable=False)
    state = db.Column(db.String(20), default='pending', nullable=False)
    payment_ref = db.Column(db.String(160))
    reference_hash = db.Column(db.String(64), unique=True)
    account_id = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    reviewed_at = db.Column(db.DateTime)
    reviewer = db.Column(db.String(80))
    note = db.Column(db.String(500), default='')

    @classmethod
    def awaiting_review(cls):
        return cls.query.filter(cls.state == 'pending', cls.payment_ref.isnot(None))


review_queue_index = db.Index('ix_rp_order_state_id', Order.state, Order.id)
buyer_order_index = db.Index('ix_rp_order_account_state', Order.account_id, Order.state, Order.id)


class InboxRead(db.Model):
    __tablename__ = 'rp_inbox_read'
    viewer = db.Column(db.String(80), primary_key=True)
    item_id = db.Column(db.Integer, primary_key=True)


class OrderReceipt(db.Model):
    __tablename__ = 'rp_order_receipt'
    order_id = db.Column(db.Integer, db.ForeignKey('rp_order.id'), primary_key=True)
    image_enc = db.Column(db.LargeBinary, nullable=False)
    mime = db.Column(db.String(20), nullable=False)


class HiddenOrder(db.Model):
    __tablename__ = 'rp_hidden_order'
    account_id = db.Column(db.Integer, db.ForeignKey('rp_account.id'), primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('rp_order.id'), primary_key=True)


class AdminPurchaseDelivery(db.Model):
    __tablename__ = 'rp_admin_purchase_delivery'
    order_id = db.Column(db.Integer, db.ForeignKey('rp_order.id'), primary_key=True)
    recipient = db.Column(db.String(32), primary_key=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    next_attempt_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime)


class Setting(db.Model):
    __tablename__ = 'rp_setting'
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.JSON, nullable=False)

class Audit(db.Model):
    __tablename__ = 'rp_audit'
    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    actor = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(80), nullable=False)
    details = db.Column(db.String(500), nullable=False)

class Notice(db.Model):
    __tablename__ = 'rp_notice'
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, index=True)
    telegram_id = db.Column(db.String(32))
    dedupe = db.Column(db.String(160), unique=True, nullable=False)
    body_enc = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    retry_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    error = db.Column(db.String(160))

pending_delivery = Notice.sent_at.is_(None) & Notice.telegram_id.isnot(None)
notice_outbox_index = db.Index('ix_rp_notice_outbox', Notice.id,
                               sqlite_where=pending_delivery, postgresql_where=pending_delivery)

class Throttle(db.Model):
    __tablename__ = 'rp_throttle'
    key = db.Column(db.String(100), primary_key=True)
    count = db.Column(db.Integer, default=0, nullable=False)
    until = db.Column(db.DateTime, nullable=False)

class UsagePoint(db.Model):
    __tablename__ = 'rp_usage_point'
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, nullable=False, index=True)
    at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    generation = db.Column(db.Integer, nullable=False)
    used_bytes = db.Column(db.BigInteger, nullable=False)

usage_retention_index = db.Index('ix_rp_usage_point_retention', UsagePoint.at)
throttle_retention_index = db.Index('ix_rp_throttle_retention', Throttle.until)


class CustomerProfile(db.Model):
    __tablename__ = 'rp_customer_profile'
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    options = db.Column(db.JSON, nullable=False)
    is_default = db.Column(db.Boolean, nullable=False, default=False)

class ManagementBot(db.Model):
    __tablename__ = 'rp_management_bot'
    account_id = db.Column(db.Integer, primary_key=True)
    bot_id = db.Column(db.String(32), unique=True, nullable=True)
    token_enc = db.Column(db.Text, nullable=True)
    username = db.Column(db.String(64), nullable=True)
    approved = db.Column(db.Boolean, nullable=False, default=False)
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    revision = db.Column(db.Integer, nullable=False, default=1)
    offset = db.Column(db.BigInteger, nullable=False, default=0)
    language = db.Column(db.String(2), nullable=False, default='en')
    pending = db.Column(db.JSON, nullable=True)
    polled_at = db.Column(db.DateTime, nullable=True)
    error = db.Column(db.String(200), nullable=True)


class AccountSecurity(db.Model):
    __tablename__ = 'rp_account_security'
    account_id = db.Column(db.Integer, db.ForeignKey('rp_account.id'), primary_key=True)
    totp_secret_enc = db.Column(db.Text, nullable=True)
    pending_secret_enc = db.Column(db.Text, nullable=True)
    recovery_hashes = db.Column(db.JSON, nullable=False, default=list)
    last_totp_step = db.Column(db.BigInteger, nullable=False, default=-1)
    enabled_at = db.Column(db.DateTime, nullable=True)


class PaymentVerification(db.Model):
    __tablename__ = 'rp_payment_verification'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('rp_order.id'), unique=True, nullable=False)
    method = db.Column(db.String(24), nullable=False)
    external_reference_hash = db.Column(db.String(64), unique=True, nullable=False)
    external_reference = db.Column(db.String(160), nullable=False)
    amount = db.Column(db.String(40), nullable=False)
    currency = db.Column(db.String(20), nullable=False)
    reviewer = db.Column(db.String(80), nullable=False)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AuthBudget(db.Model):
    __tablename__ = 'rp_auth_budget'
    key = db.Column(db.String(255), primary_key=True)
    count = db.Column(db.Integer, nullable=False)
    until = db.Column(db.Float, nullable=False, index=True)


class AuthEvent(db.Model):
    __tablename__ = 'rp_auth_event'
    id = db.Column(db.BigInteger().with_variant(db.Integer, 'sqlite'), primary_key=True, autoincrement=True)
    actor = db.Column(db.String(96), nullable=False)
    at = db.Column(db.DateTime, nullable=False)


class ProvisionJob(db.Model):
    __tablename__ = 'rp_provision_job'
    id = db.Column(db.String(32), primary_key=True)
    account_id = db.Column(db.Integer, nullable=False, index=True)
    request_key = db.Column(db.String(96), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)
    channel = db.Column(db.String(8), nullable=False)
    section = db.Column(db.String(16), nullable=False)
    action = db.Column(db.String(24), nullable=False)
    payload_enc = db.Column(db.Text, nullable=True)
    session_version = db.Column(db.Integer, nullable=False)
    generation = db.Column(db.Integer, nullable=False)
    bot_revision = db.Column(db.Integer)
    recipient = db.Column(db.String(32))
    state = db.Column(db.String(20), nullable=False, default='queued')
    stage = db.Column(db.String(24), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    available_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    result = db.Column(db.JSON)
    message = db.Column(db.String(240))
    notified_at = db.Column(db.DateTime)
    notify_after = db.Column(db.DateTime)
    notify_attempts = db.Column(db.Integer, nullable=False, default=0)
    __table_args__ = (db.UniqueConstraint('account_id','request_key',name='uq_rp_job_request'),)


from .queue_scheduler import EXECUTION_STATES
provision_execution_index = db.Index('uq_rp_job_running_account', ProvisionJob.account_id, unique=True,
    postgresql_where=ProvisionJob.state.in_(EXECUTION_STATES),
    sqlite_where=ProvisionJob.state.in_(EXECUTION_STATES))
provision_ordering_index = db.Index('ix_rp_job_account_state_created', ProvisionJob.account_id,
    ProvisionJob.state, ProvisionJob.created_at, ProvisionJob.id)
provision_due_index = db.Index('ix_rp_job_due', ProvisionJob.state, ProvisionJob.available_at)
