from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, SubmitField, DecimalField, BooleanField
from wtforms.validators import DataRequired, Optional, NumberRange

class PeerForm(FlaskForm):
    iface                = SelectField('Interface', coerce=int, validators=[DataRequired()])
    name                 = StringField('Friendly Name', validators=[DataRequired()])
    address              = SelectField('Peer IP Address', choices=[], validators=[DataRequired()])
    allowed_ips          = StringField('Allowed IPs', validators=[Optional()])
    endpoint             = StringField('Endpoint (host:port)', validators=[Optional()])
    persistent_keepalive = IntegerField('Keepalive (s)', default=25, validators=[Optional(), NumberRange(min=0)])
    mtu                  = IntegerField('MTU', validators=[Optional(), NumberRange(min=576, max=65535)])
    dns                  = StringField('DNS (for client)', validators=[Optional()])

    data_limit           = DecimalField('Traffic Limit', validators=[Optional(), NumberRange(min=0)])
    limit_unit           = SelectField('Unit', choices=[('Mi','MiB'),('Gi','GiB')], default='Mi')

    time_limit_days      = IntegerField('Active Days',  validators=[Optional(), NumberRange(min=0)])
    time_limit_hours     = IntegerField('Active Hours', validators=[Optional(), NumberRange(min=0, max=23)])
    start_on_first_use   = BooleanField('Start timer on first connection')

    unlimited            = BooleanField('Unlimited (ignores data & timer)')

    phone_number         = StringField('Phone Number', validators=[Optional()])
    telegram_id          = StringField('Telegram ID', validators=[Optional()])

    submit               = SubmitField('Save')
