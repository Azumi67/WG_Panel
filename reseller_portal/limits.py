
from . import service as s


FIELDS = {
    'read_per_minute': ('Page refreshes per minute', 240, 30, 1200),
    'write_per_minute': ('Changes per minute', 60, 5, 120),
    'create_per_minute': ('Create actions per minute', 10, 1, 30),
    'bulk_limit': ('Maximum batch size', 50, 1, 50),
    'profile_limit': ('Saved presets', 50, 1, 100),
}

def validate(data):
    return {key:s.integer({key:data.get(key,default)},key,low,high)
            for key,(_,default,low,high) in FIELDS.items()}

def effective(spec):
    result={}
    for key,(_,default,low,high) in FIELDS.items():
        try:value=int(spec.get('operation_limits',{}).get(key,default))
        except (ValueError,TypeError,AttributeError):value=default
        result[key]=max(low,min(high,value))
    return result

def batch(account,count):
    maximum=effective(account.spec)['bulk_limit']
    if not 1<=count<=maximum:raise ValueError(f'This account allows at most {maximum} resources per operation.')

def profile_capacity(account):
    from .models import CustomerProfile
    maximum=effective(account.spec)['profile_limit']
    if CustomerProfile.query.filter_by(account_id=account.id).count()>=maximum:
        raise ValueError(f'Saved profile limit reached ({maximum}).')

def reserve_request(account_id,write):
    from models import db
    from .models import Account
    from .request_budget import reserve, reserve_read
    account=db.session.get(Account,account_id)
    if not account:return False
    kind='write' if write else 'read'
    maximum=effective(account.spec)[kind+'_per_minute']
    if not write and db.engine.dialect.name == 'postgresql':
        return reserve_read(account_id, maximum, 60)
    return reserve(account_id,kind,maximum,60)
