
from . import service as s

FEATURES={
 'usage':'Plan usage & expiry', 'peers':'Peer directory', 'subscriptions':'Subscriptions',
 'create':'Create customers', 'bulk':'Bulk peer creation', 'profiles':'Saved customer profiles', 'edit':'Edit customer settings',
 'reset_data':'Reset customer traffic', 'reset_timer':'Reset customer timer', 'rotate_link':'Replace subscription links', 'control_access':'Pause & resume', 'delete':'Delete customers',
 'download':'Configurations & links', 'notifications':'Notification preferences', 'logs':'Own activity logs', 'backup':'Encrypted customer backup', 'problems':'Problem & recovery alerts',
}
EVENTS={'plan_expiry':'Plan expiry','plan_usage':'Plan traffic','customer_expiry':'Customer expiry','customer_usage':'Customer traffic','problems':'Problems & recovery'}


SAFE_DEFAULTS=frozenset({'usage','peers','subscriptions','notifications','logs'})
SENSITIVE_FEATURES=frozenset({'create','bulk','profiles','edit','reset_data','reset_timer','rotate_link','control_access','delete','download','backup'})


def configured(a):
    saved=s.setting('telegram_access:'+str(a.id),None)
    if saved is None:
        return [k for k in FEATURES if k in SAFE_DEFAULTS]
    return [k for k in FEATURES if k in saved] if isinstance(saved,(list,tuple,set)) else []

def effective(a):
    grants=set(a.spec.get('permissions',[]))
    return {k for k in configured(a) if k in ('usage','notifications','problems') or k in grants}

def preferences(a):
    saved=s.setting('telegram_preferences:'+str(a.id),{}) or {}
    return {k:bool(saved.get(k,k in ('enabled','plan_expiry','plan_usage'))) for k in ('enabled',*EVENTS)}

def can_notify(a,event):
    prefs=preferences(a)
    section='subscriptions' if event.startswith('subscription_') else 'peers' if event.startswith('peer_') else None
    normalized=event.replace('subscription_','customer_').replace('peer_','customer_')
    grants=effective(a)
    return (event!='problems' or 'problems' in grants) and 'notifications' in grants and (not event.startswith('plan_') or 'usage' in grants) and (not section or section in grants) and prefs['enabled'] and prefs.get(normalized,False)

def save_access(a,data):
    if data.get('telegram_features_present')=='1':
        s.put('telegram_access:'+str(a.id),[k for k in FEATURES if k in data.getlist('telegram_features')])
