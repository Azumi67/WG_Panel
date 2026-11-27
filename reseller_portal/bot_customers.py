import re
import secrets
from datetime import timedelta, timezone
from html import escape

from models import db, InterfaceConfig
from . import management as m, network_policy, service as s
from .limits import effective as limits, profile_capacity
from .models import CustomerProfile
from .telegram_policy import effective as grants
from .telegram_text import isolated, number, persian_time
from .regional import display


FIELDS = {
    'count': ('Number of peers', 'تعداد کاربران'),
    'name': ('Name', 'نام'),
    'traffic': ('Traffic allowance', 'حجم مجاز'),
    'days': ('Duration', 'مدت اعتبار'),
    'start_on_first_use': ('Start timer', 'آغاز اعتبار'),
    'phone_number': ('Phone number', 'شماره تلفن'),
    'telegram_id': ('Telegram contact', 'شناسه تلگرام'),
    'note': ('Note', 'یادداشت'),
    'address': ('Client tunnel IP (WireGuard)', 'آی‌پی تونل کاربر (WireGuard)'),
    'allowed_ips': ('Allowed IPs', 'مسیرهای مجاز'),
    'include_internal_network': ('Internal networks', 'شبکه‌های داخلی'),
    'endpoint': ('Server endpoint', 'آدرس و پورت سرور'),
    'peer_endpoint': ('Fixed client endpoint', 'آدرس و پورت ثابت کاربر'),
    'dns': ('DNS servers', 'سرورهای DNS'),
    'mtu': ('Client MTU (bytes)', 'MTU کاربر (بایت)'),
    'persistent_keepalive': ('Keepalive', 'فاصلهٔ ارسال Keepalive'),
}
HINTS = {
    'count': ('How many peers do you want to create?', 'چند کاربر می‌خواهید بسازید؟'),
    'name': ('Enter a name, up to 48 characters.', 'یک نام با حداکثر ۴۸ نویسه وارد کنید.'),
    'traffic': ('Choose a unit, then enter the amount.', 'واحد را انتخاب کنید و سپس مقدار حجم را بنویسید.'),
    'days': ('Enter days, or days:hours:minutes (for example 0:6:30).', 'تعداد روز را بنویسید. برای تعیین ساعت و دقیقه، زمان را به صورت روز:ساعت:دقیقه وارد کنید؛ مثلاً ۰:۶:۳۰.'),
    'start_on_first_use': ('When should the timer start?', 'اعتبار کاربر از چه زمانی محاسبه شود؟'),
    'phone_number': ('Enter the customer’s phone number.', 'شماره تلفن مشتری را وارد کنید.'),
    'telegram_id': ('Enter the customer’s Telegram ID or username.', 'شناسه عددی یا نام کاربری تلگرام مشتری را وارد کنید.'),
    'note': ('Add a note for this subscription.', 'برای این اشتراک یادداشتی بنویسید.'),
    'address': ('This is the private IP assigned INSIDE the WireGuard tunnel, not the server/public endpoint. Enter a free IP from this interface (for example 10.66.66.7), or select automatic assignment. Your administrator must enable Choose free client IP.', 'این IP داخلی تونل WireGuard است، نه آدرس عمومی سرور. یک IP آزاد از محدوده همین رابط وارد کنید (مثلاً 10.66.66.7) یا تخصیص خودکار را انتخاب کنید. مدیر باید اجازه انتخاب IP را فعال کند.'),
    'allowed_ips': ('Enter comma-separated CIDR routes.', 'مسیرها را با طول پیشوند وارد کنید و با ویرگول جدا کنید.'),
    'include_internal_network': ('Include the internal routes assigned by your administrator?', 'مسیرهای داخلی تعیین‌شده توسط مدیر به تنظیمات کاربر اضافه شوند؟'),
    'endpoint': ('Enter a server hostname or IP and UDP port.', 'نام میزبان یا IP سرور و پورت UDP را وارد کنید.'),
    'peer_endpoint': ('Enter the client’s fixed host and UDP port.', 'نام میزبان یا IP ثابت کاربر و پورت UDP را وارد کنید.'),
    'dns': ('Enter DNS server IPs separated by commas.', 'آدرس سرورهای DNS را با ویرگول جدا کنید.'),
    'mtu': ('Client MTU in BYTES, not a port or an IP. Example: 1420 is common, but not universal; some IPv6 paths need 1280. Use the value advised by your administrator, or Skip for the panel default (1420). Range: 576–9000.', 'MTU بر حسب بایت است، نه پورت یا IP. مقدار 1420 متداول است اما برای همه اتصال‌ها مناسب نیست؛ برخی مسیرهای IPv6 به 1280 نیاز دارند. مقدار تعیین‌شده توسط مدیر را وارد کنید یا برای مقدار پیش‌فرض پنل (1420) رد کنید. محدوده: 576 تا 9000.'),
    'persistent_keepalive': ('Enter the interval in seconds (0 to turn it off).', 'فاصله را به ثانیه وارد کنید. صفر یعنی خاموش.'),
}
KEYS = {'traffic':('data_limit_value','data_limit_unit','customer_unlimited'),
        'days':('time_limit_days','time_limit_hours','time_limit_minutes'),
        'phone_number':('phone_number','phone_numbers'), 'telegram_id':('telegram_id','telegram_ids')}
DEFAULTS = {'allowed_ips':'0.0.0.0/0, ::/0','mtu':1420,'persistent_keepalive':25}


METADATA_FIELDS = frozenset({'name','phone_number','telegram_id','note'})

ACTION_GRANTS = {
    'create':'create', 'edit':'edit', 'enable':'control_access', 'disable':'control_access',
    'delete':'delete', 'rotate':'rotate_link', 'reset_data':'reset_data', 'reset_timer':'reset_timer',
}


def detail(account, section, resource, peers, host, language):
    from panel_core.telegram_notices import card, telegram_body
    from .presentation import peer_states
    fa=language=='fa'
    def tr(en, persian):return persian if fa else en
    def n(value):return number(value) if fa else str(value)
    labels={'Plan unavailable':('Plan unavailable','پلن غیرفعال'), 'Expired':('Expired','منقضی'),
            'Data exhausted':('Traffic exhausted','حجم تمام‌شده'), 'Paused':('Paused','متوقف'), 'Enabled':('Enabled','فعال')}
    state=m.reason(resource,account)
    fields=[(tr('Customer','مشتری'),resource.name),(tr('ID','شناسه'),n(resource.id))]
    if section=='peers':
        row,_=s.own_peer(account,resource.id)
        if state is None and (row.blocked or resource.status!='online'):state='Paused'
        snapshot=peer_states([resource],host,live=False,owner_account_id=account.id)[resource.id]['connection']
        connection={'online':tr('Online','متصل'),'offline':tr('Offline','آفلاین')}.get(snapshot,tr('Unknown','نامشخص'))
        fields.extend([(tr('Access','دسترسی'),tr(*labels[state or 'Enabled'])),(tr('Connection','اتصال'),connection),
                       (tr('Interface','رابط'),resource.iface.name),(tr('Client address','آدرس کاربر'),resource.address)])
    else:
        fields.extend([(tr('Access','دسترسی'),tr(*labels[state or 'Enabled'])),(tr('Locations','تعداد موقعیت‌ها'),n(len(peers)))])
    used=m.usage(resource)
    cap=resource.limit_bytes()
    used_text=n(f'{used/s.GIB:.2f}')+' '+tr('GiB','گیگابایت')
    if cap:
        unit=resource.data_limit_unit or 'Mi'
        used_text+=tr(' of ',' از ')+n(resource.data_limit_value)+' '+tr(unit+'B','مگابایت' if unit=='Mi' else 'گیگابایت')
    fields.append((tr('Traffic used','مصرف'),used_text))
    expires=min(resource.expires_at,account.expires_at) if resource.expires_at else account.expires_at
    if resource.start_on_first_use and not resource.first_used_at and resource.time_limit_days:
        fields.append((tr('Timer','آغاز اعتبار'),tr('First connection','اولین اتصال')))
    fields.append((tr('Valid until','پایان اعتبار') if resource.expires_at else tr('Plan expires','پایان پلن'),persian_time(expires) if fa else display(expires)))
    title=tr('Peer details','مشخصات کاربر') if section=='peers' else tr('Subscription details','مشخصات اشتراک')
    return telegram_body(card(title,fields,symbol='◇' if section=='peers' else '⌘'))


def peer_short_link(account, peer):
    from urllib.parse import quote
    from models import ShortLink

    base = s.base_url()
    s.own_peer(account, peer.id)
    link = ShortLink.query.filter_by(peer_id=peer.id).order_by(ShortLink.id).first()
    if link is None:
        with s.account_settings(account.id) as current:
            s.own_peer(current, peer.id)
            link = ShortLink.query.filter_by(peer_id=peer.id).order_by(ShortLink.id).first()
            if link is None:
                link = ShortLink(peer_id=peer.id, token=secrets.token_urlsafe(16))
                db.session.add(link)
                db.session.flush()
    return base + '/u/' + quote(link.token, safe='')


def export_peer(peer, host, *, qr=False, config=None):
    if config is None:
        config=host['_client_conf_txt'](peer)
    if not qr:
        return {'document':config,'filename':f'peer-{peer.id}.conf'}
    import io
    import qrcode
    from panel_core.qr import PNGImage
    out=io.BytesIO()
    image=qrcode.make(config,image_factory=PNGImage,box_size=7,border=4)
    image.save(out)
    return {'document':out.getvalue(),'filename':f'peer-{peer.id}.png','mime':'image/png'}


def edit_values(account, op, host):
    section,field=op['section'],op['field']
    obj,peers=m.target(account,section,op['id'])
    iface=obj.iface if section=='peers' else next((p.iface for p in peers if p.iface_id in account.spec['interfaces']),None)
    if not iface or iface.id not in account.spec['interfaces']:
        raise ValueError('Interface no longer available.')
    fields=authorized_fields(account,iface,section,'guided',host,editing=True)
    changes=op['changes']
    if field not in fields or not changes or set(changes)-set(field_keys(field)) or {'customer_unlimited','phone_numbers','telegram_ids'} & set(changes):
        raise ValueError('Permission changed.')
    value_keys={'traffic':('data_limit_value','data_limit_unit'),'days':('time_limit_days',),
                'include_internal_network':('allowed_ips',)}.get(field,(field,))
    data={'name':obj.name,'start_on_first_use':bool(obj.start_on_first_use)}
    if field=='include_internal_network':
        routes=[route.strip() for route in (obj.allowed_ips or DEFAULTS['allowed_ips']).split(',')]
        if not changes[field]:
            internal=set(network_policy.get(account).get('internal_routes',()))
            routes=[route for route in routes if route not in internal]
            if not routes:raise ValueError('Enter replacement allowed routes first.')
        data['allowed_ips']=', '.join(routes)
    return obj,{**data,**changes},value_keys


def field_keys(field):
    return KEYS.get(field,(field,))


def deadline():
    return (s.now()+timedelta(minutes=20)).replace(tzinfo=timezone.utc).timestamp()


def expiry(draft):
    return draft.get('until', 0) < s.now().replace(tzinfo=timezone.utc).timestamp()


def button(text, command):
    return {'text':text, 'callback_data':command}


def authorized_fields(account, iface, section, mode, host, *, editing=False):
    permissions = account.spec.get('permissions', ())
    fields = ['count'] if mode == 'bulk' else []
    fields.extend(('name','traffic','days'))
    if mode == 'quick':
        return fields
    fields.extend(('start_on_first_use','phone_number','telegram_id'))
    if section == 'subscriptions':
        fields.append('note')
        if editing:
            return fields
    if section == 'peers' and mode != 'bulk' and not editing and 'choose_address' in permissions:
        fields.append('address')
    if 'network_options' in permissions:
        policy = network_policy.get(account)
        fields.append('allowed_ips')
        if policy.get('allow_internal') and policy.get('internal_routes'):
            fields.append('include_internal_network')
        if (not policy or policy.get('allow_endpoint')) and not network_policy.assigned_endpoint(account,iface,host):
            fields.append('endpoint')
        if not policy or policy.get('allow_fixed'):
            fields.append('peer_endpoint')
        fields.extend(('dns','mtu','persistent_keepalive'))
    return fields


def clean_options(account, draft, fields):
    keys = {key for field in fields for key in field_keys(field)}
    if 'customer_unlimited' not in account.spec.get('permissions',()):
        keys.discard('customer_unlimited')
    return {k:v for k,v in draft.get('values',{}).items() if k in keys}


def checked_operation(account, operation, host):
    section = operation['section']
    permissions = grants(account)
    if section not in ('peers','subscriptions') or not {section,'create'} <= permissions:
        raise ValueError('Creation is not enabled.')
    count = operation.get('count',1)
    if (count != 1 or operation.get('bulk')) and (section != 'peers' or 'bulk' not in permissions):
        raise ValueError('Bulk creation is not enabled.')
    iface = db.session.get(InterfaceConfig,operation['iface'])
    if not iface or iface.id not in account.spec['interfaces']:
        raise ValueError('Interface is no longer available.')
    opts = operation['options']
    mode = 'bulk' if operation.get('bulk') or count != 1 else 'guided'
    fields = authorized_fields(account,iface,section,mode,host)
    if clean_options(account,{'values':opts},fields) != opts:
        raise ValueError('Customer permissions have changed.')
    if type(count) is not int or not 1<=count<=limits(account.spec)['bulk_limit']:
        raise ValueError('Batch size exceeds the account limit.')
    if 'address' in opts:
        m.requested_address(iface,opts['address'])
    m.validate_options(account,opts)
    if operation.get('profile'):
        own_profile(account, section, operation['profile'])
    return iface


def own_profile(account, section, pid):
    if 'profiles' not in grants(account) or section not in ('peers','subscriptions'):
        raise ValueError('Profile access changed.')
    profile = CustomerProfile.query.filter_by(id=pid,account_id=account.id,kind='peer' if section=='peers' else 'subscription').first()
    if not profile:
        raise ValueError('Profile is no longer available.')
    return profile


def profile_name(account, kind, raw, *, exclude=None):
    name=raw.strip()
    if not name or len(name)>64 or any(ord(c)<32 or c in '<>"' for c in name):
        raise ValueError('Invalid profile name.')
    query=CustomerProfile.query.filter_by(account_id=account.id,kind=kind,name=name)
    if exclude is not None:query=query.filter(CustomerProfile.id!=exclude)
    if query.first():raise ValueError('Profile name already used.')
    return name


class CustomerWizard:
    def __init__(self, account, bot, host, draft):
        self.account, self.bot, self.host = account, bot, host
        self.fa = bot.language == 'fa'
        self.draft = dict(draft)
        self.section = draft['section']
        self.iface = db.session.get(InterfaceConfig,draft['iface'])
        if not self.iface or self.iface.id not in account.spec['interfaces']:
            raise ValueError('Interface no longer available.')
        self.mode = draft.get('mode','quick')
        access = grants(account)
        self.editing = bool(draft.get('edit_id'))
        required = {self.section, 'edit' if self.editing else 'create'}
        if self.mode == 'bulk':
            required.add('bulk')
        if not required <= access:
            raise ValueError('Permission changed.')
        s.require_active(account)
        self.fields = authorized_fields(account,self.iface,self.section,self.mode,host,editing=self.editing)
        if self.editing:
            self.fields = [field for field in self.fields if field == draft['edit_field']]
            if not self.fields:
                raise ValueError('Field no longer available.')
        self.values = dict(draft.get('values',{}))
        if 'values' not in draft:
            self.values.update((draft.get('operation') or {}).get('options',{}))
            if 'name' in draft:self.values['name'] = draft['name']
            if 'gib' in draft:self.values.update(data_limit_value=draft['gib'], data_limit_unit='Gi')
            if 'days' in draft:self.values['time_limit_days'] = draft['days']
        self.values = clean_options(account,{'values':self.values},self.fields)
        if self.values.get('customer_unlimited'):
            self.fields = [f for f in self.fields if f not in ('days','start_on_first_use')]
        step = self.draft['step']
        if step not in (*self.fields,'review','profile','profile-name'):
            self.draft['step'] = self.fields[0]
        if self.draft.get('profile') and 'profiles' not in access:
            raise ValueError('Profile access changed.')

    def tr(self, en, fa):
        return fa if self.fa else en

    def n(self, value):
        return number(value) if self.fa else str(value)

    def save(self, step=None):
        self.draft.update(step=step or self.draft['step'],values=dict(self.values),until=deadline(),nonce=secrets.token_urlsafe(9))
        self.draft.pop('operation',None)
        if self.draft['step']=='review':
            self.draft['operation']=self.operation()
        self.bot.pending = dict(self.draft)

    def operation(self):
        opts = dict(self.values)
        count = opts.pop('count',1)
        if not self.editing:
            required=['name','traffic']
            if self.mode=='bulk':required.append('count')
            if not self.values.get('customer_unlimited'):required.append('days')
            if any(not self.value(key) for key in required):raise ValueError('Complete the customer settings.')
        if self.editing:
            return {'action':'edit','section':self.section,'id':self.draft['edit_id'],
                    'field':self.draft['edit_field'],'changes':opts}
        op = {'action':'create','section':self.section,'iface':self.iface.id,'options':opts}
        if self.mode=='bulk':
            op.update(count=count,bulk=True)
        if self.draft.get('profile'):
            op['profile'] = self.draft['profile']
        checked_operation(self.account,op,self.host)
        return op

    def value(self, field):
        values = self.values
        if field == 'traffic':
            if values.get('customer_unlimited'):return self.tr('Remaining plan allowance','سهمیهٔ باقی‌ماندهٔ پلن')
            if 'data_limit_value' not in values:return ''
            unit = values.get('data_limit_unit','Gi')
            return self.n(values['data_limit_value'])+' '+self.tr(unit+'B','مگابایت' if unit=='Mi' else 'گیگابایت')
        if field == 'days':
            if 'time_limit_days' not in values:return ''
            parts = [(values['time_limit_days'],self.tr('days','روز')),(values.get('time_limit_hours',0),self.tr('hours','ساعت')),(values.get('time_limit_minutes',0),self.tr('min','دقیقه'))]
            return ' · '.join(self.n(v)+' '+unit for v,unit in parts if v) or self.tr('Until plan expiry','تا پایان پلن')
        if field in ('start_on_first_use','include_internal_network') and field in values:
            if field=='start_on_first_use':return self.tr('First connection','اولین اتصال') if values[field] else self.tr('Immediately','همین حالا')
            return self.tr('Included','اضافه شود') if values[field] else self.tr('Off','خاموش')
        for key in field_keys(field):
            if key in values:
                v=values[key]
                if isinstance(v,list):return '، '.join(v) if self.fa else ', '.join(v)
                return self.n(v) if isinstance(v,int) else str(v)
        return ''

    def render(self, error=None):
        step = self.draft['step']
        if step == 'profile':
            return self.profile_menu()
        if step=='profile-name':
            hint=self.tr('Enter a unique name for these settings. Customer names, addresses and contacts are excluded.','یک نام یکتا برای این تنظیمات بنویسید. نام، آدرس اختصاصی و اطلاعات تماس مشتری در الگو ذخیره نمی‌شوند.')
            return {'text':(error+'\n\n' if error else '')+hint,
                    'reply_markup':{'inline_keyboard':[[button(self.tr('Back to review','بازگشت به بازبینی'),'step-back '+self.draft['nonce']+' profile-name')]]}}
        title = self.tr('Create peer','ساخت کاربر') if self.section=='peers' else self.tr('Create subscription','ساخت اشتراک')
        if self.mode=='bulk':title=self.tr('Create peers in bulk','ساخت گروهی کاربران')
        if self.editing:title=self.tr('Edit customer','ویرایش مشتری')
        lines=['<b>'+title+'</b>',escape(isolated(self.iface.name))]
        rows=[]
        nonce=self.draft['nonce']
        def choice(label, verb):
            return button(label,'cw '+nonce+' '+verb)
        if error:lines.extend(['',escape(error)])
        if step=='review':
            lines.extend(['','<b>'+self.tr('Review before confirming','بازبینی پیش از تأیید')+'</b>'])
            for field in self.fields:
                value=self.value(field)
                if self.editing and value=='':value=self.tr('Clear this value','پاک شود')
                if value:
                    lines.append(self.tr(*FIELDS[field])+' · '+escape(isolated(value[:180])))
            rows.append([button(self.tr('Save change','ذخیرهٔ تغییر') if self.editing else self.tr('Confirm creation','تأیید و ساخت'),'confirm '+nonce)])
            if not self.editing and 'profiles' in grants(self.account) and not self.draft.get('saved_profile'):
                rows.append([choice(self.tr('Save as profile','ذخیره به‌عنوان الگو'),'save-profile')])
            if self.draft.get('saved_profile'):
                lines.extend(['',self.tr('Profile saved','الگو ذخیره شد')+' · '+escape(self.draft['saved_profile'])])
        else:
            lines.extend(['','<b>'+self.tr(*FIELDS[step])+'</b>',self.tr(*HINTS[step])])
            if step=='address':
                lines.append(self.tr('This option is visible only when your administrator enables Choose free client IP.', 'این گزینه فقط با مجوز «انتخاب IP آزاد کاربر» از طرف مدیر نمایش داده می‌شود.'))
            if step=='mtu':
                lines.append(self.tr('Requires the administrator’s Network settings permission.', 'این گزینه به مجوز «تنظیمات شبکه» از طرف مدیر نیاز دارد.'))
            if step=='name' and self.mode=='bulk':
                lines.append(self.tr('Each name gets a numbered suffix, such as team-01.','نام‌ها به‌ترتیب شماره‌گذاری می‌شوند، مانند team-01.'))
            if step in ('phone_number','telegram_id') and self.mode=='bulk':
                lines.append(self.tr('Enter one contact per line, in peer order.','برای هر کاربر، به‌ترتیب یک شناسه یا شماره در هر خط بنویسید.'))
            current=self.value(step)
            if self.editing and not current:
                obj,_=m.target(self.account,self.section,self.draft['edit_id'])
                if step=='traffic' and obj.data_limit_value:
                    current=f'{self.n(obj.data_limit_value)} '+(self.tr('MiB','مگابایت') if obj.data_limit_unit=='Mi' else self.tr('GiB','گیگابایت'))
                elif step=='days':
                    total=round(1440*(obj.time_limit_days or 0))
                    current=(self.n(total//1440)+':'+self.n(f'{(total//60)%24:02d}')+':'+self.n(f'{total%60:02d}')) if total else self.tr('Until plan expiry','تا پایان پلن')
                elif step=='start_on_first_use':
                    current=self.tr('First connection','اولین اتصال') if obj.start_on_first_use else self.tr('Immediately','همین حالا')
                elif step not in ('traffic','include_internal_network'):
                    stored=getattr(obj,step,None)
                    if stored is not None:current=str(stored)
            default=DEFAULTS.get(step)
            if current or default is not None:
                label=self.tr('Current','مقدار فعلی') if current else self.tr('Default','پیش‌فرض')
                lines.append(label+' · <code>'+escape(str(current or default))+'</code>')
            if step=='name' and not self.editing and 'profiles' in grants(self.account):
                if CustomerProfile.query.filter_by(account_id=self.account.id,kind='peer' if self.section=='peers' else 'subscription').with_entities(CustomerProfile.id).first():
                    rows.append([choice(self.tr('Use a saved profile','انتخاب الگوی ذخیره‌شده'),'profiles')])
            if step=='name' and self.mode=='guided' and not self.editing:
                rows.append([choice(self.tr('Quick setup','ساخت سریع'),'quick')])
            if step=='traffic':
                selected=self.values.get('data_limit_unit','Gi')
                rows.append([choice(('✓ ' if selected==unit else '')+self.tr(unit+'B',fa),'unit '+unit)
                              for unit,fa in [('Mi','مگابایت'),('Gi','گیگابایت')]])
                if not self.editing and 'customer_unlimited' in self.account.spec['permissions']:
                    rows.append([choice(self.tr('Use plan allowance','استفاده از سهمیهٔ پلن'),'shared')])
            if step in ('start_on_first_use','include_internal_network'):
                yes,no=(self.tr('First connection','اولین اتصال'),self.tr('Immediately','همین حالا')) if step=='start_on_first_use' else (self.tr('Include','اضافه شود'),self.tr('Skip','رد کردن'))
                rows.append([choice(no,'no'),choice(yes,'yes')])
            if self.editing and step in ('phone_number','telegram_id','note','dns','endpoint','peer_endpoint'):
                rows.append([choice(self.tr('Clear this value','پاک کردن این مقدار'),'clear')])
            optional=step not in ('name','traffic','days','count')
            if not self.editing and (optional or current) and step not in ('start_on_first_use','include_internal_network'):
                rows.append([choice(self.tr('Keep current','حفظ مقدار فعلی') if current else self.tr('Use default','پیش‌فرض') if default is not None or step=='address' else self.tr('Skip','رد کردن'),'next')])
            if optional and not self.editing:
                rows.append([choice(self.tr('Review with current settings','بازبینی با همین تنظیمات'),'review')])
        nav=[]
        if step=='review' or step!=self.fields[0]:
            nav.append(button(self.tr('Back','مرحلهٔ قبل'),'step-back '+nonce+' '+step))
        nav.append(button(self.tr('Cancel','انصراف'),'cancel '+nonce))
        rows.append(nav)
        return {'text':'\n'.join(lines),'parse_mode':'HTML','reply_markup':{'inline_keyboard':rows}}

    def profile_menu(self):
        page=self.draft.get('page',0)
        profiles=(CustomerProfile.query.filter_by(account_id=self.account.id,kind='peer' if self.section=='peers' else 'subscription')
                  .order_by(CustomerProfile.is_default.desc(),CustomerProfile.id).offset(page*6).limit(7).all())
        nonce=self.draft['nonce']
        rows=[[button(('☆ ' if p.is_default else '')+p.name,'cw '+nonce+' profile '+str(p.id))] for p in profiles[:6]]
        nav=[]
        if page:nav.append(button('←','cw '+nonce+' page '+str(page-1)))
        if len(profiles)>6:nav.append(button('→','cw '+nonce+' page '+str(page+1)))
        if nav:rows.append(nav)
        rows.append([button(self.tr('Back','بازگشت'),'step-back '+nonce+' profile')])
        return {'text':self.tr('Choose one of your saved profiles.','یکی از الگوهای ذخیره‌شدهٔ خود را انتخاب کنید.'),'reply_markup':{'inline_keyboard':rows}}

    def apply_profile(self, pid):
        profile=own_profile(self.account,self.section,pid)
        raw=dict(profile.options or {})
        if self.section=='subscriptions' and ('client' in raw or 'advanced' in raw):
            raw={**(raw.get('advanced') if isinstance(raw.get('advanced'),dict) else {}),**(raw.get('client') if isinstance(raw.get('client'),dict) else {})}
            if isinstance(raw.get('routes'),list):
                raw['allowed_ips']=', '.join(raw['routes'])
        if 'data_limit' in raw:raw.setdefault('data_limit_value',raw['data_limit'])
        if 'limit_unit' in raw:raw.setdefault('data_limit_unit',raw['limit_unit'])
        kept=clean_options(self.account,{'values':raw},self.fields)
        for key in ('name','count','phone_number','phone_numbers','telegram_id','telegram_ids','address','customer_unlimited'):
            kept.pop(key,None)
        if kept.get('data_limit_value') in ('',0,'0',None):
            kept.pop('data_limit_value',None)
        for key in list(kept):
            if kept[key] is None or kept[key]=='':kept.pop(key)
        validated=m.validate_options(self.account,{**kept,'name':'Profile'})
        if 'data_limit_value' in kept:kept['data_limit_value']=validated['data_limit_value']
        if any(key in kept for key in field_keys('days')):
            total=round(validated['time_limit_days']*1440)
            kept.update(time_limit_days=total//1440,time_limit_hours=(total%1440)//60,time_limit_minutes=total%60)
        if 'start_on_first_use' in kept:kept['start_on_first_use']=validated['start_on_first_use']
        if 'include_internal_network' in kept:kept['include_internal_network']=kept['include_internal_network'] in (True,1,'1','true','on')
        self.values={**{k:v for k,v in self.values.items() if k in ('name','count')},**kept}
        self.draft['profile']=profile.id
        self.save('name')
        return self.render()

    def text_value(self, field, raw):
        if field == 'name':
            if not 1<=len(raw)<=48 or not raw.replace('‌','').isprintable():raise ValueError()
            return {'name':raw}
        if field=='traffic':
            match=re.fullmatch(r'(\d{1,12})\s*(MiB?|GiB?|مگابایت|گیگابایت)?',raw,re.I)
            if not match:raise ValueError()
            quantity=int(match[1])
            unit=self.values.get('data_limit_unit','Gi')
            if match[2]:unit='Mi' if match[2].lower().startswith(('m','م')) else 'Gi'
            maximum=self.account.spec['traffic_gib']*(1024 if unit=='Mi' else 1)
            if not 1<=quantity<=maximum:raise ValueError()
            return {'data_limit_value':quantity,'data_limit_unit':unit}
        if field=='days':
            match=re.fullmatch(r'(\d{1,4})(?::(\d{1,2})(?::(\d{1,2}))?)?',raw)
            if not match:raise ValueError()
            days,hours,minutes=(int(item or 0) for item in match.groups())
            if days>3650 or hours>23 or minutes>59 or (self.mode=='quick' and days+hours+minutes==0):raise ValueError()
            values={'time_limit_days':days}
            if hours:values['time_limit_hours']=hours
            if minutes:values['time_limit_minutes']=minutes
            return values
        if field=='count':
            if not raw.isdecimal() or len(raw)>2:raise ValueError()
            count=int(raw)
            remaining=self.account.spec['peers']-s.counts(self.account)[0]
            if not 1<=count<=min(50,remaining,limits(self.account.spec)['bulk_limit']):raise ValueError()
            return {'count':count}
        if field in ('start_on_first_use','include_internal_network'):
            if raw not in ('yes','no'):raise ValueError()
            return {field:raw=='yes'}
        if field=='address':return {field:m.requested_address(self.iface,raw)}
        if field in ('phone_number','telegram_id'):
            entries=[v.strip() for v in re.split(r'[,،\n]',raw)] if self.mode=='bulk' else [raw]
            if len(entries)>self.values.get('count',1):raise ValueError()
            for v in entries:
                m.validate_options(self.account,{'name':'Customer',field:v})
            return {field+'s':entries} if self.mode=='bulk' else {field:raw}
        if field in ('allowed_ips','dns'):
            raw=raw.replace('،',',')
        if field in ('mtu','persistent_keepalive'):
            if not raw.isdecimal() or len(raw)>5:raise ValueError()
            raw=int(raw)
        m.validate_options(self.account,{'name':'Customer',field:raw})
        return {field:raw}

    def advance(self):
        idx=self.fields.index(self.draft['step'])+1
        while idx<len(self.fields) and self.draft.get('profile') and self.value(self.fields[idx]):
            idx+=1
        self.save(self.fields[idx] if idx<len(self.fields) else 'review')
        return self.render()

    def invalid(self):
        step=self.draft['step']
        if step=='traffic':
            unit=self.values.get('data_limit_unit','Gi')
            max_value=self.account.spec['traffic_gib']*(1024 if unit=='Mi' else 1)
            error=self.tr(f'Enter a whole number from 1 to {max_value}.',f'عددی صحیح بین ۱ و {self.n(max_value)} وارد کنید.')
        elif step=='count':
            maximum=min(limits(self.account.spec)['bulk_limit'],self.account.spec['peers']-s.counts(self.account)[0])
            error=self.tr(f'You can create up to {maximum} peers in this batch.',f'در این گروه حداکثر {self.n(maximum)} کاربر می‌توانید بسازید.')
        elif step=='mtu':
            error=self.tr('MTU must be a whole number of bytes from 576 to 9000 (e.g. 1420).', 'MTU باید عدد صحیح بین ۵۷۶ تا ۹۰۰۰ بایت باشد؛ مانند ۱۴۲۰.')
        elif step=='address':
            error=self.tr('Enter a free private IP on this WireGuard interface, not the public server host.', 'IP داخلی آزاد همین رابط WireGuard را وارد کنید، نه آدرس عمومی سرور.')
        elif step=='days':
            error=self.tr('Use up to 3650 days, 23 hours and 59 minutes.','حداکثر ۳۶۵۰ روز، ۲۳ ساعت و ۵۹ دقیقه مجاز است.')
        else:
            error=self.tr('Please check this value and try again.','لطفاً مقدار واردشده را بررسی کنید و دوباره بفرستید.')
        return self.render(error)

    def handle(self, raw, callback, cmd, parts, menu):
        step=self.draft['step']
        nonce=self.draft.get('nonce')
        if cmd=='cancel':
            if len(parts)==2 and parts[1]==nonce or not callback and len(parts)==1:
                self.bot.pending=None
                return {'text':self.tr('Cancelled.','لغو شد.'),'reply_markup':{'inline_keyboard':menu()}}
            return self.render()
        if expiry(self.draft):
            self.bot.pending=None
            return {'text':self.tr('This setup expired. Start again from the customer menu.','مهلت این مرحله تمام شد. از منوی مشتریان دوباره شروع کنید.'),
                    'reply_markup':{'inline_keyboard':[[button(self.tr('Back to customers','بازگشت به مشتریان'),self.section+' 0')]]}}
        if not nonce:self.save()
        if cmd=='resume-draft':return self.render()
        if cmd in ('confirm','confirm-backup','step-back','cw') and (len(parts)<2 or parts[1]!=self.draft['nonce']):
            return self.render()
        if cmd=='confirm' and len(parts)==2 and step=='review':
            if not self.editing:
                for required in ('count','name','traffic','days'):
                    if required in self.fields and not self.value(required):
                        self.save(required)
                        return self.render(self.tr('Review your current settings.','تنظیمات فعلی را بررسی کنید.'))
            op=self.operation()
            if self.draft.get('operation')!=op:
                self.save('review')
                return self.render(self.tr('Your permissions or settings changed. Review these details again.','مجوزها یا تنظیمات تغییر کرده‌اند. مشخصات را دوباره بررسی کنید.'))
            self.bot.pending=None
            return {'operation':op}
        if cmd=='step-back' and len(parts)==3 and parts[2]==step:
            target='review' if step=='profile-name' else 'name' if step=='profile' else self.fields[-1] if step=='review' else self.fields[max(0,self.fields.index(step)-1)]
            self.save(target)
            return self.render()
        if cmd=='cw' and len(parts)>=3:
            action=parts[2]
            if action=='save-profile' and step=='review' and not self.editing and 'profiles' in grants(self.account) and not self.draft.get('saved_profile'):
                self.save('profile-name')
            elif step=='name' and self.mode=='guided' and action=='quick' and not self.editing:
                self.mode=self.draft['mode']='quick'
                self.draft.pop('profile',None)
                self.fields=['name','traffic','days']
                self.values={k:v for k,v in self.values.items() if k=='name'}
                self.save('name')
            elif action=='profiles' and step=='name' and not self.editing and 'profiles' in grants(self.account):
                self.draft['page']=0
                self.save('profile')
            elif step=='profile' and 'profiles' in grants(self.account):
                if action=='page' and len(parts)==4 and parts[3].isdecimal():
                    self.draft['page']=min(int(parts[3]),100);self.save()
                if action=='profile' and len(parts)==4 and parts[3].isdecimal():
                    try:return self.apply_profile(int(parts[3]))
                    except ValueError:return self.render()
            elif action=='clear' and self.editing and step in ('phone_number','telegram_id','note','dns','endpoint','peer_endpoint'):
                self.values={step:''}
                self.save('review')
            elif action=='unit' and step=='traffic' and len(parts)==4 and parts[3] in ('Mi','Gi'):
                if self.values.get('data_limit_unit','Gi') != parts[3]:
                    self.values.pop('data_limit_value',None)
                self.values['data_limit_unit']=parts[3]
                self.save()
            elif action=='shared' and step=='traffic' and not self.editing and 'customer_unlimited' in self.account.spec['permissions']:
                for key in (*field_keys('traffic'),*field_keys('days'),'start_on_first_use'):
                    self.values.pop(key,None)
                self.values['customer_unlimited']=True
                self.fields=[f for f in self.fields if f not in ('days','start_on_first_use')]
                return self.advance()
            elif action in ('yes','no') and step in ('start_on_first_use','include_internal_network'):
                self.values.update(self.text_value(step,action))
                return self.advance()
            elif action=='next' and not self.editing and step in self.fields and (step not in ('name','traffic','days','count') or self.value(step)):
                return self.advance()
            elif action=='review' and not self.editing and step in self.fields and step not in ('name','traffic','days','count'):
                self.save('review')
            return self.render()
        if step=='profile-name' and not callback and not raw.startswith('/') and cmd not in ('confirm','cw','step-back','confirm-backup'):
            if self.editing or 'profiles' not in grants(self.account):raise ValueError('Permission changed.')
            kind='peer' if self.section=='peers' else 'subscription'
            try:
                name=profile_name(self.account,kind,raw)
                profile_capacity(self.account)
            except ValueError:
                return self.render(self.tr('Check the name and the number of available profile slots.','نام الگو و ظرفیت باقی‌ماندهٔ الگوها را بررسی کنید.'))
            keep=set(m.NETWORK)|{'data_limit_value','data_limit_unit','time_limit_days','time_limit_hours','time_limit_minutes','start_on_first_use','include_internal_network'}
            stored={k:v for k,v in self.values.items() if k in keep}
            db.session.add(CustomerProfile(account_id=self.account.id,kind=kind,name=name,options=stored))
            s.audit('reseller:'+str(self.account.id),'profile_created',name)
            self.draft['saved_profile']=name
            self.save('review')
            return self.render()
        if not callback and not raw.startswith('/') and cmd not in ('confirm','confirm-backup','step-back','cw') and step in self.fields:
            try:
                values=self.text_value(step,raw)
            except (ValueError,TypeError,OverflowError):
                return self.invalid()
            for key in field_keys(step):self.values.pop(key,None)
            self.values.update(values)
            if step=='traffic' and not self.editing:
                self.fields=authorized_fields(self.account,self.iface,self.section,self.mode,self.host)
            return self.advance()
        return self.render()


def activity_fa(action):
    return {'management_bot_action':'مدیریت مشتری','management_bot_rejected':'درخواست انجام‌نشده',
            'bot_download':'دریافت تنظیمات','telegram_backup_export':'دریافت پشتیبان','telegram_test':'آزمایش اتصال',
            'telegram_alert':'هشدار مشتری','telegram_problem':'هشدار سرویس','telegram_recovery':'رفع مشکل',
            'telegram_notifications':'تنظیم اعلان‌ها','telegram_connected':'اتصال ربات','telegram_disconnected':'قطع اتصال ربات',
            'telegram_delivery':'تنظیم ارسال پیام','telegram_bot_enabled':'تغییر وضعیت ربات'}.get(action,'فعالیت ربات')
