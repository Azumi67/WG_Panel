from . import service as s
from .bot_customers import button, deadline, expiry, own_profile, profile_name
from .models import CustomerProfile
from .telegram_policy import effective
from models import db
import secrets


def handle(account, bot, raw, callback, command, parts, menu):
    pending = bot.pending or {}
    renaming = pending.get('kind') == 'profile-rename' and not callback and not raw.startswith('/') and command != 'cancel'
    if command not in ('profiles','profile-list','profile-open','profile-rename','profile-delete','profile-remove','profile-default') and not renaming:
        return None
    access = effective(account)
    if 'profiles' not in access: raise ValueError('Permission changed.')
    s.require_active(account)
    fa = bot.language == 'fa'

    def tr(en, persian):
        return persian if fa else en

    def reply(text, rows):
        return {'text': text, 'reply_markup': {'inline_keyboard': rows}}

    if callback and command in ('profiles','profile-list','profile-open') and pending.get('kind') in ('profile-rename','profile-delete'):
        bot.pending=None
    if command == 'profiles' and not renaming:
        rows = []
        for section, label in [('peers',tr('Peer profiles','الگوهای کاربران')),('subscriptions',tr('Subscription profiles','الگوهای اشتراک'))]:
            if section in access: rows.append([button(label,'profile-list '+section+' 0')])
        rows.append([button(tr('Main menu','منوی اصلی'),'menu')])
        return reply(tr('Saved customer profiles','الگوهای ذخیره‌شدهٔ مشتریان'),rows)
    if renaming or command == 'profile-remove':
        section = pending.get('section')
    else:
        section = parts[1] if len(parts)>1 else None
    if section not in ('peers','subscriptions') or section not in access: raise ValueError('Permission changed.')
    kind = 'peer' if section == 'peers' else 'subscription'
    profile_query = CustomerProfile.query.filter_by(account_id=account.id,kind=kind)
    if command == 'profile-list' and not renaming:
        page = max(0,min(100,int(parts[2])))
        found = profile_query.order_by(CustomerProfile.is_default.desc(),CustomerProfile.id).offset(6*page).limit(7).all()
        rows = [[button(('☆ ' if p.is_default else '')+p.name,f'profile-open {section} {p.id}')] for p in found[:6]]
        key = 'profile-list '+section+' '
        paging = []
        if page: paging.append(button('←',key+str(page-1)))
        if len(found)>6: paging.append(button('→',key+str(page+1)))
        if paging: rows.append(paging)
        rows.append([button(tr('Back','بازگشت'),'profiles')])
        text = tr('Choose a saved profile.','یک الگوی ذخیره‌شده را انتخاب کنید.') if found else tr('No saved profiles.','هنوز الگویی ذخیره نکرده‌اید.')
        if not found and 'create' in access:
            text += '\n\n'+tr('Set up a customer and choose Save as profile on the review screen.','هنگام ساخت مشتری، در مرحلهٔ بازبینی «ذخیره به‌عنوان الگو» را انتخاب کنید.')
            rows.insert(0,[button(tr('Set up a customer','ساخت مشتری'),'new '+section)])
        return reply(text,rows)
    if renaming or command=='profile-remove':
        if expiry(pending) or (command=='profile-remove' and
                (pending.get('kind')!='profile-delete' or len(parts)!=2 or pending.get('nonce')!=parts[1])):
            return reply(tr('Open the latest profile menu.','منوی الگوها را دوباره باز کنید.'),menu())
        pid = pending['profile_id']
    else:
        pid = int(parts[2])
    profile = own_profile(account,section,pid)
    back = [button(tr('Back to profiles','بازگشت به الگوها'),'profile-list '+section+' 0')]
    if renaming:
        try: name = profile_name(account,kind,raw,exclude=pid)
        except ValueError: return reply(tr('Choose a unique name, up to 64 characters.','یک نام یکتا با حداکثر ۶۴ نویسه انتخاب کنید.'),[back])
        profile.name = name
        bot.pending = None
        s.audit('reseller:'+str(account.id),'profile_rename',str(pid))
    elif command=='profile-default':
        for current in profile_query.all(): current.is_default = current.id==pid
        s.audit('reseller:'+str(account.id),'profile_default',str(pid))
    elif command=='profile-remove':
        db.session.delete(profile)
        bot.pending = None
        s.audit('reseller:'+str(account.id),'profile_delete',str(pid))
        return reply(tr('Profile deleted.','الگو حذف شد.'),[back])
    elif command in ('profile-rename','profile-delete'):
        nonce = secrets.token_urlsafe(9)
        bot.pending = dict(kind=command,section=section,profile_id=pid,until=deadline(),nonce=nonce)
        cancel = button(tr('Cancel','انصراف'),'cancel '+nonce)
        if command=='profile-rename':
            return reply(tr('Enter the new profile name.','نام جدید الگو را بنویسید.'),[[cancel]])
        return reply(tr('Delete this saved profile?','این الگو حذف شود؟')+'\n'+profile.name,
                     [[button(tr('Delete profile','حذف الگو'),'profile-remove '+nonce),cancel]])
    target = f'{section} {pid}'
    rows = []
    if 'create' in access: rows.append([button(tr('Use in customer setup','استفاده برای ساخت مشتری'),'new-profile '+target)])
    if not profile.is_default: rows.append([button(tr('Set as default','تنظیم به‌عنوان پیش‌فرض'),'profile-default '+target)])
    rows.append([button(tr('Rename','تغییر نام'),'profile-rename '+target),button(tr('Delete','حذف'),'profile-delete '+target)])
    rows.append(back)
    text = ('☆ ' if profile.is_default else '')+profile.name
    if profile.is_default: text += '\n'+tr('Default profile','الگوی پیش‌فرض')
    return reply(text,rows)
