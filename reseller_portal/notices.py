from panel_core.telegram_notices import card
from . import service as s
from .regional import display
from .telegram_text import isolated, number, persian_time, rtl_lines


def language(account=None, chat=None):
    tid = account.telegram_id if account else chat
    return s.setting('bot_lang:'+str(tid), 'en') if tid else 'en'


def account_notice(account, event, *, order=None, note='', password_url=None, chat=None):
    fa = language(account, chat) == 'fa'
    def tr(en, persian):
        return persian if fa else en
    titles = {
        'approved': ('Plan activated','پلن فعال شد'), 'renewed':('Plan renewed','پلن تمدید شد'),
        'rejected':('Payment declined','پرداخت تأیید نشد'), 'created':('Workspace ready','پنل نمایندگی آماده است'),
        'suspended':('Workspace suspended','دسترسی به پنل متوقف شد'), 'rotate':('New sign-in link','لینک ورود تازه'),
        'password':('Set your password','تنظیم گذرواژه'), 'totp':('Authenticator reset','ورود دومرحله‌ای بازنشانی شد'),
        'manual':('Message from your administrator','پیام مدیر پنل'),
    }
    fields = [(tr('Account','حساب'), isolated(account.username) if fa else account.username)] if account else []
    if order:
        fields += [(tr('Order','سفارش'), number(order.id) if fa else str(order.id)),
                   (tr('Plan','پلن'), order.spec.get('plan_name') or str(order.plan_id))]
    buttons = []
    if event in ('approved','renewed'):
        fields.append((tr('Valid until','پایان اعتبار'), persian_time(account.expires_at) if fa else display(account.expires_at)))
    if password_url:
        buttons.append((tr('Set password','تنظیم گذرواژه'), password_url))
        note = tr('The password link is valid for 24 hours.', 'لینک تنظیم گذرواژه تا ۲۴ ساعت اعتبار دارد.')
    if event in ('approved','renewed','created','rotate','totp'):
        buttons.append((tr('Open workspace','ورود به پنل'),s.workspace_link(account)))
    if event == 'suspended':
        note = tr('Contact your administrator about account access.', 'برای دسترسی به حساب با مدیر پنل تماس بگیرید.')
    elif event == 'totp':
        note = tr('Sign in to connect your authenticator again.', 'وارد پنل شوید و برنامه ورود دومرحله‌ای را دوباره وصل کنید.')
    notice = card(tr(*titles[event]), fields, note, '⊘' if event in ('rejected','suspended') else '◇', buttons)
    if fa:
        notice['text'] = rtl_lines(notice['text'])
    return notice
