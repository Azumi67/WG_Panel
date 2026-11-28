
import json
import re
import secrets
from html import escape
from datetime import timedelta
from models import db
from .models import Account,Plan,Order,Notice
from . import service as s
from .regional import display
from .telegram_text import isolated, number, persian_price, persian_time, rtl_lines


def payment_problem(spec):
    if not isinstance(spec,dict):return 'Provide instructions for the buyer.'
    text=spec.get('payment_instructions')
    if not isinstance(text,str) or not text.strip():return 'Provide instructions for the buyer.'
    if len(text.strip())>1500:return 'Keep buyer instructions within 1500 characters.'
    return None


def valid_payment(spec):
    return payment_problem(spec) is None


def refresh_workspace_button(payload, chat_id):
    owner_id = payload.get('workspace_owner')
    rows = payload.get('reply_markup', {}).get('inline_keyboard', [])
    links = [item for row in rows for item in row if 'url' in item and '/r/' in item['url']]
    if not links and owner_id is None:
        return True
    account = Account.query.filter_by(telegram_id=chat_id).first()
    if owner_id is not None and (not account or account.id != owner_id):
        return False
    current = s.workspace_link(account)
    for item in links:
        if not current or (owner_id is None and item['url'] != current):
            return False
        item['url'] = current
    return True


def handle(update):
    cb=update.get('callback_query') or {}
    msg=cb.get('message') or update.get('message') or {}
    sender=cb.get('from') or msg.get('from') or {};chat=msg.get('chat') or {}
    if chat.get('type')!='private' or sender.get('is_bot') or type(sender.get('id')) is not int or sender['id']<=0 or sender['id']!=chat.get('id'):return
    tid=str(sender['id']);uid=str(update.get('update_id',''))
    if not uid.isdigit():return
    uid=s.digest(str(s.setting('bot_token','')))[:24]+':'+uid
    if Notice.query.filter_by(dedupe='0:0:update:'+uid).first():return
    if not s.throttle('bot:'+tid,20,60):return
    saved_language=s.setting('bot_lang:'+tid,None)
    lang=saved_language or ('fa' if str(sender.get('language_code','')).lower().startswith('fa') else 'en')
    if lang not in ('en','fa'):lang='en'
    if saved_language not in ('en','fa'):
        s.put('bot_lang:'+tid,lang)
    def tr(en,fa):return fa if lang=='fa' else en
    text=str(msg.get('text','')).strip()[:2000] if not cb else ''
    aliases={'📦 Plans':'/plans','📊 My account':'/status','🔐 Open workspace':'/link','❓ Help':'/help','‹ Main menu':'/start'}
    text=aliases.get(text,text);parts=text.split(maxsplit=2)
    command=parts[0].split('@')[0].lower() if parts else ''
    action={'/start':'home','/help':'help','/plans':'plans','/status':'account','/orders':'orders','/menu':'home','/link':'link','/language':'language','/id':'identity'}.get(command,'input');arg=''
    nav=s.setting('bot_nav:'+tid,{})
    if cb:
        fields=str(cb.get('data','')).split(':')
        if len(fields)==4 and fields[0]=='rp' and secrets.compare_digest(fields[1],str(nav.get('nonce',''))) and nav.get('until','')>s.now().isoformat():
            action,arg=fields[2:]
        else:action='stale'
    elif command=='/buy' and len(parts)>1:action,arg='plan',parts[1]
    elif command=='/language' and len(parts)>1 and parts[1] in ('en','fa'):action,arg='lang',parts[1]
    elif re.fullmatch(r'Buy plan #\d+',text):action,arg='plan',text.rsplit('#',1)[1]
    elif re.fullmatch(r'Submit reference #\d+',text):action,arg='receipt',text.rsplit('#',1)[1]
    if action=='lang' and arg in ('en','fa'):
        lang=arg;saved_language=lang;s.put('bot_lang:'+tid,lang);action='home'
    nonce=secrets.token_hex(4)
    rows=[];body='';edit_id=msg.get('message_id') if cb and action!='stale' else None
    icons = {'plans':'◇', 'account':'◷', 'orders':'≡', 'help':'?', 'identity':'⌖', 'language':'◎',
             'order':'▤', 'plan':'◇', 'receipt':'▣', 'cancelcheck':'×', 'cancel':'×',
             'home':'‹', 'buy':'＋', 'checkout':'›', 'lang':'◎'}
    def button(en,fa,act,ident=''):
        return {'text':('‏' if lang=='fa' else '')+icons.get(act, '›')+' '+(fa if lang=='fa' else en),'callback_data':f'rp:{nonce}:{act}:{ident}'}
    def home_button():return button('Main menu','منوی اصلی','home')
    def own(oid):
        order=s.buyer_orders(tid).filter_by(id=int(oid)).first()
        if not order:raise ValueError(tr('Order not found.','سفارش یافت نشد.'))
        return order
    def summary(spec):
        price = escape(str(spec['price']) + ' ' + str(spec['currency']))
        days, traffic, peers, subs = (int(spec[k]) for k in ('days', 'traffic_gib', 'peers', 'subscriptions'))
        return tr(f'<b>{price}</b>   ·   {days} days\n{traffic:,} GiB   ·   {peers:,} peers   ·   {subs:,} subscriptions',
                  f'مبلغ: <b>{escape(persian_price(spec["price"],spec["currency"]))}</b>\nاعتبار: {number(days)} روز  ·  حجم: {number(traffic)} گیگابایت\nظرفیت: {number(peers)} کاربر و {number(subs)} اشتراک')
    def order_status(order):
        if order.state == 'pending':
            return tr('Under review', 'در انتظار بررسی') if order.payment_ref else tr('Awaiting payment', 'در انتظار پرداخت')
        return {'approved': tr('Activated', 'فعال شده'), 'rejected': tr('Rejected', 'رد شده'),
                'cancelled': tr('Cancelled', 'لغو شده')}.get(order.state, order.state)

    formatted = False
    def order_screen(order):
        nonlocal body,rows,formatted
        formatted = True
        status = order_status(order)
        plan_title = escape(str(order.spec.get('plan_name') or tr(f'Plan #{order.plan_id}', f'پلن {number(order.plan_id)}')))
        body = f'<b>{status}</b>  ·  ' + tr(f'Order #{order.id}', f'سفارش {number(order.id)}') + '\n' + plan_title + '\n\n' + summary(order.spec)
        if order.state=='pending' and not order.payment_ref:
            body+='\n\n'+tr('<b>Payment instructions</b>','<b>راهنمای پرداخت</b>')+'\n'+escape(order.spec['payment_instructions'])
            body+='\n\n'+tr('After paying, submit your receipt photo or transaction reference. Activation requires admin approval.','پس از پرداخت، تصویر رسید یا کد پیگیری را ارسال کنید. فعال‌سازی پس از تأیید مدیر انجام می‌شود.')
            rows=[[button('Submit receipt','ارسال رسید','receipt',str(order.id))],[button('Cancel order','لغو سفارش','cancelcheck',str(order.id)),button('Refresh status','وضعیت سفارش','order',str(order.id))]]
        elif order.state=='pending':
            body+='\n\n'+tr('Receipt received. Your order stays here until the administrator approves or declines it. Your new plan period starts on approval. Please do not pay again.','رسید دریافت شد و تا تصمیم مدیر در صف بررسی می‌ماند. دوره جدید از زمان تأیید شروع می‌شود. دوباره پرداخت نکنید.')
            rows=[[button('Refresh status','وضعیت سفارش','order',str(order.id))]]
        else:rows=[]
        rows.append([home_button()])
    account=None
    try:
        account=Account.query.filter_by(telegram_id=tid).first()
        if action=='home':
            s.put('bot_receipt:'+tid,{})
            welcome=s.setting('bot_welcome_fa' if lang=='fa' else 'bot_welcome','')
            body=welcome or tr('Welcome to your reseller desk.\nChoose a plan or manage your account below.','خوش آمدید. برای خرید یا تمدید، یک پلن انتخاب کنید.')
            rows=[[button('Browse plans','مشاهده پلن‌ها','plans'),button('My account','حساب من','account')],[button('My orders','سفارش‌های من','orders'),button('Help','راهنما','help')],[button('My ID','شناسه من','identity'),button('Language · زبان','زبان','language')]]
            formatted = True
            body = tr('◇ <b>Plan shop</b>', '◇ <b>خرید و تمدید پلن</b>') + '\n' + escape(body)
            open_order = s.buyer_orders(tid).filter_by(state='pending').order_by(Order.id.desc()).first()
            workspace = s.workspace_link(account)
            if workspace:
                body = (
                    tr('◇ <b>My dashboard</b>', '◇ <b>داشبورد من</b>') + '\n' + escape(isolated(account.username)) + ' · ' +
                    (tr('Plan expired','پلن منقضی شده') if account.expires_at<=s.now() else tr('Traffic used up','حجم پلن تمام شده') if not s.active(account) else tr('Active plan','پلن فعال')))
                limit=int(account.spec['traffic_gib']);used=account.used_bytes/s.GIB
                remaining=max(0,limit-used);percent=min(100,max(0,round(used/max(1,limit)*100)))
                filled=round(percent/10);meter='▰'*filled+'▱'*(10-filled)
                body+='\n\n'+tr('◷ <b>Account allowance</b>','◷ <b>مصرف پلن</b>')
                body+='\n'+tr(f'<code>{meter}</code> {percent}% used',f'حجم مصرف‌شده: {number(percent)}٪')
                body+='\n'+tr(f'<b>{remaining:,.2f} GiB</b> left of {limit:,} GiB',f'حجم باقی‌مانده: <b>{number(round(remaining,2))} گیگابایت</b> از {number(limit)} گیگابایت')
                body+='\n'+tr('Valid until: ','پایان اعتبار: ')+escape(persian_time(account.expires_at) if lang=='fa' else display(account.expires_at))
                if welcome:
                    body+='\n\n'+escape(welcome)
                rows.insert(0, [{'text': tr('⌁ Open workspace', '⌁ ورود به پنل'), 'url': workspace}])
            if open_order:
                status = tr('Under review', 'در انتظار بررسی') if open_order.payment_ref else tr('Awaiting receipt', 'در انتظار رسید')
                body += '\n\n' + tr(f'Order #{open_order.id}', f'سفارش {number(open_order.id)}') + ' · ' + status
                if open_order.payment_ref:
                    body += '\n' + tr('Your receipt is saved. We will message you after review.', 'رسیدتان ثبت شد. نتیجه را همین‌جا به شما خبر می‌دهیم.')
                rows.insert(1 if workspace else 0, [button('View open order', 'پیگیری سفارش', 'order', str(open_order.id))])
        elif action=='identity':
            body=tr(f'Your Telegram ID: {tid}',f'شناسه تلگرام شما: {isolated(tid)}')
            body+='\n'+(tr(f'Reseller: {account.username} · R-{account.id}',f'حساب نمایندگی: {isolated(account.username)}') if account else tr('No reseller account linked yet. Give this ID to the administrator for manual account creation.','هنوز حساب نمایندگی متصل نشده است. برای ساخت حساب دستی، این شناسه را به مدیر بدهید.'))
            rows=[[home_button()]]
        elif action=='language':
            formatted = True
            body=tr('<b>Language preferences</b>\nChoose the language used for your plan shop messages.',
                    '<b>انتخاب زبان</b>\nزبان پیام‌های ربات خرید و تمدید پلن را انتخاب کنید.')
            english = button('English','English','lang','en')
            persian = button('فارسی','فارسی','lang','fa')
            english['text'] = ('✓ ' if lang == 'en' else '') + 'English'
            persian['text'] = '\u200f' + ('✓ ' if lang == 'fa' else '') + 'فارسی'
            rows = [[english, persian], [home_button()]]
        elif action=='plans':
            catalog = Plan.query.filter_by(active=True)
            total = max(1, (catalog.count()+7)//8)
            page = min(max(0,int(arg or 0)),total-1)
            plans = catalog.order_by(Plan.id.desc()).offset(page*8).limit(8).all()
            body=tr('Choose a plan\nTap a plan to view its limits and price.','انتخاب پلن\nبرای مشاهده قیمت و محدودیت‌ها، پلن را انتخاب کنید.')
            if not plans:body=tr('No plans are ready for purchase yet.','در حال حاضر پلنی برای خرید آماده نیست.')
            rows=[[button(p.name,p.name,'plan',str(p.id))] for p in plans]
            navrow=[]
            if page:navrow.append(button('Previous','قبلی','plans',str(page-1)))
            if page+1<total:navrow.append(button('Next','بعدی','plans',str(page+1)))
            if navrow:rows.append(navrow)
            rows.append([home_button()])
        elif action in ('plan','checkout','buy'):
            plan=db.session.get(Plan,int(arg))
            if not plan or not plan.active:raise ValueError(tr('This plan is unavailable. Choose another plan.','این پلن در دسترس نیست. پلن دیگری انتخاب کنید.'))
            if action in ('buy','checkout') and not valid_payment(plan.spec):
                raise ValueError(tr('Payment setup is incomplete for this plan. Please contact support.','اطلاعات پرداخت این پلن هنوز تکمیل نشده است. لطفاً با پشتیبانی تماس بگیرید.'))
            if action=='buy':
                order=s.order_new(tid,plan.id);order_screen(order)
            else:
                formatted = True
                body = '<b>'+escape(plan.name)+'</b>\n\n'+summary(plan.spec)
                if not valid_payment(plan.spec):body+='\n\n'+tr('Payment setup incomplete — contact support before paying.','اطلاعات پرداخت تکمیل نشده است؛ قبل از پرداخت با پشتیبانی تماس بگیرید.')
                if action=='checkout':
                    body+='\n\n'+tr('Renewal begins a fresh period immediately after approval and replaces the current allowance.','تمدید بلافاصله پس از تأیید شروع می‌شود و سهمیه فعلی را جایگزین می‌کند.') if account else '\n\n'+tr('Your account starts after administrator approval.','حساب شما پس از تأیید مدیر فعال می‌شود.')
                    rows=[[button('Confirm renewal' if account else 'Create order','تأیید تمدید' if account else 'ثبت سفارش','buy',arg)],[button('Back','بازگشت','plan',arg),home_button()]]
                else:rows=[[button('Renew with this plan' if account else 'Continue','تمدید با این پلن' if account else 'ادامه','checkout',arg)],[button('Back to plans','بازگشت به پلن‌ها','plans')]]
        elif action in ('order','receipt','cancelcheck','cancel'):
            order=own(arg)
            if action=='receipt':
                if order.state!='pending' or order.payment_ref:order_screen(order)
                else:
                    s.put('bot_receipt:'+tid, {'order': order.id})
                    body=tr(f'Send receipt · Order #{order.id}\n\nSend a receipt as a Telegram photo (up to 5 MB), or send the transaction reference as text. You may include a caption with the photo.\n\nSend it when ready. Once received, it stays in review until the administrator decides.',f'ارسال رسید سفارش {number(order.id)}\n\nعکس رسید (تا ۵ مگابایت) یا کد پیگیری پرداخت را همین‌جا بفرستید. پس از ثبت رسید، سفارش تا پاسخ مدیر باز می‌ماند.')
                    rows=[[button('Back to order','بازگشت به سفارش','order',arg),home_button()]]
            elif action in ('cancelcheck','cancel'):
                if order.state not in ('pending','cancelled') or order.payment_ref:raise ValueError(tr('An order under review cannot be cancelled here. Contact support.','رسید این سفارش در حال بررسی است. برای پیگیری با پشتیبانی تماس بگیرید.'))
                if action=='cancelcheck':body=tr('Cancel this unpaid order?','سفارش پرداخت‌نشده لغو شود؟');rows=[[button('Yes, cancel','بله، لغو شود','cancel',arg),button('Keep order','حفظ سفارش','order',arg)]]
                else:
                    order = s.cancel_order(tid,order.id)
                    s.put('bot_receipt:'+tid,{})
                    order_screen(order)
            else:s.put('bot_receipt:'+tid,{});order_screen(order)
        elif action=='orders':
            orders=s.buyer_orders(tid).order_by(Order.id.desc()).limit(8).all()
            body=tr('Your recent orders','سفارش‌های اخیر شما') if orders else tr('You have no orders yet.','هنوز سفارشی ثبت نکرده‌اید.')
            rows = []
            for order in orders:
                status = order_status(order)
                rows.append([button(f'Order #{order.id} · {status}', f'سفارش {number(order.id)} · {status}', 'order', str(order.id))])
            rows.append([home_button()])
        elif action in ('account','link'):
            if not account:body=tr('No reseller account yet. Browse plans to get started.','هنوز حساب نمایندگی ندارید. از بخش پلن‌ها شروع کنید.');rows=[[button('Browse plans','مشاهده پلن‌ها','plans')],[home_button()]]
            else:
                pc,sc=s.counts(account)
                body=tr(f'{account.username} · R-{account.id}\nTelegram ID: {tid}\nTraffic remaining: {max(0,account.spec["traffic_gib"]-account.used_bytes/s.GIB):.2f} GiB\nPeers: {pc}/{account.spec["peers"]} · Subscriptions: {sc}/{account.spec["subscriptions"]}\nExpires: {display(account.expires_at)}',f'حساب نمایندگی: {isolated(account.username)}\nشناسه تلگرام: {isolated(tid)}\nحجم باقی‌مانده: {number(round(max(0,account.spec["traffic_gib"]-account.used_bytes/s.GIB),2))} گیگابایت\nکاربران: {number(pc)} از {number(account.spec["peers"])}  ·  اشتراک‌ها: {number(sc)} از {number(account.spec["subscriptions"])}\nپایان اعتبار: {persian_time(account.expires_at)}')
                workspace = s.workspace_link(account)
                if workspace:rows=[[{'text':tr('⌁ Open workspace','⌁ ورود به پنل'),'url':workspace}]]
                else:body+='\n\n'+tr('Workspace access is currently unavailable.','ورود به پنل در حال حاضر در دسترس نیست.')
                order_buttons = [button('My orders','سفارش‌های من','orders')]
                if account.state == 'active':
                    order_buttons.insert(0, button('Renew plan','تمدید پلن','plans'))
                rows += [order_buttons,[home_button()]]
        elif action=='help':
            body=tr('Choose a plan, create an order and follow its payment instructions. Submit a receipt photo or transaction reference. The administrator verifies payment before activation. Never send passwords or wallet seeds.','پلن را انتخاب و سفارش ثبت کنید. طبق راهنمای سفارش پرداخت کنید و عکس رسید یا کد پیگیری را بفرستید. مدیر پیش از فعال‌سازی پرداخت را بررسی می‌کند. رمز عبور یا عبارت بازیابی کیف پول ارسال نکنید.')
            support=s.setting('bot_support_fa','') if lang=='fa' else s.setting('bot_support','')
            if support:body+='\n\n'+support
            rows=[[home_button()]]
        elif action=='stale':
            body=tr('This menu has expired. Open the latest menu below. Your orders are preserved.','این منو منقضی شده است. از منوی جدید استفاده کنید. سفارش‌های شما محفوظ هستند.');rows=[[home_button()]]
        else:
            pending=s.setting('bot_receipt:'+tid,{})


            if not pending and msg.get('photo'):
                awaiting=s.buyer_orders(tid).filter_by(state='pending').limit(2).all()
                if len(awaiting)==1:
                    pending={'order':awaiting[0].id}
            if command=='/receipt' and len(parts)==3:
                pending={'order':parts[1]};text=parts[2]
            if not pending or not pending.get('order'):
                raise ValueError(tr('Open My orders → Submit receipt, then send a photo or transaction reference.','از سفارش‌های من ← ارسال رسید وارد شوید، سپس عکس یا کد پیگیری را ارسال کنید.'))
            order=own(pending['order'])
            if order.state!='pending':raise ValueError(tr('This order has already been reviewed.','این سفارش قبلاً بررسی شده است.'))
            if order.payment_ref:order_screen(order)
            elif msg.get('photo'):
                photo=msg['photo'][-1]
                if int(photo.get('file_size',0))>5*1024*1024:raise ValueError(tr('The photo is too large. Send one under 5 MB.','حجم عکس زیاد است. عکس کمتر از ۵ مگابایت ارسال کنید.'))
                file_id=str(photo.get('file_id',''));unique=str(photo.get('file_unique_id',''))
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,256}',unique) or not re.fullmatch(r'[A-Za-z0-9_-]{1,512}',file_id):raise ValueError(tr('Invalid photo. Send it again as a Telegram photo.','عکس معتبر نیست. دوباره به‌صورت عکس تلگرام بفرستید.'))
                s.receipt(tid,order.id,'photo:'+s.digest(unique))
                s.put('receipt_photo:'+str(order.id),{'file_id':file_id,'unique':unique,'caption':str(msg.get('caption',''))[:500]})
                s.put('bot_receipt:'+tid,{});order_screen(order)
            elif msg.get('document') or msg.get('sticker') or not text or (command.startswith('/') and command != '/receipt'):
                raise ValueError(tr('Please send a receipt photo or text transaction reference. Stickers and document attachments are not accepted.','لطفاً عکس رسید یا کد پیگیری متنی ارسال کنید. استیکر و فایل ضمیمه پذیرفته نمی‌شود.'))
            elif text.lower() in ('paid','done','payment sent','واریز شد','پرداخت شد'):
                raise ValueError(tr('Please send the receipt photo or transaction reference; “paid” alone cannot be reviewed.','لطفاً عکس رسید یا کد پیگیری ارسال کنید؛ پیام «واریز شد» کافی نیست.'))
            else:s.receipt(tid,order.id,text);s.put('bot_receipt:'+tid,{});order_screen(order)
    except (ValueError,TypeError,KeyError) as exc:
        formatted = False
        body=str(exc) if isinstance(exc,ValueError) else tr('The request is invalid. Please return to your orders.','درخواست معتبر نیست. به سفارش‌های خود بازگردید.')
        if isinstance(exc, ValueError) and body.startswith('You already have a pending order for another plan.'):
            body=tr('You have an open order for another plan. Open My orders to resume or cancel an unpaid order. For a receipt under review, contact support.',
                    'شما برای طرح دیگری سفارش باز دارید. از «سفارش‌های من» وارد شوید و سفارش پرداخت‌نشده را ادامه دهید یا لغو کنید. اگر رسید در حال بررسی است، با پشتیبانی تماس بگیرید.')
        if lang == 'fa' and isinstance(exc, ValueError) and body.isascii():
            errors = {
                'Daily purchase limit reached.':'امروز به سقف تعداد سفارش رسیده‌اید. فردا دوباره تلاش کنید.',
                'This account is suspended. Contact your administrator.':'دسترسی حساب متوقف شده است. با مدیر پنل تماس بگیرید.',
                'Pending order not found.':'سفارش بازی برای این رسید پیدا نشد.',
                'A receipt is already under review for this order.':'رسید این سفارش قبلاً ثبت شده و در حال بررسی است.',
                'This reference has already been submitted.':'این کد پیگیری قبلاً برای سفارش دیگری ثبت شده است.',
                'Plan is unavailable.':'این پلن در دسترس نیست. پلن دیگری انتخاب کنید.',
                'Send a receipt photo or a single-line transaction reference of up to 160 characters.':'عکس رسید یا کد پیگیری را در یک خط و حداکثر در ۱۶۰ نویسه بفرستید.',
            }
            body = errors.get(body,'این درخواست انجام نشد. وضعیت سفارش را در «سفارش‌های من» بررسی کنید.')
        rows=[[button('My orders','سفارش‌های من','orders'),home_button()]]
    s.put('bot_nav:'+tid,{'nonce':nonce,'until':(s.now()+timedelta(minutes=30)).isoformat()})
    if not formatted:
        titles={'plans':('◇ Plans','◇ پلن‌ها'),'orders':('≡ My orders','≡ سفارش‌های من'),'account':('◷ My account','◷ حساب من'),'link':('⌁ Workspace','⌁ پنل نمایندگی'),'help':('? Help','؟ راهنما'),'identity':('⌖ My Telegram ID','⌖ شناسه تلگرام من'),'receipt':('▣ Payment receipt','▣ رسید پرداخت')}
        title=tr(*titles.get(action,('◇ Plan shop','◇ فروشگاه پلن')))
        body='<b>'+escape(title)+'</b>\n\n'+escape(body[:3500])
        formatted=True
    payload={'text':rtl_lines(body) if lang=='fa' else body,'reply_markup':{'inline_keyboard':rows},'edit_id':edit_id}
    if account:
        payload['workspace_owner'] = account.id

    if formatted:
        payload['parse_mode'] = 'HTML'
    if not s.setting('bot_inline_ready:'+tid,False):
        s.notify(None,'keyboard:'+uid,'RPBOT1:'+json.dumps({'text':tr('Menu updated. Use the buttons below.','منو به‌روزرسانی شد. از دکمه‌های زیر استفاده کنید.'),'reply_markup':{'remove_keyboard':True}}),tid)
        s.put('bot_inline_ready:'+tid,True)
    s.notify(None,'update:'+uid,'RPBOT1:'+json.dumps(payload,ensure_ascii=False),tid)
    return (int(tid),lang) if saved_language in ('en','fa') else None
