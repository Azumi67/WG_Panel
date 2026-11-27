from panel_core.telegram_notices import card, telegram_body

import os
import re
import secrets
from datetime import timedelta,timezone
from flask import request,g,abort,render_template,redirect,url_for,flash,session
from models import db,InterfaceConfig
from .models import Account,ManagementBot,Ownership
from . import service as s,management as m
from . import bot_customers as customers, bot_profiles
from .bot_customers import deadline
from .limits import reserve_request
from .regional import display
from .telegram_text import isolated, number, persian_time, rtl_lines
from .telegram_policy import FEATURES,EVENTS,effective,preferences,can_notify,save_access
from sqlalchemy.exc import OperationalError
from .database import SettingsWriterBusy, settings_transaction, writer_busy


def reserved_ids(host,exclude_sales=False):
    tokens=[os.getenv('TG_BOT_TOKEN',''),os.getenv('TELEGRAM_BOT_TOKEN','')]
    tokens.append(host.get('_load_tg_settings',lambda:{})().get('bot_token',''))
    if not exclude_sales and s.setting('bot_token'):tokens.append(s.decrypt(s.setting('bot_token')))
    return {t.split(':',1)[0] for t in tokens if t}


def check_unique(bot_id,aid,host,exclude_sales=False):
    environment_ids={t.split(':',1)[0] for t in (os.getenv('TG_BOT_TOKEN',''),os.getenv('TELEGRAM_BOT_TOKEN','')) if t}
    if bot_id in environment_ids:raise ValueError('Use a separate bot: this token is still configured for the admin bot in TG_BOT_TOKEN or TELEGRAM_BOT_TOKEN. Removing it in the panel does not clear those server settings. Remove the old token there and restart the panel and admin bot service before reusing it.')
    if bot_id in reserved_ids(host,exclude_sales):raise ValueError('Use a separate bot from the administrator and sales bots. Disconnect the token from its current bot settings before reusing it.')
    if ManagementBot.query.filter(ManagementBot.bot_id==bot_id,ManagementBot.account_id!=aid).first():
        raise ValueError('This bot is already connected to another workspace.')


def allowed(a,b):
    return bool(a and b and b.approved and b.enabled and b.token_enc and a.telegram_id and a.state=='active' and a.spec.get('panel_access'))


def notification_recipient(a):
    return a.telegram_id


def connection_status(a,b):
    from .health import heartbeat
    poll=heartbeat(b.polled_at.isoformat() if b and b.polled_at else None)
    status={'state':'missing','label':'Not connected','detail':'Save a dedicated bot token to manage your customers.'}
    if not b or not b.approved:status.update(label='Not approved',detail='Your administrator must enable management bot access.')
    elif not b.token_enc:pass
    elif not b.enabled:status.update(label='Paused',detail='Enable the bot to receive customer-management commands.')
    elif not a.telegram_id:status.update(label='Account not linked',detail='Ask your administrator to set your Telegram user ID.')
    elif a.state!='active':status.update(label='Account inactive',detail='Your administrator must activate this reseller account.')
    elif b.error:status.update(state='stale',label='Connection needs attention',detail=b.error)
    elif poll['state']=='ready':status.update(state='ready',label='Receiving commands',detail='Open a private chat with this bot and send /start from your linked Telegram account.')
    else:
        from .health import service_status
        worker=service_status('worker')
        status.update(state='stale',label='Waiting for worker' if worker['state']!='ready' else 'Waiting for bot polling',detail='Ask your administrator to check wg-reseller-worker.service. It receives customer-management commands for this bot.')
    return {**status,'last_poll':poll.get('at')}

def bot_events(aid):
    from .models import Audit
    from sqlalchemy import or_
    return Audit.query.filter(Audit.actor=='reseller:'+str(aid)).filter(or_(Audit.action.startswith('management_bot_',autoescape=True),Audit.action.startswith('telegram_',autoescape=True),Audit.action.startswith('bot_',autoescape=True)))

def render_settings(aid,error=None):
    b=db.session.get(ManagementBot,aid)
    from .health import heartbeat
    from .models import Audit
    grants=effective(g.reseller)
    logs=bot_events(aid).order_by(Audit.id.desc()).limit(8).all() if 'logs' in grants else []
    return render_template('reseller/management_bot.html',form_error=error,notification_recipient=notification_recipient(g.reseller),telegram_grants=grants,telegram_preferences=preferences(g.reseller),telegram_events=EVENTS,telegram_features=FEATURES,events=logs,bot_health=heartbeat(b.polled_at.isoformat() if b.polled_at else None),connection=connection_status(g.reseller,b),bot=b,account=g.reseller,reseller_mode=True,section='bot',HAS_NODES=False,HAS_SETTINGS=False)

def register(bp,admin,member,host_get):
    @bp.post('/resellers/accounts/<int:aid>/management-bot')
    @admin
    def management_bot_approval(aid):
        with settings_transaction(wait_seconds=10):
            a=db.session.get(Account,aid)
            if not a or a.state=='deleted':abort(404)
            b=db.session.get(ManagementBot,aid)
            if not b:b=ManagementBot(account_id=aid);db.session.add(b)
            from .renewal import remember_telegram
            remember_telegram(a, b, request.form)
            save_access(a,request.form)
            b.approved=request.form.get('approved')=='on';b.pending=None;b.revision=(b.revision or 0)+1
            if not b.approved:b.enabled=False
            s.audit('admin','management_bot_approval',f'Account {aid}: {b.approved}')
        flash('Management bot permission updated.','success')
        return redirect(url_for('reseller.admin_page'))

    @bp.get('/r/api/management-bot/status')
    @member()
    def management_bot_status():
        b=db.session.get(ManagementBot,g.reseller.id)
        if not b or not b.approved:abort(403)
        return connection_status(g.reseller,b),200,{'Cache-Control':'no-store'}

    @bp.route('/r/management-bot',methods=['GET','POST'])
    @member()
    def management_bot_settings():
        aid=g.reseller.id;b=db.session.get(ManagementBot,aid)
        if not b or not b.approved:abort(403)
        def saved(message,view='connection'):
            if request.accept_mimetypes.best=='application/json':
                current=db.session.get(ManagementBot,aid)
                return dict(ok=True,message=message,enabled=current.enabled,has_token=bool(current.token_enc),
                    username=current.username, polled_at=current.polled_at.isoformat()+'Z' if current.polled_at else None, notifications_enabled=preferences(db.session.get(Account,aid))['enabled'] and 'notifications' in effective(db.session.get(Account,aid)),recipient=notification_recipient(db.session.get(Account,aid)),connection=connection_status(db.session.get(Account,aid),current))
            flash(message,'success')
            return redirect(url_for('reseller.management_bot_settings',view=view),code=303)
        if request.method=='POST' and request.form.get('action','') not in ('','connect','disconnect','delivery','bot_enabled','test','notifications'):
            raise ValueError('This action is no longer available. Reload your Telegram settings.')
        if request.method=='POST' and request.form.get('action') in ('delivery','bot_enabled'):
            action=request.form['action']
            with settings_transaction():
                a=db.session.get(Account,aid);b=db.session.get(ManagementBot,aid)
                if not a or not b or not b.approved or a.state!='active' or not a.spec.get('panel_access') or a.session_version!=session.get('rp_version'):abort(403)
                enabled=request.form.get('enabled')=='on'
                if action=='delivery':
                    if 'notifications' not in effective(a):abort(403)
                    s.put('telegram_preferences:'+str(aid),{**preferences(a),'enabled':enabled})
                else:
                    if enabled and (not b.token_enc or not a.telegram_id):raise ValueError('Save a verified bot token and link your Telegram account before enabling the bot.')
                    b.enabled=enabled;b.pending=None
                b.revision+=1
                s.put('bot_reply:'+str(aid),{})
                s.audit('reseller:'+str(aid),'telegram_'+action,'Enabled' if enabled else 'Disabled')
            return saved('Telegram delivery saved.' if action=='delivery' else 'Bot status saved.')
        if request.method=='POST' and request.form.get('action')=='test':
            if not allowed(g.reseller,b) or 'notifications' not in effective(g.reseller):abort(403)
            from .request_guard import reserve
            if not reserve([('telegram-test:'+str(aid),3,60)]):abort(429)
            db.session.rollback();a=db.session.get(Account,aid);b=db.session.get(ManagementBot,aid)
            if not allowed(a,b) or a.session_version!=session.get('rp_version') or 'notifications' not in effective(a):abort(403)
            from .worker import telegram
            try:telegram(s.decrypt(b.token_enc),'sendMessage',{'chat_id':notification_recipient(a),**telegram_body(card('آزمایش تلگرام' if b.language=='fa' else 'Telegram test', [('حساب' if b.language=='fa' else 'Account', a.username)], 'اتصال برقرار است.' if b.language=='fa' else 'Delivery to your linked account is working.'))})
            except RuntimeError:raise ValueError('Test delivery failed. Check the bot connection and start a private chat with your bot.') from None
            with settings_transaction():s.audit('reseller:'+str(aid),'telegram_test','Test sent to the linked account')
            return saved('Test message sent.','connection')
        if request.method=='POST' and request.form.get('action')=='notifications':
            with settings_transaction():
                a=db.session.get(Account,aid);b=db.session.get(ManagementBot,aid)
                if not b or not b.approved or a.state!='active' or not a.spec.get('panel_access') or a.session_version!=session.get('rp_version') or 'notifications' not in effective(a):abort(403)
                s.put('telegram_preferences:'+str(aid),{k:request.form.get(k)=='on' for k in ('enabled',*EVENTS)})
                b.revision+=1
                s.put('bot_reply:'+str(aid),{})
                s.audit('reseller:'+str(aid),'telegram_notifications','Notification preferences updated')
            return saved('Notification preferences saved.','notifications')
        if request.method=='POST':
            revision=b.revision;token=request.form.get('token','').strip();info=None
            disconnect=request.form.get('action')=='disconnect'
            if token and not disconnect:
                if not re.fullmatch(r'\d{5,20}:[A-Za-z0-9_-]{20,100}',token):raise ValueError('Invalid bot token format.')
                from .request_guard import reserve
                if not reserve([('management-verify:'+str(aid),5,60)]):raise ValueError('Too many token checks. Wait one minute before trying again.')
                check_unique(token.split(':',1)[0],aid,host_get())
                from .worker import telegram
                db.session.rollback()
                try:
                    info=telegram(token,'getMe',{})
                    hook=telegram(token,'getWebhookInfo',{})
                except RuntimeError:raise ValueError('Telegram did not complete verification. Check the token and this server’s access to api.telegram.org, then retry. No connection settings were changed.') from None
                if not info.get('is_bot') or str(info.get('id'))!=token.split(':',1)[0]:raise ValueError('Bot identity could not be verified.')
                if hook.get('url'):raise ValueError('This bot has a webhook. Disconnect its previous application before connecting it here.')
            with settings_transaction():
                b=db.session.get(ManagementBot,aid);a=db.session.get(Account,aid)
                if not b or not b.approved or b.revision!=revision or a.state!='active' or not a.spec.get('panel_access') or a.session_version!=session.get('rp_version'):abort(409)
                if disconnect:
                    b.polled_at=None
                    b.bot_id=None;b.token_enc=None;b.username=None;b.enabled=False;b.offset=0
                else:
                    first_connection=bool(info and not b.token_enc and request.form.get('action')=='connect')
                    if info:
                        check_unique(str(info['id']),aid,host_get())
                        if b.bot_id!=str(info['id']):
                            b.offset=0
                            b.polled_at=None
                        b.bot_id=str(info['id']);b.token_enc=s.encrypt(token);b.username=info.get('username','')
                    b.enabled=first_connection or request.form.get('enabled')=='on'
                    if b.enabled and (not b.token_enc or not a.telegram_id):raise ValueError('A verified token and administrator-linked numeric Telegram user ID are required.')
                    b.language='fa' if request.form.get('language')=='fa' else 'en'
                b.pending=None;b.error=None;b.revision+=1
                s.put('bot_reply:'+str(aid),{})
                s.audit('reseller:'+str(aid),'management_bot_settings','Disconnected' if disconnect else 'Connection settings updated')
            return saved('Bot disconnected.' if disconnect else 'Bot settings saved.','connection')
        return render_settings(aid)


def reply(text,buttons=None):
    return {'text':text[:4000],'reply_markup':{'inline_keyboard':buttons or []},'link_preview_options':{'is_disabled':True}}


def request_input(a,b,update):
    cb=update.get('callback_query') or {}
    msg=cb.get('message') or update.get('message') or {}
    sender=cb.get('from') or msg.get('from') or {}
    chat=msg.get('chat') or {}
    if not allowed(a,b) or chat.get('type')!='private' or not all(str(value)==str(a.telegram_id) for value in (sender.get('id'),chat.get('id'))):
        return None
    raw=str(cb.get('data') or msg.get('text') or '').strip()
    pending=b.pending or {}
    maximum=4096 if not cb and pending.get('mode')=='bulk' and pending.get('step') in ('phone_number','telegram_id') else 512
    if len(raw)>maximum:return None
    received=msg.get('date')
    if not cb and received is not None:
        if not isinstance(received,(int,float)) or s.now().replace(tzinfo=timezone.utc).timestamp()-received>300:return None
    if raw.startswith('/'):raw=re.sub(r'^(/\w+)@\w+(?=\s|$)',r'\1',raw)
    parts=raw.split()
    cmd=parts[0].lstrip('/') if parts else 'start'
    return cb,raw,parts,cmd


def reserve_input(account,bot,parsed):
    _,_,parts,cmd=parsed
    pending=bot.pending or {}
    write=cmd in ('confirm','confirm-backup') and len(parts)==2 and parts[1]==pending.get('nonce') and bool(pending.get('operation'))
    preference=(cmd=='set-alert' and len(parts)==3) or (cmd in ('lang','language') and len(parts)==2)
    save_profile=not parsed[0] and not parsed[1].startswith('/') and (pending.get('kind')=='profile-rename' or pending.get('step')=='profile-name')
    return reserve_request(account.id,write or preference or save_profile or cmd in ('profile-default','profile-remove'))


def handle(a,b,update,host,*,defer_files=False,budget=None):
    result = _handle(a,b,update,host,defer_files,budget)
    if result and b.language == 'fa' and 'text' in result and not result['text'].startswith('https://'):
        result['text'] = rtl_lines(result['text'])
        for row in result.get('reply_markup',{}).get('inline_keyboard',[]):
            for button in row:
                button['text'] = '‏' + button['text']
    return result


def _handle(a,b,update,host,defer_files,budget):
    parsed=request_input(a,b,update)
    if parsed is None:return None
    cb,raw,parts,cmd=parsed
    tr=lambda en,fa:fa if b.language=='fa' else en
    if not (reserve_input(a,b,parsed) if budget is None else budget):
        return reply(tr('Too many requests. Try again in one minute.','درخواست‌ها زیاد است. یک دقیقه دیگر تلاش کنید.'))
    if cmd=='language' and len(parts)==2 and parts[1] in ('en','fa'):
        cmd='lang'
    if cmd=='lang' and len(parts)==2 and parts[1] in ('en','fa'):
        b.language=parts[1]
        cmd='menu'
        tr=lambda en,fa:fa if b.language=='fa' else en
    if cmd=='language':
        return reply(tr('◎ Language\nChoose your preferred language.','◎ زبان\nزبان موردنظر خود را انتخاب کنید.'),[[{'text':('✓ ' if b.language=='en' else '')+'English','callback_data':'lang en'},{'text':('✓ ' if b.language=='fa' else '')+'فارسی','callback_data':'lang fa'}],[{'text':tr('Back','بازگشت'),'callback_data':'menu'}]])
    if a.expires_at <= s.now():
        b.pending = None
        from .plan_reminders import awaiting_review
        fields = [(tr('Account','حساب'), a.username), (tr('Status','وضعیت'),tr('Plan expired','پلن منقضی شده'))]
        order = awaiting_review(a)
        if order:
            fields.append((tr('Order','سفارش')+' '+str(order.id),tr('Receipt under review','رسید در انتظار بررسی')))
        buttons = [(tr('⌁ Open workspace','⌁ ورود به پنل'), s.workspace_link(a))]
        shop = s.setting('bot_username') if s.setting('bot_enabled') else ''
        if isinstance(shop, str) and re.fullmatch(r'[A-Za-z0-9_]{5,32}', shop):
            buttons.append((tr('Plan shop','فروشگاه پلن'), 'https://t.me/'+shop))
        result = telegram_body(card(tr('Reseller dashboard','پنل نمایندگی'), fields,
                   tr('Renew your plan to resume customer access.','برای فعال شدن دسترسی مشتریان، پلن خود را تمدید کنید.') if not order else '',
                   symbol='◷', buttons=buttons))
        keyboard = result.setdefault('reply_markup', {'inline_keyboard':[]})['inline_keyboard']
        keyboard.append([{'text':tr('↻ Refresh','↻ تازه‌سازی'), 'callback_data':'menu'},{'text':tr('◎ Language','◎ زبان'),'callback_data':'language'}])
        return result
    grants=effective(a)
    if cmd=='operation' and len(parts)==2 and (cb or raw.startswith('/')):
        from .provision_queue import bot_status
        return bot_status(a,b,parts[1])
    def require(section,perm=None):
        if section not in ('peers','subscriptions') or section not in grants or perm and perm not in grants:raise ValueError('permission')
    def menu(include_workspace=True):
        rows = []
        directories = []
        for section, label, fa in (
            ('peers', '◇ Peers', '◇ کاربران'),
            ('subscriptions', '⌘ Subscriptions', '⌘ اشتراک‌ها'),
        ):
            if section in grants:
                directories.append({'text': tr(label, fa), 'callback_data': section+' 0'})
        tools = []
        for grant, label, fa, command in (
            ('usage', '◷ Plan usage', '◷ مصرف پلن', 'usage'),
            ('logs', '≡ Activity', '≡ گزارش فعالیت', 'logs 0'),
            ('notifications', '◌ Notifications', '◌ اعلان‌ها', 'alerts'),
            ('profiles', '☆ Profiles', '☆ الگوها', 'profiles'),
            ('backup', '▣ Backup', '▣ پشتیبان', 'backup'),
        ):
            if grant in grants and (grant!='profiles' or {'peers','subscriptions'} & grants):
                tools.append({'text': tr(label, fa), 'callback_data': command})
        for group in [directories]+[tools[i:i+2] for i in range(0,len(tools),2)]:
            if group:
                rows.append(group)
        workspace = s.workspace_link(a)
        if workspace and include_workspace:
            rows.insert(0,[{'text': tr('⌁ Open workspace', '⌁ ورود به پنل'), 'url': workspace}])
        if not s.active(a) and 'usage' in grants:
            shop = s.setting('bot_username') if s.setting('bot_enabled') else ''
            if isinstance(shop, str) and re.fullmatch(r'[A-Za-z0-9_]{5,32}', shop):
                rows.append([{'text': tr('◇ Plan shop', '◇ فروشگاه پلن'), 'url': 'https://t.me/'+shop}])
        rows.append([{'text': tr('◎ Language', '◎ زبان'), 'callback_data': 'language'}, {'text': tr('? Help', '؟ راهنما'), 'callback_data': 'help'}])
        rows.append([{'text': tr('↻ Refresh', '↻ تازه‌سازی'), 'callback_data': 'menu'}])
        draft = b.pending or {}
        if draft.get('kind')=='create' and ('edit' if draft.get('edit_id') else 'create') in grants and draft.get('section') in grants:
            rows.insert(1 if workspace and include_workspace else 0,[{'text':tr('Continue customer setup','ادامهٔ تنظیمات مشتری'),'callback_data':'resume-draft'}])
        return rows
    pending = b.pending or {}
    draft_commands = ('resume-draft','cancel','confirm','confirm-backup','step-back','cw')
    if cmd=='confirm' and len(parts)==2 and pending.get('nonce')!=parts[1]:
        previous=s.setting('bot_creation:'+str(a.id),{})
        if (previous.get('nonce')==parts[1] and previous.get('revision')==b.revision
                and previous.get('recipient')==a.telegram_id and previous.get('section') in grants):
            section=previous['section']
            column=Ownership.peer_id if section=='peers' else Ownership.subscription_id
            owned=Ownership.query.filter_by(account_id=a.id,deleted=False).filter(column.in_(previous['ids']))
            if owned.with_entities(column).distinct().count()==len(previous['ids']):
                return created_reply(previous,b.language=='fa')
            return reply(tr('This request was already completed.','این درخواست قبلاً انجام شده است.'),[[customers.button(tr('View customers','مشاهدهٔ فهرست'),section+' 0')]])
    if pending.get('submit_id') is not None and (cmd in draft_commands or (not cb and not raw.startswith('/'))):
        section=(pending.get('operation') or {}).get('section',pending.get('section','peers'))
        uid=pending['submit_id']
        return reply(tr(f'Confirmation {uid} was received. Open the list to see the result.',f'درخواست {number(uid)} دریافت شد. نتیجه را در فهرست ببینید.'),
                     [[customers.button(tr('View customers','مشاهدهٔ فهرست'),section+' 0')]])
    if pending.get('kind')=='create' and cmd=='cancel' and ((len(parts)==2 and parts[1]==pending.get('nonce')) or (not cb and len(parts)==1)):
        b.pending=None
        return reply(tr('Cancelled.','لغو شد.'),menu())
    if pending.get('kind')=='create' and (cmd in draft_commands or (not cb and not raw.startswith('/'))):
        wizard=customers.CustomerWizard(a,b,host,pending)
        return wizard.handle(raw,cb,cmd,parts,menu)
    if cmd in ('confirm','confirm-backup','cancel') and len(parts)==2 and parts[1]!=pending.get('nonce'):
        return reply(tr('Use the buttons in the latest message.','از دکمه‌های آخرین پیام استفاده کنید.'),menu())
    if cmd in ('cw','resume-draft','step-back'):
        return reply(tr('Open the customer menu to start a new setup.','برای شروع دوباره، منوی مشتریان را باز کنید.'),menu())
    profile_result=bot_profiles.handle(a,b,raw,cb,cmd,parts,menu)
    if profile_result is not None:return profile_result
    if cmd in ('create','client') and len(parts)==1:
        parts=['new','peers' if cmd=='create' else 'subscriptions']
        cmd='new'
    if (cmd in ('new','new-bulk') and len(parts)==2) or (cmd=='new-profile' and len(parts)==3):
        section=parts[1]
        require(section,'create')
        s.require_active(a)
        mode='bulk' if cmd=='new-bulk' else 'guided'
        if mode=='bulk' and ('bulk' not in grants or section!='peers'):raise ValueError('permission')
        profile_suffix=''
        if cmd=='new-profile':
            profile=customers.own_profile(a,section,int(parts[2]))
            profile_suffix=' '+str(profile.id)
        b.pending=None
        interfaces=InterfaceConfig.query.filter(InterfaceConfig.id.in_(a.spec['interfaces'])).order_by(InterfaceConfig.name).all()
        rows=[[customers.button(i.name,f'new-interface {section} {i.id} {mode}'+profile_suffix)] for i in interfaces]
        rows.append([customers.button(tr('Back','بازگشت'),section+' 0')])
        return reply(tr('Choose an interface.','رابط موردنظر را انتخاب کنید.') if interfaces else tr('No interfaces are assigned to your account.','هیچ رابطی برای حساب شما تعیین نشده است.'),rows)
    if cmd=='new-interface' and len(parts) in (3,4,5):
        section=parts[1]
        require(section,'create')
        mode=parts[3] if len(parts)>=4 else 'quick'
        if mode not in ('quick','guided','bulk') or (mode=='bulk' and (section!='peers' or 'bulk' not in grants)):
            raise ValueError('permission')
        wizard=customers.CustomerWizard(a,b,host,{'kind':'create','mode':mode,'section':section,'iface':int(parts[2]),'step':'count' if mode=='bulk' else 'name'})
        if len(parts)==5:
            if mode!='guided':raise ValueError('Unexpected profile option')
            return wizard.apply_profile(int(parts[4]))
        wizard.save()
        return wizard.render()
    if cmd in ('start','menu'):
        if pending.get('kind')!='create':b.pending=None
        from html import escape
        from sqlalchemy import func
        from models import Peer
        from .models import Order

        expired = a.expires_at <= s.now()
        exhausted = a.used_bytes >= a.spec['traffic_gib'] * s.GIB
        status = tr('Active', 'فعال')
        if expired:
            status = tr('Plan expired', 'پلن منقضی شده')
        elif exhausted:
            status = tr('Traffic exhausted', 'سهمیه تمام شده')
        lines = [tr('◇ <b>Reseller dashboard</b>', '◇ <b>پنل نمایندگی</b>'),
                 f'<code>{escape(a.username)}</code>  ·  {status}']
        workspace=s.workspace_link(a)
        if workspace:
            label=tr('Open workspace','ورود به پنل')
            lines.append(f'⌁ <a href="{escape(workspace,quote=True)}">{escape(label)}</a>')
        if (expired or exhausted) and 'usage' in grants:
            from .plan_reminders import awaiting_review
            waiting = awaiting_review(a)
            if waiting:
                lines.append(tr(f'Renewal #{waiting.id} · Receipt under review', f'تمدید #{waiting.id} · رسید در حال بررسی'))
            else:
                lines.append(tr('Renew in the plan shop or contact your administrator.', 'از فروشگاه پلن تمدید کنید یا با مدیر تماس بگیرید.'))
        scope = Ownership.query.filter_by(account_id=a.id, deleted=False)
        if {'peers', 'subscriptions'} & grants:
            lines.extend(['', tr('⌘ <b>Customer inventory</b>', '⌘ <b>کاربران من</b>')])
        if 'peers' in grants:
            peers = (db.session.query(Peer.status, Ownership.blocked, func.count(Peer.id))
                     .join(Ownership, Ownership.peer_id == Peer.id)
                     .filter(Ownership.account_id == a.id, Ownership.deleted.is_(False),
                             Ownership.subscription_id.is_(None))
                     .group_by(Peer.status, Ownership.blocked).all())
            total = sum(count for _, _, count in peers)
            enabled = sum(count for state, blocked, count in peers if state == 'online' and not blocked) if s.active(a) else 0
            lines.append(tr(f'Peers  <b>{total} total</b> · {enabled} enabled', f'کاربران: <b>{number(total)}</b>  ·  فعال: {number(enabled)}'))
        if 'subscriptions' in grants:
            total = scope.with_entities(Ownership.subscription_id).filter(Ownership.subscription_id.isnot(None)).distinct().count()
            lines.append(tr(f'Subscriptions  <b>{total}</b>', f'اشتراک‌ها: <b>{number(total)}</b>'))
        if 'usage' in grants:
            limit = int(a.spec['traffic_gib'])
            used = a.used_bytes / s.GIB
            remaining = max(0, limit - used)
            percent = min(100, round(100 * used / max(1, limit)))
            filled = round(percent / 10)
            meter = '▰' * filled + '▱' * (10 - filled)
            lines.extend(['', tr('◷ <b>Account allowance</b>', '◷ <b>مصرف پلن</b>'),
                          tr(f'<code>{meter}</code>  {percent}% used', f'حجم مصرف‌شده: {number(percent)}٪'),
                          tr(f'<b>{remaining:,.2f} GiB</b> left of {limit:,} GiB', f'حجم باقی‌مانده: <b>{number(round(remaining,2))} گیگابایت</b> از {number(limit)} گیگابایت'),
                          tr('Expired on ' if expired else 'Valid until ', 'پایان اعتبار: ') + escape(persian_time(a.expires_at) if b.language=='fa' else display(a.expires_at))])
        result = reply('\n'.join(lines), menu(include_workspace=not bool(workspace)))
        result['parse_mode'] = 'HTML'
        return result
    if cmd in ('alerts','set-alert'):
        if 'notifications' not in grants:raise ValueError('permission')
        options={'enabled':tr('Receive notifications','دریافت اعلان‌ها')}
        if 'usage' in grants:
            options.update(plan_expiry=tr('Plan expiry','پایان اعتبار پلن'),plan_usage=tr('Plan traffic','مصرف پلن'))
        if {'peers','subscriptions'} & grants:
            options.update(customer_expiry=tr('Customer expiry','پایان اعتبار مشتری'),customer_usage=tr('Customer traffic','مصرف مشتری'))
        if 'problems' in grants:options['problems']=tr('Service alerts','هشدارهای سرویس')
        prefs=preferences(a)
        if cmd=='set-alert':
            if len(parts)!=3 or parts[1] not in options or parts[2] not in ('0','1'):raise ValueError('permission')
            value=parts[2]=='1'
            if prefs[parts[1]]!=value:
                prefs[parts[1]]=value
                s.put('telegram_preferences:'+str(a.id),prefs)
                s.audit('reseller:'+str(a.id),'telegram_notifications',parts[1]+'='+parts[2])
        rows=[[customers.button(('✓ ' if prefs[key] else '○ ')+label,f'set-alert {key} {int(not prefs[key])}')] for key,label in options.items()]
        rows.append([customers.button(tr('Main menu','منوی اصلی'),'menu')])
        return reply(tr('Notifications','اعلان‌ها')+'\n\n'+tr('Tap a setting to change it. Messages go to this private chat.','برای تغییر هر گزینه روی آن بزنید. پیام‌ها به همین گفت‌وگوی خصوصی ارسال می‌شوند.'),rows)
    if cmd=='usage':
        if 'usage' not in grants:return reply(tr('Choose an enabled tool.','ابزار مجاز را انتخاب کنید.'),menu())
        pc,sc=s.counts(a)
        return reply(tr(f'{a.username} · Reseller workspace\nTraffic: {a.used_bytes/s.GIB:.2f} / {a.spec["traffic_gib"]} GiB\nPeers: {pc}/{a.spec["peers"]}\nSubscriptions: {sc}/{a.spec["subscriptions"]}\nExpires: {display(a.expires_at)}',f'مصرف پلن {isolated(a.username)}\n\nحجم مصرف‌شده: {number(round(a.used_bytes/s.GIB,2))} از {number(a.spec["traffic_gib"])} گیگابایت\nکاربران: {number(pc)} از {number(a.spec["peers"])}\nاشتراک‌ها: {number(sc)} از {number(a.spec["subscriptions"])}\nپایان اعتبار: {persian_time(a.expires_at)}'),menu())
    if cmd=='backup':
        if 'backup' not in grants or 'backup' not in a.spec.get('permissions',[]):
            raise ValueError('permission')
        nonce=secrets.token_urlsafe(12)
        b.pending={'nonce':nonce,'until':(s.now()+timedelta(minutes=3)).replace(tzinfo=timezone.utc).timestamp(),
                   'operation':{'action':'own_backup'}}
        return reply(tr('Send an encrypted customer recovery backup to this private chat? It includes customer keys and subscription links. Restore it in your workspace Backup page; deleted customers return paused.',
                        'پشتیبان رمزگذاری‌شده کاربران شامل کلیدها و لینک اشتراک به همین گفت‌وگو ارسال شود؟ بازیابی در صفحه پشتیبان فضای کاری انجام می‌شود؛ کاربران حذف‌شده غیرفعال بازیابی می‌شوند.'),
                     [[{'text':tr('Confirm backup','تأیید پشتیبان'),'callback_data':'confirm-backup '+nonce},
                       {'text':tr('Cancel','لغو'),'callback_data':'cancel'}]])
    if cmd=='confirm-backup' and len(parts)==2:
        pending=b.pending or {}
        if pending.get('until',0)<s.now().replace(tzinfo=timezone.utc).timestamp() or pending.get('operation',{}).get('action')!='own_backup':
            return reply(tr('Confirmation expired. Start again.','تأیید منقضی شده است. دوباره شروع کنید.'),menu())
        b.pending=None
        if 'backup' not in effective(a) or 'backup' not in a.spec.get('permissions',[]):raise ValueError('permission')
        from .request_guard import reserve
        if not reserve([('reseller-telegram-backup:'+str(a.id),3,3600)]):
            return reply(tr('Backup rate limit reached. Try later.','محدودیت تعداد پشتیبان؛ بعداً تلاش کنید.'),menu())
        s.audit('reseller:'+str(a.id),'telegram_backup_export','Encrypted customer recovery')
        if defer_files:
            return {'export':'backup'}
        from .own_backup import recovery_document
        filename, document = recovery_document(a)
        return {'document':document,'filename':filename,'mime':'application/zip'}
    if cmd=='logs':
        if 'logs' not in grants:raise ValueError('permission')
        from .models import Audit
        page=max(0,min(100000,int(parts[1]) if len(parts)>1 else 0))
        query=bot_events(a.id)
        total=query.count();page=min(page,max(0,(total-1)//8))
        events=query.order_by(Audit.id.desc()).offset(page*8).limit(8).all()
        text=tr('Your activity','فعالیت‌های شما')+'\n'+('\n'.join((persian_time(e.at) if b.language=='fa' else display(e.at))+' · '+(customers.activity_fa(e.action) if b.language=='fa' else e.action.replace('_',' ').title()) for e in events) or tr('No activity yet.','هنوز فعالیتی ثبت نشده است.'))
        nav=[]
        if page:nav.append({'text':'←','callback_data':f'logs {page-1}'})
        if (page+1)*8<total:nav.append({'text':'→','callback_data':f'logs {page+1}'})
        return reply(text,([nav] if nav else [])+[[{'text':tr('Main menu','منوی اصلی'),'callback_data':'menu'}]])
    search=None
    if cmd=='find' and len(parts)==2:
        section=parts[1]
        require(section)
        if section == 'peers':
            b.pending={'kind':'find','section':'peers','until':deadline()}
            return reply(tr('Find a peer\n\nType a name or #ID to search, or choose Show all peers.',
                            'جست‌وجوی کاربر\n\nنام یا شناسهٔ # را بنویسید، یا همهٔ کاربران را ببینید.'),
                         [[customers.button(tr('Show all peers','نمایش همهٔ کاربران'),'peers-list 0')],
                          [customers.button(tr('Back to peers','بازگشت به کاربران'),'peers 0')]])
        cmd=section
        parts=[section,'0']
    show_peer_list = False
    if cmd=='peers-list' and len(parts)==2 and parts[1].isdecimal():
        require('peers')
        show_peer_list = True
        cmd='peers'
        parts=['peers',parts[1]]
    if pending.get('kind')=='find' and not cb and not raw.startswith('/') and cmd not in draft_commands:
        if customers.expiry(pending) or not 1<=len(raw)<=64:
            return reply(tr('Start a new search and enter up to 64 characters.','جست‌وجوی تازه‌ای شروع کنید و حداکثر ۶۴ نویسه بنویسید.'),menu())
        search=raw
        cmd=pending['section']
        parts=[cmd,'0']
        b.pending={**pending,'query':search}
    elif cmd=='results' and len(parts)==3 and pending.get('kind')=='find' and parts[1]==pending.get('section') and pending.get('query') and not customers.expiry(pending):
        search=pending['query']
        cmd=parts[1]
        parts=[cmd,parts[2]]
    if cmd in ('peers','subscriptions'):
        require(cmd)
        if cmd == 'peers' and not show_peer_list and search is None:
            b.pending = None
            buttons = []
            if 'create' in grants and s.active(a):
                creation = [customers.button(tr('＋ Create peer','＋ ساخت کاربر'),'new peers')]
                if 'bulk' in grants:
                    creation.append(customers.button(tr('Create in bulk','ساخت گروهی'),'new-bulk peers'))
                buttons.append(creation)
            buttons.append([customers.button(tr('⌕ Find a peer','⌕ جست‌وجوی کاربر'),'find peers')])
            buttons.append([customers.button(tr('Main menu','منوی اصلی'),'menu')])
            return reply(tr('Peers\n\nCreate a customer or find an existing peer.',
                            'کاربران\n\nکاربر جدید بسازید یا یکی از کاربران فعلی را جست‌وجو کنید.'),buttons)
        page=max(0,min(100000,int(parts[1]) if len(parts)>1 else 0))
        if search is None:
            b.pending={'kind':'find','section':cmd,'until':deadline()}
        from models import Peer, Subscription, SubscriptionPeer
        from sqlalchemy.orm import aliased
        model = Peer if cmd == 'peers' else Subscription
        resource_id = Ownership.peer_id if cmd == 'peers' else Ownership.subscription_id
        rows = db.session.query(model.id,model.name).join(Ownership,resource_id == model.id).filter(Ownership.account_id == a.id, Ownership.deleted.is_(False))
        if cmd == 'peers':
            rows = rows.filter(Ownership.subscription_id.is_(None))
        else:
            other = aliased(Ownership)
            foreign = db.session.query(other.id).filter(other.subscription_id == Subscription.id, other.deleted.is_(False), other.account_id != a.id).exists()
            owned_link = db.session.query(other.id).filter(other.subscription_id == SubscriptionPeer.subscription_id,
                other.peer_id == SubscriptionPeer.peer_id, other.deleted.is_(False), other.account_id == a.id).correlate(SubscriptionPeer).exists()
            unknown = db.session.query(SubscriptionPeer.id).filter(SubscriptionPeer.subscription_id == Subscription.id, ~owned_link).exists()
            rows = rows.filter(~foreign, ~unknown)
        if search:
            rows=rows.filter(model.id==int(search[1:])) if search.startswith('#') and search[1:].isdecimal() and len(search)<=18 else rows.filter(model.name.icontains(search,autoescape=True))
        entries=rows.distinct().order_by(model.id).offset(page*8).limit(9).all()
        buttons=[]
        if 'create' in grants and s.active(a) and search is None and cmd!='peers':
            create_label=tr('＋ Create peer','＋ ساخت کاربر') if cmd=='peers' else tr('＋ Create subscription','＋ ساخت اشتراک')
            create_row=[customers.button(create_label,'new '+cmd)]
            if cmd=='peers' and 'bulk' in grants:create_row.append(customers.button(tr('Create in bulk','ساخت گروهی'),'new-bulk peers'))
            buttons.append(create_row)
        for rid, name in entries[:8]:
            buttons.append([{'text':tr(f'{name} · #{rid}',f'{isolated(name)} · {number(rid)}')[:60],'callback_data':f'view {cmd} {rid}'}])
        nav=[]
        paging='results '+cmd if search else 'peers-list' if cmd=='peers' else cmd
        if page:nav.append(customers.button('←',f'{paging} {page-1}'))
        if len(entries)>8:nav.append(customers.button('→',f'{paging} {page+1}'))
        if nav:buttons.append(nav)
        buttons.append([{'text':tr('Main menu','منوی اصلی'),'callback_data':'menu'}])
        title=tr('Peers','کاربران') if cmd=='peers' else tr('Subscriptions','اشتراک‌ها')
        if search:buttons.insert(-1,[customers.button(tr('Show all','نمایش همه'),('peers-list' if cmd=='peers' else cmd)+' 0')])
        subtitle=tr('Tap a name to open it, or type a name or #ID to search.','روی نام مشتری بزنید یا نام یا شمارهٔ او را با # بنویسید.') if entries else tr('No matching customers. Try another name or #ID.','مشتری‌ای پیدا نشد. نام یا شناسهٔ دیگری بنویسید.') if search else tr('No customers yet.','هنوز مشتری‌ای ثبت نشده است.')
        return reply(title+'\n\n'+subtitle,buttons)
    if cmd=='view' and len(parts)==3:
        section,rid=parts[1],int(parts[2]);require(section);obj,peers=m.target(a,section,rid);buttons=[]
        result=customers.detail(a,section,obj,peers,host,b.language)
        if not s.active(a):
            result['reply_markup']={'inline_keyboard':[[customers.button(tr('Back','بازگشت'),section+' 0')]]}
            return result
        if 'control_access' in grants:
            buttons.append([{'text':tr('Pause','توقف'),'callback_data':f'disable {section} {rid}'},{'text':tr('Enable','فعال‌سازی'),'callback_data':f'enable {section} {rid}'}])
        if 'edit' in grants:buttons.append([customers.button(tr('Edit settings','ویرایش تنظیمات'),f'edit {section} {rid}')])
        resets=[customers.button(tr(en,fa),f'{action} {section} {rid}') for action,en,fa in
                [('reset_data','Reset traffic','بازنشانی مصرف'),('reset_timer','Reset timer','بازنشانی زمان')] if action in grants]
        if resets:buttons.append(resets)
        if 'download' in grants:
            exports=[customers.button(tr('Configuration','فایل تنظیمات') if section=='peers' else tr('Subscription link','لینک اشتراک'),f'download {section} {rid}')]
            if section=='peers':exports.append(customers.button(tr('QR code','کد QR'),f'qr peers {rid}'))
            buttons.append(exports)
        if section=='subscriptions' and 'rotate_link' in grants:buttons.append([customers.button(tr('Replace link','تعویض لینک'),f'rotate {section} {rid}')])
        if 'delete' in grants:buttons.append([customers.button(tr('Delete','حذف'),f'delete {section} {rid}')])
        buttons.append([{'text':tr('Back','بازگشت'),'callback_data':section+' 0'}])
        result['reply_markup']={'inline_keyboard':buttons}
        return result
    if (cmd=='edit' and len(parts)==3) or (cmd=='edit-field' and len(parts)==4):
        section,rid=parts[1],int(parts[2])
        require(section,'edit')
        s.require_active(a)
        obj,peers=m.target(a,section,rid)
        iface=obj.iface if section=='peers' else next((peer.iface for peer in peers if peer.iface_id in a.spec['interfaces']),None)
        if not iface or iface.id not in a.spec['interfaces']:raise ValueError('No assigned interface')
        fields=customers.authorized_fields(a,iface,section,'guided',host,editing=True)
        if obj.timer_started_at and 'start_on_first_use' in fields:fields.remove('start_on_first_use')
        if cmd=='edit':
            choices=[customers.button(tr(*customers.FIELDS[f]),f'edit-field {section} {rid} {f}') for f in fields]
            rows=[choices[i:i+2] for i in range(0,len(choices),2)]
            rows.append([customers.button(tr('Back','بازگشت'),f'view {section} {rid}')])
            return reply(tr('Choose a setting to edit.','گزینه‌ای را برای ویرایش انتخاب کنید.'),rows)
        if parts[3] not in fields:raise ValueError('permission')
        wizard=customers.CustomerWizard(a,b,host,dict(kind='create',mode='guided',section=section,iface=iface.id,step=parts[3],edit_id=rid,edit_field=parts[3]))
        wizard.save()
        return wizard.render()
    if cmd in ('download','qr') and len(parts)==3:
        section,rid=parts[1],int(parts[2]);require(section,'download');s.require_active(a);obj,_=m.target(a,section,rid)
        if cmd=='qr' and section!='peers':raise ValueError('permission')
        s.audit('reseller:'+str(a.id),'bot_download',f'{section}:{rid}')
        if section=='subscriptions':
            if defer_files:return {'export':'subscription_link','id':rid}
            return reply(s.base_url()+'/s/'+obj.token)
        if defer_files:
            return {'export':'qr' if cmd=='qr' else 'peer','id':rid}
        return customers.export_peer(obj,host,qr=cmd=='qr')
    if cmd=='cancel':b.pending=None;return reply(tr('Cancelled.','لغو شد.'),menu())
    if cmd=='confirm' and len(parts)==2:
        pending = b.pending or {}
        op = pending.get('operation') or {}
        if not op or op.get('action') == 'own_backup' or pending.get('until',0) < s.now().replace(tzinfo=timezone.utc).timestamp():
            return reply(tr('This confirmation has expired. Start again.','مهلت تأیید تمام شد. دوباره شروع کنید.'),menu())
        b.pending = None
        return {'operation':pending['operation']}
    if cmd in ('create','client') and len(parts)>=5:
        section='peers' if cmd=='create' else 'subscriptions';require(section,'create')
        iface=int(parts[1]);gib=int(parts[2]);days=int(parts[3]);name=' '.join(parts[4:])
        if iface not in a.spec['interfaces'] or gib<=0 or days<=0:raise ValueError('invalid')
        opts={'name':name,'data_limit_value':gib,'data_limit_unit':'Gi','time_limit_days':days}
        m.validate_options(a,opts)
        op={'action':'create','section':section,'iface':iface,'options':opts}
        summary=f'{name}\n{gib} GiB · {days} '+tr('days','روز')
    elif cmd in ('enable','disable','delete','reset_data','reset_timer','rotate') and len(parts)==3:
        section,rid=parts[1],int(parts[2])
        require(section,customers.ACTION_GRANTS[cmd])
        if cmd=='rotate' and section!='subscriptions':raise ValueError('permission')
        obj,_=m.target(a,section,rid)
        labels={'enable':('Enable','فعال‌سازی'),'disable':('Pause','توقف'),'delete':('Delete','حذف'),
                'reset_data':('Reset traffic counters','بازنشانی شمارندهٔ مصرف'),'reset_timer':('Reset timer','شروع دوبارهٔ اعتبار'),
                'rotate':('Replace the subscription link','تعویض لینک اشتراک')}
        op={'action':cmd,'section':section,'id':rid}
        summary=tr(*labels[cmd])+' · '+obj.name
        if cmd=='enable':summary+='\n'+tr('Expired time or exhausted customer data renews only when permitted by the administrator. Plan usage is retained.','زمان یا حجم تمام‌شدهٔ مشتری فقط با اجازهٔ مدیر تمدید می‌شود. مصرف پلن حفظ می‌شود.')
        if cmd=='rotate':summary+='\n'+tr('The old link will stop working.','لینک قبلی از دسترس خارج می‌شود.')
    else:
        lines=[tr('Workspace help','راهنمای پنل نمایندگی')]
        if 'peers' in grants:lines.append(tr('Peers — search and manage your customers.','کاربران — مشتریان خود را پیدا و مدیریت کنید.'))
        if 'subscriptions' in grants:lines.append(tr('Subscriptions — find a subscription and its available actions.','اشتراک‌ها — اشتراک و گزینه‌های در دسترس آن را ببینید.'))
        if 'create' in grants and {'peers','subscriptions'} & grants:
            lines.append(tr('Open a customer section and choose Create. Review the details before confirming.','برای ساخت مشتری، بخش کاربران یا اشتراک‌ها را باز کنید. پیش از تأیید، مشخصات را مرور کنید.'))
        if len(lines)==1:lines.append(tr('Choose an enabled tool from the menu.','یکی از ابزارهای فعال منو را انتخاب کنید.'))
        return reply('\n\n'.join(lines),menu())
    s.require_active(a)
    nonce=secrets.token_urlsafe(12);b.pending={'nonce':nonce,'until':(s.now()+timedelta(minutes=5)).replace(tzinfo=timezone.utc).timestamp(),'operation':op}
    return reply(tr('Confirm this change:\n','این تغییر را تأیید کنید:\n')+summary,[[{'text':tr('Confirm','تأیید'),'callback_data':'confirm '+nonce},{'text':tr('Cancel','لغو'),'callback_data':'cancel'}]])


def execute(a,b,op,host,*,update_id=None,usage_sample=None,on_created=None,on_external_start=None,on_external_rollback=None):
    if not allowed(a,b):raise ValueError('Access changed')
    s.require_active(a)
    section,action=op['section'],op['action']
    perm=customers.ACTION_GRANTS.get(action)
    if section not in ('peers','subscriptions') or not {section,perm} <= effective(a):raise ValueError('Permission changed')
    if action=='create':
        customers.checked_operation(a,op,host)
        aid,revision,recipient = a.id,b.revision,a.telegram_id
        def record(current, result):
            bot=db.session.get(ManagementBot,aid,with_for_update=True)
            if not allowed(current,bot) or bot.revision!=revision or current.telegram_id!=recipient:
                raise ValueError('Permission changed')
            customers.checked_operation(current,op,host)
            if update_id is not None:
                s.put('bot_creation:'+str(aid),dict(update=update_id,revision=revision,recipient=recipient,
                      nonce=(bot.pending or {}).get('nonce'),**result))
                if (bot.pending or {}).get('submit_id')==update_id:
                    bot.pending=None
            s.audit('reseller:'+str(aid),'management_bot_action',section+':create')
            if on_created:on_created(current,result)
        return s.provision(a,[op['iface']],op['options']['name'],section=='subscriptions',host,options=op['options'],count=op.get('count',1),on_created=record,usage_sample=usage_sample,on_external_start=on_external_start,on_external_rollback=on_external_rollback)
    elif action=='edit':
        obj,values,fields=customers.edit_values(a,op,host)
        if op['field'] in customers.METADATA_FIELDS:
            db.session.refresh(obj,with_for_update=True)
            value=m.validate_options(a,values)[op['field']]
            setattr(obj,op['field'],value)
            s.audit('reseller:'+str(a.id),'edit',section+':'+str(obj.id))
        else:m.execute_customer_actions(a,section,action,[op['id']],values,host,fields=fields)
    else:m.execute_customer_actions(a,section,action,[op['id']],{},host)
    s.audit('reseller:'+str(a.id),'management_bot_action',section+':'+action)
    return dict(section=section,ids=[op['id']])


def answer_callback(telegram, token, callback_id):
    try:telegram(token,'answerCallbackQuery',{'callback_query_id':callback_id})
    except RuntimeError:pass


def created_reply(result,fa):
    section=result['section']
    ids=result['ids']
    if section=='subscriptions':
        message='اشتراک ساخته شد.' if fa else 'Subscription created.'
        label='مشاهدهٔ اشتراک' if fa else 'View subscription'
    else:
        message=(number(len(ids))+' کاربر ساخته شد.') if fa else ('Peer created.' if len(ids)==1 else f'{len(ids)} peers created.')
        label='مشاهدهٔ کاربر' if fa else 'View peer'
    directory='کاربران' if fa and section=='peers' else 'اشتراک‌ها' if fa else section.title()
    rows=[[customers.button(directory,section+' 0')]]
    if len(ids)==1:
        rows.insert(0,[customers.button(label,f'view {section} {ids[0]}')])
    return reply(message,rows)


def committed_creation(aid, revision, uid, recipient, operation):
    if not operation or operation['action'] != 'create':
        return None
    receipt = s.setting('bot_creation:'+str(aid), {})
    if receipt.get('revision') == revision and receipt.get('update') == uid and receipt.get('recipient') == recipient:
        return receipt
    return None


def restore_confirmation(aid,revision,uid,recipient,draft,reason=None):
    with settings_transaction():
        bot=db.session.get(ManagementBot,aid,with_for_update=True)
        account=db.session.get(Account,aid)
        if (not draft or not allowed(account,bot) or bot.revision!=revision or
                account.telegram_id!=recipient or bot.offset!=uid+1 or (bot.pending and bot.pending.get('submit_id')!=uid)):
            return None
        if (draft.get('operation') or {}).get('action')=='create' and not bot.pending:
            return None
        renewed={**draft,'nonce':secrets.token_urlsafe(10),'until':deadline()}
        renewed.pop('submit_id',None)
        bot.pending=renewed
        fa=bot.language=='fa'
        review=renewed.get('kind')=='create'
        label=('مرور مشخصات' if fa else 'Review details') if review else ('تلاش دوباره' if fa else 'Try again')
        message='مشخصات شما ذخیره شد. برای ادامه دوباره تأیید کنید.' if fa else 'Your details are saved. Review and confirm again when ready.'
        return reply((reason+'\n\n' if reason else '')+message,
            [[customers.button(label,'resume-draft' if review else 'confirm '+renewed['nonce']),
              customers.button('انصراف' if fa else 'Cancel','cancel '+renewed['nonce'])]])


def prepare_export(a,b,result,host):
    if a.expires_at<=s.now():return None
    if result['export']=='backup':
        if 'backup' not in effective(a) or 'backup' not in a.spec.get('permissions',[]):return None
        from .own_backup import recovery_document
        from .backup_service import bot_snapshot, record
        aid=a.id
        try:name,data=bot_snapshot(a,b,recovery_document)
        except PermissionError:return None
        record(aid,'Telegram',name,len(data))
        return {'document':data,'filename':name,'mime':'application/zip'}
    if result['export']=='subscription_link':
        if not {'subscriptions','download'}.issubset(effective(a)) or not s.active(a):return None
        obj,_=m.target(a,'subscriptions',result['id'])
        return reply(s.base_url()+'/s/'+obj.token)
    if result['export'] not in ('qr','peer') or not {'peers','download'}.issubset(effective(a)) or not s.active(a):return None
    obj,_=m.target(a,'peers',result['id'])
    qr_export=result['export']=='qr'
    config_text=host['_client_conf_txt'](obj)
    media=customers.export_peer(obj,host,qr=qr_export,config=config_text)
    short_link=None
    try:
        short_link=customers.peer_short_link(a,obj)
    except Exception as exc:
        from flask import current_app
        current_app.logger.warning('Reseller bot short-link delivery unavailable account=%s error=%s',a.id,type(exc).__name__)
        db.session.rollback()
    from .bot_peer_delivery import caption as peer_caption
    expiry_display=(persian_time(obj.expires_at) if b.language=='fa' else display(obj.expires_at)) if obj.expires_at else None
    media['caption']=peer_caption(obj,config_text,short_link,qr=qr_export,language=b.language,expires_label=expiry_display)
    media['parse_mode']='HTML'
    return media


def cycle(aid,host,*,poll_timeout=0,acknowledge=None,schedule_alerts=None,publish_menu=None):
    from .worker import telegram, show_message, validate_updates
    from .workspace_replies import stage, drain
    b=db.session.get(ManagementBot,aid);a=db.session.get(Account,aid)
    if not allowed(a,b):return
    revision=b.revision;token=s.decrypt(b.token_enc);recipient=a.telegram_id
    if b.bot_id in reserved_ids(host):raise ValueError('Bot identity conflicts with administrator or sales bot')
    db.session.rollback()
    retry=drain(aid,host,telegram,show_message)
    if retry:return float(retry)
    b=db.session.get(ManagementBot,aid);a=db.session.get(Account,aid)
    if not allowed(a,b) or b.revision!=revision or a.telegram_id!=recipient:return
    offset=b.offset
    recovered = bool(b.error)
    update_health=recovered or not b.polled_at or (s.now()-b.polled_at).total_seconds()>=30
    menu_config=None
    if publish_menu:
        from panel_core.telegram_commands import workspace_commands
        expired=a.expires_at<=s.now()
        active=s.active(a)
        stamp=(b.revision,b.language,a.session_version,a.generation,active,expired,bool(b.offset))
        if publish_menu.due(token,recipient,stamp):
            menu_config=(stamp,workspace_commands(effective(a),active,expired),b.language)
    db.session.rollback()
    if menu_config:
        publish_menu.submit(token,recipient,*menu_config,selected=True)
    updates=telegram(token,'getUpdates',{'offset':offset,'timeout':poll_timeout,'limit':10,'allowed_updates':['message','callback_query']})
    updates=validate_updates(updates)
    for update in updates:
        uid=update.get('update_id')
        callback_id=(update.get('callback_query') or {}).get('id')
        if isinstance(uid,int) and uid>=offset and callback_id:
            (acknowledge or answer_callback)(telegram,token,callback_id)
    for update in updates:
        uid=update.get('update_id')
        callback=update.get('callback_query') or {}
        if not isinstance(uid,int) or uid<offset:continue
        b=db.session.get(ManagementBot,aid);a=db.session.get(Account,aid)
        if not allowed(a,b) or b.revision!=revision:return
        if uid<b.offset:continue
        parsed=request_input(a,b,update)
        budget=reserve_input(a,b,parsed) if parsed is not None else False
        result=None
        operation=None
        prepared=None
        try:
            if parsed and parsed[3] in ('start','menu','usage','logs','peers','subscriptions','help') and a.expires_at>s.now():
                pending=b.pending or {}
                if not pending or (pending.get('kind')=='create' and (parsed[0] or parsed[1].startswith('/'))):
                    prepared=(b.pending,a.session_version,a.generation,a.expires_at,s.active(a),effective(a))
                    result=handle(a,b,update,host,defer_files=True,budget=budget)
                    next_pending=b.pending
            db.session.rollback()
            with settings_transaction(label='reseller-bot:update'):
                b=db.session.get(ManagementBot,aid,with_for_update=True);a=db.session.get(Account,aid)
                if not allowed(a,b) or b.revision!=revision:return
                if uid < b.offset:continue
                draft=b.pending
                if prepared is None or prepared!=(b.pending,a.session_version,a.generation,a.expires_at,s.active(a),effective(a)) or a.expires_at<=s.now():
                    result=handle(a,b,update,host,defer_files=True,budget=budget)
                else:
                    b.pending=next_pending
                if result and 'operation' in result:
                    from .provision_queue import enqueue,JobConflict
                    operation=result['operation']
                    fa=b.language=='fa'
                    try:
                        job=enqueue(a,operation,f'tg:{revision}:{uid}',bot=b)
                        if operation['action']=='create':b.pending=None
                        result=reply(('در صف پردازش. نتیجه ارسال خواهد شد. کد: ' if fa else 'Queued for processing. The result will be sent here. Reference: ')+job['id'],[[customers.button('بررسی وضعیت' if fa else 'Check status','operation '+job['id'])]])
                    except JobConflict:
                        b.pending=draft
                        result=reply('درخواست ثبت نشد؛ صف پر است، شناسه درخواست تکراری است یا عملیات نیاز به بررسی مدیر دارد. بخش عملیات را بررسی کنید.' if fa else 'Request not queued: queue capacity, request identifier conflict or administrator review. Check Operations in the workspace.')
                stage(a,b,uid,result,(callback.get('message') or {}).get('message_id'))
                b.offset=uid+1
        except (SettingsWriterBusy, OperationalError):
            db.session.rollback()
            raise
        except Exception as exc:
            from .bot_runtime_log import event as bot_event
            db.session.rollback()
            bot_event('reseller','ERROR','operation_failed',account_id=aid,update_id=uid,error=exc)
            with settings_transaction(label='management:update-error'):
                b=db.session.get(ManagementBot,aid,with_for_update=True);a=db.session.get(Account,aid)
                if not allowed(a,b) or b.revision!=revision or a.telegram_id!=recipient:return
                
                
                if b.offset<=uid:
                    if request_input(a,b,update) is not None:
                        text=(f'درخواست تأیید نشد. وضعیت عملیات را بررسی کنید. کد: {number(uid)}' if b.language=='fa'
                              else f'Request not confirmed. Check Operations or the customer list before repeating it. Reference: {uid}.')
                        stage(a,b,uid,reply(text),None)
                    b.offset=uid+1
        db.session.rollback()
        retry=drain(aid,host,telegram,show_message)
        if retry:return float(retry)
    db.session.rollback();b=db.session.get(ManagementBot,aid);a=db.session.get(Account,aid)
    if not allowed(a,b) or b.revision!=revision:return
    active_chat = bool(updates or (b.pending or {}).get('until',0) > s.now().replace(tzinfo=timezone.utc).timestamp())
    if update_health:
        try:
            with settings_transaction(label='management:poll-health', health_only=True):
                b=db.session.get(ManagementBot,aid);a=db.session.get(Account,aid)
                if not allowed(a,b) or b.revision!=revision:return
                b.polled_at=s.now();b.error=None
        except (SettingsWriterBusy, OperationalError) as exc:
            from .bot_runtime_log import event as bot_event
            db.session.rollback()
            bot_event('reseller','WARNING','poll_health_deferred',account_id=aid,error=exc)
            return active_chat
        if schedule_alerts:
            schedule_alerts(aid,revision,recovered)
        else:
            workspace_alerts(aid,revision,recovered)
    return active_chat


def workspace_alerts(aid,revision,recovered):
    from .plan_reminders import deliver_workspace
    from .worker import telegram
    b=db.session.get(ManagementBot,aid);a=db.session.get(Account,aid)
    if not allowed(a,b) or b.revision!=revision:
        return
    token=s.decrypt(b.token_enc)
    deliver_workspace(a,telegram)
    deliver_problem_alerts(a,b,revision,token,telegram,recovered=recovered)
    deliver_customer_alerts(a,b,revision,token,telegram)


def run(app,host,stop):
    from .worker_supervision import pulse
    from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
    from threading import Lock
    from .worker import TelegramTransportError, workspace_telegram_clients, callback_answers, telegram
    from panel_core.telegram_commands import MenuPublisher
    import time

    capacity=8
    scheduled=set()
    alert_lock=Lock()
    def schedule_alerts(aid,revision,recovered):
        with alert_lock:
            if aid in scheduled:
                return
            scheduled.add(aid)
        def send():
            try:
                with app.app_context():
                    workspace_alerts(aid,revision,recovered)
            except Exception as exc:
                app.logger.warning('Workspace alert delivery deferred for account %s (%s).',aid,type(exc).__name__)
            finally:
                with alert_lock:scheduled.discard(aid)
        alerts.submit(send)

    def job(aid,poll_timeout):
        with app.app_context():
            try:return cycle(aid,host,poll_timeout=poll_timeout,acknowledge=acknowledge,schedule_alerts=schedule_alerts,publish_menu=publisher)
            except (SettingsWriterBusy,OperationalError) as exc:
                from .bot_runtime_log import event as bot_event
                bot_event('reseller','WARNING','poll_database_busy' if writer_busy(exc) else 'poll_database_error',account_id=aid,error=exc)
                db.session.rollback()
                app.logger.warning('Workspace bot database operation deferred for account %s.',aid)
            except Exception as exc:
                from .bot_runtime_log import event as bot_event
                bot_event('reseller','WARNING','poll_failed',account_id=aid,error=exc)
                db.session.rollback()
                detail = str(exc) if isinstance(exc, TelegramTransportError) else 'Bot unavailable. Check the token, webhook, account permissions and server connectivity.'
                try:
                    current=db.session.get(ManagementBot,aid)
                    if current and current.enabled and current.error!=detail:
                        app.logger.warning('Workspace bot for account %s: %s',aid,detail)
                        with settings_transaction():
                            current=db.session.get(ManagementBot,aid,with_for_update=True)
                            if current and current.enabled:current.error=detail
                except (SettingsWriterBusy,OperationalError):db.session.rollback()
                if isinstance(exc, TelegramTransportError) and getattr(exc,'retry_after',0):
                    return float(exc.retry_after)
            finally:db.session.remove()

    futures={};started={};due={};backoff={};ids=[];next_list=0
    from .bot_runtime_log import record as bot_record
    bot_record(app.instance_path, 'reseller','INFO','poller_started')
    with (workspace_telegram_clients() as connect,
          callback_answers(connect,'workspace-buttons') as acknowledge,
          MenuPublisher(telegram) as publisher,
          ThreadPoolExecutor(max_workers=3,thread_name_prefix='workspace-alerts',initializer=connect) as alerts,
          ThreadPoolExecutor(max_workers=capacity,thread_name_prefix='reseller-management',initializer=connect) as pool):
        while not stop.is_set():
            now=time.monotonic()
            for aid,f in list(futures.items()):
                if not f.done():continue
                del futures[aid]
                started.pop(aid,None)
                try:active=f.result()
                except Exception as exc:
                    app.logger.warning('Workspace bot for account %s could not finish (%s).',aid,type(exc).__name__)
                    active=None
                if isinstance(active,float):
                    backoff.pop(aid,None)
                    due[aid]=now+max(.1,active)
                elif active is None:
                    backoff[aid]=min(30,2*backoff.get(aid,1))
                    due[aid]=now+backoff[aid]
                else:
                    backoff.pop(aid,None)
                    due[aid]=now+(.02 if active else .12)
            if now>=next_list:
                with app.app_context():
                    try:
                        ids=[aid for aid, in db.session.query(ManagementBot.account_id).join(Account,Account.id==ManagementBot.account_id)
                             .filter(ManagementBot.approved.is_(True),ManagementBot.enabled.is_(True),Account.state=='active',Account.telegram_id.isnot(None))]
                        due={aid:at for aid,at in due.items() if aid in ids}
                        backoff={aid:delay for aid,delay in backoff.items() if aid in ids}
                        if all(now-at < 180 for at in started.values()):pulse()
                    except Exception:app.logger.warning('Workspace bot list refresh deferred.')
                    finally:db.session.remove()
                next_list=now+3
            for aid in sorted(ids,key=lambda aid:(due.get(aid,0),aid)):
                if len(futures)>=capacity:break
                if aid not in futures and due.get(aid,0)<=now:
                    futures[aid]=pool.submit(job,aid,6 if len(ids)<=capacity else 1)
                    started[aid]=now
            delay=min(.25,max(.01,next_list-now))
            if len(futures)<capacity:
                delay=min([delay]+[max(.01,due[aid]-now) for aid in ids if aid not in futures and aid in due])
            if futures:wait(tuple(futures.values()),timeout=delay,return_when=FIRST_COMPLETED)
            else:stop.wait(delay)


def deliver_customer_alerts(a,b,revision,token,telegram):
    if a.expires_at <= s.now():return
    from .models import Ownership
    from .telegram_policy import preferences
    prefs=preferences(a)
    if not prefs['enabled'] or not (prefs['customer_expiry'] or prefs['customer_usage']):return
    aid=a.id;cursor_key='telegram_alert_cursor:'+str(aid);cursor=int(s.setting(cursor_key,0))
    rows=Ownership.query.filter_by(account_id=aid,deleted=False).filter(Ownership.id>cursor).order_by(Ownership.id).limit(40).all()
    if not rows:
        if cursor:
            with settings_transaction():s.put(cursor_key,0)
        return
    sent=0;last=cursor
    for ownership in rows:
        last=ownership.id
        section='subscriptions' if ownership.subscription_id else 'peers'
        rid=ownership.subscription_id or ownership.peer_id
        prefix='subscription' if ownership.subscription_id else 'peer'
        if not any(can_notify(a,prefix+'_'+event) for event in ('expiry','usage')):continue
        try:resource,_=m.target(a,section,rid)
        except (ValueError,TypeError):continue
        events=[];expiry=resource.expires_at;limit=resource.limit_bytes();used=m.usage(resource)
        if expiry and expiry!=a.expires_at and expiry<=s.now()+timedelta(days=3) and can_notify(a,prefix+'_expiry'):
            events.append(('expiry','expired' if expiry<=s.now() else 'soon',display(expiry)))
        if limit and used>=limit*.8 and can_notify(a,prefix+'_usage'):
            events.append(('usage','100' if used>=limit else '90' if used>=limit*.9 else '80',f'{used/s.GIB:.2f} / {limit/s.GIB:.2f} GiB'))
        for event,level,detail in events:
            if sent>=4:break
            key=f'tg_alert:{aid}:{section}:{rid}:{event}'
            marker=f'{a.generation}:{expiry}:{limit}:{level}'
            if s.setting(key)==marker:continue

            db.session.rollback();a=db.session.get(Account,aid);b=db.session.get(ManagementBot,aid)
            if not allowed(a,b) or b.revision!=revision:return
            if not can_notify(a,prefix+'_'+event):continue
            try:resource,_=m.target(a,section,rid)
            except (ValueError,TypeError):continue
            if a.expires_at <= s.now():return
            fa = b.language == 'fa'
            kind = ('اشتراک' if fa else 'Subscription') if section=='subscriptions' else ('کاربر' if fa else 'Peer')
            label = ('پایان اعتبار' if fa else 'Expires') if event=='expiry' else ('ترافیک' if fa else 'Traffic')
            title = (('اعتبار مشتری پایان یافته' if fa else 'Customer expired') if level=='expired' else ('نزدیک به پایان اعتبار مشتری' if fa else 'Customer expires soon')) if event=='expiry' else ('مصرف ترافیک مشتری' if fa else 'Customer traffic')
            if fa:
                detail=persian_time(expiry) if event=='expiry' else f'{number(round(used/s.GIB,2))} از {number(round(limit/s.GIB,2))} گیگابایت'
            entry = card(title, [(kind,resource.name),(label,detail)],symbol='◷')
            payload={'chat_id':notification_recipient(a),**telegram_body(entry)}
            db.session.rollback()
            telegram(token,'sendMessage',payload)
            with settings_transaction():
                current=db.session.get(ManagementBot,aid)
                if current and current.revision==revision:
                    s.put(key,marker);s.audit('reseller:'+str(aid),'telegram_alert',f'{section}:{rid} {event}')
            sent+=1
        if sent>=4:break
    with settings_transaction():s.put(cursor_key,last)


def deliver_problem_alerts(a,b,revision,token,telegram,recovered=None):
    from .models import Ownership
    if not can_notify(a,'problems'):return
    aid=a.id
    grants=effective(a)
    query=Ownership.query.filter_by(account_id=aid,deleted=False,blocked=True)
    from sqlalchemy import or_
    scopes=[]
    if 'peers' in grants:scopes.append(Ownership.subscription_id.is_(None))
    if 'subscriptions' in grants:scopes.append(Ownership.subscription_id.isnot(None))
    count=query.filter(or_(*scopes)).count() if scopes else 0
    key='telegram_problems:'+str(aid)
    previous=s.setting(key,{}) or {}
    old=int(previous.get('blocked',0))
    if recovered is None:recovered=bool(b.error)
    scope_key=','.join(sorted(grants & {'peers','subscriptions'}))
    if previous.get('scope',scope_key)!=scope_key:old=count
    if not scopes:count=old
    messages=[]
    fa = b.language == 'fa'
    if count and count!=old:messages.append(f'{count} موقعیت مشتری به دلیل محدودیت پلن متوقف شده است.' if fa else f'{count} of your customer locations are blocked by plan enforcement. Check your plan expiry and traffic allowance in the workspace.')
    elif old and not count:messages.append('محدودیت پلن برای مشتریان برداشته شد. وضعیت آن‌ها را در پنل بررسی کنید.' if fa else 'Your customer locations are no longer blocked by plan enforcement. Review customer status in the workspace.')
    if recovered:messages.append('اتصال تلگرام دوباره برقرار شد.' if fa else 'Telegram connection restored after an interruption. Check the workspace activity log before retrying any unconfirmed action.')
    db.session.rollback();a=db.session.get(Account,aid);b=db.session.get(ManagementBot,aid)
    if not allowed(a,b) or b.revision!=revision or not can_notify(a,'problems'):return
    if messages:
        payload = {'chat_id':notification_recipient(a),**telegram_body(card('وضعیت پنل نمایندگی' if fa else 'Workspace status', [('حساب' if fa else 'Account',a.username)], '\n'.join(messages)))}
        db.session.rollback()
        telegram(token,'sendMessage',payload)
    state = {'blocked':count,'scope':scope_key}
    if state == previous and not recovered and not messages:
        return
    with settings_transaction():
        current=db.session.get(ManagementBot,aid)
        if current and current.revision==revision:
            s.put(key,state)
            if recovered:current.error=None
            if messages:s.audit('reseller:'+str(aid),'telegram_problem_alert','Own customer access or Telegram recovery alert')
