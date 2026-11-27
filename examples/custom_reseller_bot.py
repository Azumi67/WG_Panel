import asyncio
import os
import shlex
import hashlib
from urllib.parse import urlsplit

import requests
from telegram.ext import Application, CommandHandler

PANEL = os.environ['PANEL'].rstrip('/')
KEY = os.environ['WORKSPACE_APP_KEY']
OWNER = int(os.environ['BOT_OWNER_ID'])
origin = urlsplit(PANEL)
if origin.scheme != 'https' or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment or origin.path:
    raise ValueError('PANEL must be an HTTPS origin without credentials or a path')


def api(method, path, *, body=None, request_id=None):
    headers = {'Authorization': 'Bearer ' + KEY}
    if request_id:
        headers['Idempotency-Key'] = request_id
    response = requests.request(method, PANEL + '/api/bot-apps/workspace' + path,
                                headers=headers, json=body, timeout=(5, 20), allow_redirects=False)
    if response.status_code >= 300:
        raise RuntimeError('Panel returned HTTP ' + str(response.status_code) + ('; retry reads later' if response.status_code==429 else ''))
    return response.json()


def authorized(update):
    return (update.effective_user and update.effective_user.id == OWNER
            and update.effective_chat and update.effective_chat.type == 'private')


async def start(update, context):
    if not authorized(update):
        return
    await update.message.reply_text('/status · /interfaces · /peers [after ID] · /subscriptions [after ID]\n/create <interface ID> <GiB> <days> "name"\n/enable <peer ID> · /disable <peer ID>\n/operation <request ID>')


async def read(update, context):
    if not authorized(update):
        return
    command = update.message.text.split()[0].split('@')[0]
    paths = {'/status': '/status', '/interfaces': '/interfaces', '/peers': '/customers?kind=peers', '/subscriptions': '/customers?kind=subscriptions'}
    try:
        path = paths[command]
        if command in ('/peers','/subscriptions'):
            after = int(context.args[0]) if context.args else 0
            if after < 0: raise ValueError('Invalid cursor')
            path += '&after=' + str(after)
        result = await asyncio.to_thread(api, 'GET', path)
        if 'items' in result:
            lines = [f"{item['id']} · {item['name']}" for item in result['items']]
            text = '\n'.join(lines) or 'No results'
            if command in ('/peers','/subscriptions') and len(lines)==50:
                text += '\nNext: '+command+' '+str(result['items'][-1]['id'])
        else:
            text = f"Peers: {result['peers']}/{result['peer_limit']}\nSubscriptions: {result['subscriptions']}/{result['subscription_limit']}\nExpires: {result['expires_at']}"
        await update.message.reply_text(text[:3900])
    except Exception:
        await update.message.reply_text('Unable to read workspace. Check permissions and connectivity.')


async def create(update, context):
    if not authorized(update):
        return
    try:
        _, interface_id, gib, days, name = shlex.split(update.message.text)
        body = {'interfaces': [int(interface_id)], 'options': {'name': name, 'data_limit_value': int(gib),
                'data_limit_unit': 'Gi', 'time_limit_days': int(days)}}
    except (ValueError, IndexError):
        await update.message.reply_text('Usage: /create 1 5 7 "customer name"')
        return
    request_id = request_reference(update, context)
    await update.message.reply_text('Request reference: ' + request_id + '\nCheck /operation ' + request_id + ' before repeating.')
    try:
        result = await asyncio.to_thread(api, 'POST', '/customers/peers', body=body, request_id=request_id)
        await update.message.reply_text('Operation: ' + result['operation']['state'] + '\n/operation ' + request_id)
    except Exception:
        await update.message.reply_text('Submission not confirmed. Check /operation ' + request_id + ' before submitting another request.')


def request_reference(update, context):
    
    return hashlib.sha256(f'{context.bot.id}:{update.update_id}'.encode()).hexdigest()[:32]


async def access(update, context):
    if not authorized(update):
        return
    command = update.message.text.split()[0].split('@')[0]
    try:
        rid = int(context.args[0])
        if len(context.args)!=1 or rid<=0: raise ValueError('Invalid peer ID')
    except (ValueError, IndexError):
        await update.message.reply_text('Usage: '+command+' <peer ID>')
        return
    key = request_reference(update, context)
    await update.message.reply_text('Request reference: '+key+'\nCheck /operation '+key+' before repeating.')
    try:
        result=await asyncio.to_thread(api,'POST',f'/customers/peers/{rid}/access',body={'enabled':command=='/enable'},request_id=key)
        await update.message.reply_text('Operation: '+result['operation']['state']+'\n/operation '+key)
    except Exception:
        await update.message.reply_text('Submission not confirmed. Check /operation '+key+' before repeating.')


async def operation(update, context):
    if not authorized(update):
        return
    args = context.args
    if len(args) != 1 or len(args[0]) != 32 or any(c not in '0123456789abcdef' for c in args[0]):
        await update.message.reply_text('Provide the request reference from /create.')
        return
    try:
        result = await asyncio.to_thread(api, 'GET', '/operations/by-request/' + args[0])
        job = result['operation']
        await update.message.reply_text(job['state'] + ' · ' + (job.get('message') or ''))
    except Exception:
        await update.message.reply_text('Status unavailable. Do not repeat an uncertain creation.')


if __name__ == '__main__':
    app = Application.builder().token(os.environ['CUSTOM_BOT_TOKEN']).build()
    app.add_handler(CommandHandler('start', start))
    app.add_handler(CommandHandler(['status', 'interfaces', 'peers', 'subscriptions'], read))
    app.add_handler(CommandHandler('create', create))
    app.add_handler(CommandHandler(['enable','disable'], access))
    app.add_handler(CommandHandler('operation', operation))
    app.run_polling()
