import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'static/openapi/bot-apps.json'
BASE = '/api/bot-apps'
S = {'type':'string'}
I = {'type':'integer'}
B = {'type':'boolean'}
N = {'type':'number'}


def obj(properties, required=(), **extra):
    return {'type':'object','properties':properties,**({'required':list(required)} if required else {}),**extra}


def arr(schema):
    return {'type':'array','items':schema}


def ref(name):
    return {'$ref':'#/components/schemas/'+name}


def param(name, schema=S, location='query', required=False, description=''):
    return {'name':name,'in':location,'required':required or location=='path','schema':schema,'description':description}


KIND={'type':'string','enum':['peers','subscriptions']}
AFTER=param('after',{'type':'integer','minimum':0,'default':0},description='Return IDs greater than this cursor. Up to 50 records.')
RID=param('rid',I,'path')
OID=param('oid',I,'path')
KP=param('kind',KIND,'path')
KEY=param('Idempotency-Key',{'type':'string','pattern':'^[A-Za-z0-9_-]{1,80}$'},'header',True,'Keep the same value for an uncertain request. Scoped to account and application ID.')
ERROR=ref('Error')
ORDER=ref('Order')
OP=ref('Operation')
OPT=obj({'name':{'type':'string','maxLength':48},'data_limit_value':I,'data_limit_unit':{'type':'string','enum':['Mi','Gi']},'time_limit_days':N,'time_limit_hours':{'type':'integer','minimum':0,'maximum':23},'time_limit_minutes':{'type':'integer','minimum':0,'maximum':59},'start_on_first_use':B,'phone_number':S,'telegram_id':S,'note':S,'allowed_ips':S,'dns':S,'mtu':I,'persistent_keepalive':I,'endpoint':S,'peer_endpoint':S,'address':S,'start_index':I},['name'],additionalProperties=False)
SCHEMAS={
    'Error':obj({'error':S},['error']),
    'Customer':obj({'id':I,'name':S,'enabled':B},['id','name','enabled']),
    'CustomerDetail':obj({'id':I,'name':S,'enabled':B,'data_limit_value':N,'data_limit_unit':S,'time_limit_days':N,'start_on_first_use':B,'expires_at':{'type':'string','nullable':True},'phone_number':{'type':'string','nullable':True},'telegram_id':{'type':'string','nullable':True},'note':{'type':'string','nullable':True},**{k:{'nullable':True,**(I if k in ('mtu','persistent_keepalive') else S)} for k in ('allowed_ips','dns','mtu','persistent_keepalive','endpoint','peer_endpoint')}},['id','name','enabled']),
    'Operation':obj({'id':S,'section':KIND,'action':S,'channel':S,'state':{'type':'string','enum':['queued','running','completed','rejected','review','resolved']},'created_at':S,'started_at':{'type':'string','nullable':True},'finished_at':{'type':'string','nullable':True},'stage':{'type':'string','nullable':True},'message':{'type':'string','nullable':True},'result':{'type':'object','nullable':True,'additionalProperties':True},'status_url':S},['id','section','action','state','status_url']),
    'Order':obj({'id':I,'plan':S,'price':{},'currency':S,'status':S,'created_at':S},['id','plan','price','currency','status','created_at']),
    'Options':OPT,
    'EditOptions':obj({k:v for k,v in OPT['properties'].items() if k not in ('address','start_index')},['name','data_limit_value','data_limit_unit','time_limit_days','start_on_first_use'],additionalProperties=False),
}


def build():
    paths={}
    def add(path,method,handler,summary,scope,response,params=(),body=None,accepted=False,media='application/json',description='',form=False):
        response_content=({kind:{'schema':response} for kind in media} if isinstance(media,tuple) else {media:{'schema':response}})
        responses={str(202 if accepted else 200):{'description':'Accepted into durable queue' if accepted else 'Successful response','content':response_content}}
        for status,text in ((400,'Invalid request'),(401,'Invalid or revoked credential'),(403,'Permission or policy denied'),(404,'Resource not found'),(429,'Request budget exceeded'),(503,'Database or service unavailable')):
            responses[str(status)]={'description':text,'content':{'application/json':{'schema':ERROR}}}
        if method=='post':
            for status,text in ((409,'Conflict or unavailable feature'),(411,'Content-Length required'),(413,'Request too large')):
                responses[str(status)]={'description':text,'content':{'application/json':{'schema':ERROR}}}
        responses['429']['headers']={'Retry-After':{'schema':I,'description':'Seconds before retry'}}
        role=path.split('/')[1]
        operation={'operationId':handler+'_'+method+'_'+role,'tags':[role],'summary':summary,'description':description,'security':[{'ApplicationKey':[]}], 'x-required-permissions':scope,'responses':responses}
        if params:operation['parameters']=list(params)
        if body is not None:
            operation['requestBody']={'required':True,'content':{'application/json':{'schema':body}}}
            if form:operation['requestBody']['content']['application/x-www-form-urlencoded']={'schema':body}
        paths.setdefault(BASE+path,{})[method]=operation
        return operation
    items=lambda item:obj({'items':arr(item)},['items'])
    operation=obj({'operation':OP},['operation'])
    queued=obj({'ok':B,'operation':OP},['ok','operation'])
    add('/admin/reviews','get','admin_reviews','Read review queue',['reviews'],obj({'items':arr({'allOf':[ORDER,obj({'review_url':S})]}),'timezone':S},['items','timezone']),[AFTER])
    add('/admin/reviews/{oid}/{action}','post','admin_decision','Approve or reject payment',['payment_decisions'],ORDER,[OID,param('action',{'type':'string','enum':['approve','reject']},'path')],obj({'verified':B,'note':S,'verification_method':S,'verification_reference':S}),description='Approve requires verified=true after independent payment verification. Legacy key needs payment review enabled.')
    add('/shop/plans','get','shop_plans','List published offers',['plans'],items(obj({'id':I,'name':S,'terms':S,'price':{},'currency':S,'days':I,'traffic_gib':N,'peers':I,'subscriptions':I,'payment_instructions':S})),[AFTER])
    add('/shop/orders','get','shop_orders','List buyer orders',['orders_read'],items(ORDER),[param('buyer_id',S,required=True),AFTER])
    add('/shop/orders','post','shop_orders','Create buyer order',['orders_create'],ORDER,body=obj({'buyer_id':S,'plan_id':I,'terms':S,'language':{'type':'string','enum':['en','fa']}},['buyer_id','plan_id','terms']),form=True,description='Use current offer terms. Not a provisioning idempotency endpoint.')
    receipt=add('/shop/orders/{oid}/receipt','post','shop_receipt','Submit receipt',['receipts'],ORDER,[OID],obj({'buyer_id':S,'reference':S},['buyer_id','reference']),form=True,description='Submit one nonempty reference or a photo, not both.')
    receipt['requestBody']['content']['multipart/form-data']={'schema':obj({'buyer_id':S,'photo':{'type':'string','format':'binary'}},['buyer_id','photo'])}
    add('/workspace/status','get','workspace_status','Workspace status',['usage'],obj({'account_id':I,'username':S,'expires_at':S,'used_bytes':I,'traffic_gib':N,'peers':I,'peer_limit':I,'subscriptions':I,'subscription_limit':I,'permissions':arr(S)},['account_id','username','permissions']))
    add('/workspace/interfaces','get','workspace_interfaces','Assigned interfaces',['peers OR subscriptions'],items(obj({'id':I,'name':S,'remote':B},['id','name','remote'])))
    add('/workspace/customers','get','workspace_customers','List owned customers',['kind'],obj({'account_id':I,'items':arr(ref('Customer'))},['account_id','items']),[param('kind',{**KIND,'default':'peers'}),AFTER])
    add('/workspace/customers/{kind}/{rid}','get','workspace_customer','Read customer details',['kind'],ref('CustomerDetail'),[KP,RID],description='Contact and network settings require additional edit/account permissions.')
    add('/workspace/customers/{kind}','post','workspace_create','Create customers',['kind','create','bulk when count > 1'],queued,[KP,KEY],obj({'interfaces':{'type':'array','items':I,'minItems':1,'maxItems':100,'uniqueItems':True},'count':{'type':'integer','minimum':1,'maximum':50,'default':1},'options':ref('Options')},['interfaces','options']),accepted=True,description='Peers use one interface; subscriptions require count=1. Manual address and custom network settings require additional account permissions.')
    add('/workspace/customers/{kind}/{rid}/actions','post','workspace_action','Change owned customer',['kind','action-specific scope'],queued,[KP,RID,KEY],{'oneOf':[obj({'action':{'type':'string','enum':['edit']},'options':ref('EditOptions')},['action','options']),obj({'action':{'type':'string','enum':['enable','disable','delete','reset_data','reset_timer','rotate']},'options':{'type':'object','maxProperties':0}},['action'])]},accepted=True,description='edit→edit (complete settings required); enable/disable→control_access; delete→delete; reset_data→reset_data; reset_timer→reset_timer; rotate→rotate_link (subscriptions only). Options only for edit.')
    add('/workspace/customers/{kind}/{rid}/access','post','customer_access','Set customer enabled state',['kind','control_access'],queued,[KP,RID,KEY],obj({'enabled':B},['enabled']),accepted=True)
    add('/workspace/customers/peers/{rid}/{format}','get','workspace_peer_export','Download configuration or QR',['peers','download'],{'type':'string','format':'binary'},[RID,param('format',{'type':'string','enum':['config','qr']},'path')],media=('text/plain','image/png'),description='Sensitive private configuration; never log it.')
    add('/workspace/customers/subscriptions/{rid}/link','get','workspace_subscription_link','Retrieve subscription link',['subscriptions','download'],obj({'url':S},['url']),[RID])
    add('/workspace/operations/{jid}','get','workspace_operation','Get operation result',['operation customer kind'],operation,[param('jid',{'type':'string','pattern':'^[a-f0-9]{32}$'},'path')],description='Only operations submitted by this application identity. Rotated named keys retain lookup access; revoked keys cannot authenticate.')
    add('/workspace/operations/by-request/{key}','get','workspace_operation_by_request','Recover request',['operation customer kind'],operation,[param('key',{'type':'string','pattern':'^[A-Za-z0-9_-]{1,80}$'},'path')],description='Use the original request reference after an uncertain submission.')
    for role,extra,required in [('admin',{'recipient_id':S},['recipient_id']),('shop',{'buyer_id':S,'order_id':I},['buyer_id','order_id']),('workspace',{},[])]:
        op=add('/'+role+'/messages','post','send_message','Send Telegram message',['notifications' if role=='workspace' else 'messages'],obj({'ok':B},['ok']),body=obj({'text':{'type':'string','minLength':1,'maxLength':2000},**extra},['text',*required]),form=True,description='Requires configured built-in bot and eligible recipient. Delivery can be uncertain; check before retrying.')
        op['responses']['502']={'description':'Telegram delivery not confirmed','content':{'application/json':{'schema':ERROR}}}
    return {'openapi':'3.0.3','info':{'title':'WG Panel Application API','version':'2.0','description':'Contract for external administrator, shop and reseller applications. Native admin/session and node APIs remain documented separately. HTTPS only. Named and legacy keys have distinct operation namespaces. Existing account limits remain authoritative.'},'servers':[{'url':'/'}],'paths':paths,'components':{'securitySchemes':{'ApplicationKey':{'type':'http','scheme':'bearer','description':'Use the issued application key, not a BotFather token.'}},'schemas':SCHEMAS}}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    data=json.dumps(build(),indent=2,ensure_ascii=False)+'\n'
    if args.check:
        if not DEST.exists() or DEST.read_text()!=data:raise SystemExit('Application OpenAPI file is outdated.')
    else:
        DEST.parent.mkdir(parents=True,exist_ok=True);DEST.write_text(data)
