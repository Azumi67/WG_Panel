(() => {
'use strict';
const label = iface => {
    const names = (Array.isArray(iface?.reseller_assignments) ? iface.reseller_assignments : []).map(owner => String(owner.username || '')).filter(Boolean);
    return names.length ? `Reseller · ${names.join(', ')}` : '';
};
function confirmAssignments(interfaces) {
    if (document.documentElement.hasAttribute('data-reseller-workspace')) return true;
    const assigned = [...new Set(interfaces.filter(Boolean).map(iface => label(iface) ? `${iface.node_name ? iface.node_name + ' / ' : ''}${iface.name || iface.iface || 'Interface'} — ${label(iface)}` : '').filter(Boolean))];
    return !assigned.length || window.confirm(`Reseller-assigned interface:\n${assigned.join('\n')}\n\nYou are provisioning from the administrator panel. Continue?`);
}
window.WGResellerAssignment = {label, confirm: confirmAssignments};
const host=document.querySelector('[data-reseller-visibility]');
if(!host||host.dataset.mounted)return;
host.dataset.mounted='true';
const title=document.createElement('label');title.textContent='Customer ownership';title.htmlFor='reseller-visibility-mode';
const select=document.createElement('select');select.id=title.htmlFor;select.className='input reseller-visibility-select';select.disabled=true;
for(const [value,text] of [['admin','Admin only'],['resellers','Resellers only'],['all','All customers']]){const opt=document.createElement('option');opt.value=value;opt.textContent=text;select.append(opt);}
const status=document.createElement('span');status.className='reseller-visibility-status';status.setAttribute('role','status');status.textContent='Loading…';
host.replaceChildren(title,select,status);
async function request(options={}){const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);try{const res=await fetch('/resellers/resource-visibility',{credentials:'same-origin',cache:'no-store',...options,signal:controller.signal});const data=await res.json();if(!res.ok||!['admin','resellers','all'].includes(data.mode))throw Error();return data;}finally{clearTimeout(timer);}}
async function load(){select.disabled=true;try{select.value=(await request()).mode;status.textContent='Peers & subscriptions';select.disabled=false;}catch(_){status.textContent='Unavailable · Reload to retry';}}
select.onchange=async()=>{select.disabled=true;status.textContent='Saving…';try{const data=await request({method:'POST',headers:{...window.csrfHeaders?.(true),'Content-Type':'application/json','X-CSRFToken':document.querySelector('meta[name="csrf-token"]')?.content||''},body:JSON.stringify({mode:select.value})});select.value=data.mode;status.textContent='Saved';if(host.hasAttribute('data-resource-reload')){location.reload();return;}select.disabled=false;}catch(_){await load();status.textContent='Save not confirmed · '+status.textContent;}};
load();
})();
