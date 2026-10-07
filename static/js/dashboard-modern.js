(() => {
  'use strict';
  const root = document.getElementById('nx-dashboard');
  if (!root) return;
  const $ = id => document.getElementById(id);
  const put = (id, value) => { const el = $(id); if (el) el.textContent = String(value ?? '—'); };
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const number = value => value !== null && value !== '' && Number.isFinite(Number(value)) ? Number(value) : null;
  const bytes = value => { if (number(value) === null) return '—'; let n = Math.max(0, Number(value)), i=0; const u=['B','KiB','MiB','GiB','TiB']; while(n>=1024&&i<u.length-1){n/=1024;i++;} return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
  const age = value => { const n=number(value); if(n===null||n<=0) return 'Never'; const seconds=Math.max(0,Math.floor(Date.now()/1000-n));return seconds<60?`${seconds}s ago`:seconds<3600?`${Math.floor(seconds/60)}m ago`:seconds<86400?`${Math.floor(seconds/3600)}h ago`:`${Math.floor(seconds/86400)}d ago`; };
  const clock = value => new Intl.DateTimeFormat('en', {hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:window.WG_PANEL_TIMEZONE||'UTC'}).format(new Date(value));
  const samples=[]; const sparks={}; let chart, windowSeconds=300, fastTimer, slowTimer, fastBusy=false, slowBusy=false, nodes=[], lastPeers=null;
  async function request(path) {
    const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),15000);
    try { const response=await fetch(path,{credentials:'same-origin',cache:'no-store',signal:controller.signal,headers:{Accept:'application/json'}}); if(!response.ok)throw new Error(`HTTP ${response.status}`); const data=await response.json();if(data.error||data.ok===false)throw new Error('Unavailable');return data; } finally {clearTimeout(timer);}
  }
  function initCharts(){
    if(!window.Chart){put('nx-chart-empty','Chart library unavailable. Live values are still shown above.');return;}
    chart=new Chart($('nx-traffic-chart'),{type:'line',data:{labels:[],datasets:[{label:'Download',data:[],borderColor:'#9985ff',backgroundColor:'rgba(140,117,255,.20)',fill:true},{label:'Upload',data:[],borderColor:'#568eff',backgroundColor:'rgba(86,142,255,.11)',fill:true}]},options:{responsive:true,maintainAspectRatio:false,animation:false,interaction:{mode:'index',intersect:false},elements:{line:{tension:.32,borderWidth:2.3},point:{radius:0,hitRadius:12}},plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>`${c.dataset.label}: ${Number(c.parsed.y).toFixed(2)} Mbps`}}},scales:{x:{ticks:{maxTicksLimit:6,maxRotation:0},grid:{display:false}},y:{beginAtZero:true,ticks:{maxTicksLimit:5,callback:v=>`${v} Mbps`}}}}});
    ['peer','sub','transfer','response'].forEach((key,i)=>{sparks[key]=new Chart($(`nx-${key}-spark`),{type:'line',data:{labels:[],datasets:[{data:[],borderColor:['#568eff','#9985ff','#569bff','#568eff'][i],backgroundColor:['#568eff18','#9985ff18','#569bff18','#568eff18'][i],fill:true,borderWidth:2,tension:.35,pointRadius:0}]},options:{responsive:true,maintainAspectRatio:false,animation:false,events:[],plugins:{legend:{display:false},tooltip:{enabled:false}},scales:{x:{display:false},y:{display:false}}}});});
    themeCharts();
  }
  function themeCharts(){const dark=document.documentElement.dataset.theme==='dark'; if(!chart)return;for(const axis of Object.values(chart.options.scales)){axis.ticks.color=dark?'#9da4b8':'#697187';axis.grid.color=dark?'#ffffff0a':'#1d254210';axis.border={display:false};}chart.update('none');}
  function spark(key,value){const c=sparks[key];if(!c||number(value)===null)return; c.data.labels.push('');c.data.datasets[0].data.push(value);if(c.data.labels.length>30){c.data.labels.shift();c.data.datasets[0].data.shift();}c.update('none');}
  function drawTraffic(){if(!chart)return;const recent=samples.filter(s=>s.at>=Date.now()-windowSeconds*1000);chart.data.labels=recent.map(s=>clock(s.at));chart.data.datasets[0].data=recent.map(s=>s.rx);chart.data.datasets[1].data=recent.map(s=>s.tx);chart.update('none');$('nx-chart-empty').hidden=recent.length>1;}
  function resource(key,value){const n=number(value);put(`nx-${key}`,n===null?'—':`${n.toFixed(0)}%`);const p=$(`nx-${key}-bar`);if(n===null)p.removeAttribute('value');else p.value=Math.max(0,Math.min(100,n));}
  async function refreshStats(){
    if(fastBusy||document.hidden)return;fastBusy=true;const started=performance.now();
    try{const s=await request('/api/stats');const elapsed=Math.round(performance.now()-started);put('nx-response',`${elapsed} ms`);spark('response',elapsed);
      const rx=number(s.net?.rx_rate_mb??s.rx),tx=number(s.net?.tx_rate_mb??s.tx);
      const rxMbps=rx===null?null:rx*1048576*8/1000000,txMbps=tx===null?null:tx*1048576*8/1000000;
      put('nx-rx',rxMbps===null?'—':`${rxMbps.toFixed(1)} Mbps`);put('nx-tx',txMbps===null?'—':`${txMbps.toFixed(1)} Mbps`);
      const rxt=number(s.net?.rx_total_mb),txt=number(s.net?.tx_total_mb);const total=rxt===null||txt===null?null:(rxt+txt)*1048576;put('nx-transfer',bytes(total));spark('transfer',total);
      samples.push({at:Date.now(),rx:rxMbps,tx:txMbps});while(samples.length&&samples[0].at<Date.now()-900000)samples.shift();drawTraffic();put('nx-chart-note','Live samples · collected while this page is open');
      resource('cpu',s.cpu);resource('mem',s.mem?.percent);resource('disk',s.disk?.percent);
      put('nx-host',s.hostname);put('nx-platform',s.platform);put('nx-ipv4',s.ipv4||'Not available');put('nx-ipv6',s.ipv6||'Not available');const up=number(s.uptime);put('nx-uptime',up===null?'—':`${Math.floor(up/86400)}d ${Math.floor(up%86400/3600)}h ${Math.floor(up%3600/60)}m`);
      put('nx-updated',`Updated ${clock(Date.now())} · ${window.WG_PANEL_TIMEZONE||'UTC'}`);$('nx-updated').classList.remove('is-error');
    }catch(_){put('nx-updated','Live metrics unavailable · retrying');$('nx-updated').classList.add('is-error');put('nx-response','—');put('nx-rx','—');put('nx-tx','—');put('nx-chart-note','Refresh failed · chart shows earlier samples');}
    finally{fastBusy=false;clearTimeout(fastTimer);if(!document.hidden)fastTimer=setTimeout(refreshStats,5000);}
  }
  function peerRows(peers, sample=true){
    lastPeers=peers;
    const connected=peers.filter(p=>p.conn_status==='online'||p.connection_status==='connected');put('nx-connected',connected.length);put('nx-peer-caption',`${peers.length} peers in inventory`);if(sample)spark('peer',connected.length);
    const rows=[...peers].sort((a,b)=>(number(b.latest_handshake)||0)-(number(a.latest_handshake)||0)).slice(0,5);
    $('nx-recent-peers').innerHTML=rows.length?rows.map(p=>{const nodeMatch=String(p.iface||'').match(/^n(\d+):/);const node=nodeMatch?nodes.find(n=>String(n.id)===nodeMatch[1]):null;const name=node?.name||(nodeMatch?'Remote node':'Local server');const online=p.conn_status==='online'||p.connection_status==='connected';const blocked=p.status==='blocked';return `<tr><td><div class="nx-peer-identity"><span class="nx-peer-icon"><i class="fas fa-laptop"></i></span><span><b>${esc(p.name||'Unnamed peer')}</b><small>${esc(p.address||'—')}</small></span></div></td><td><b>${esc(name)}</b><small>${esc(p.iface||'—')}</small></td><td><span class="nx-rx">${esc(bytes(number(p.rx)===null?null:Number(p.rx)*1048576))} ↓</span><small class="nx-tx">${esc(bytes(number(p.tx)===null?null:Number(p.tx)*1048576))} ↑</small></td><td><span class="nx-status-pill ${blocked?'warning':online?'online':'offline'}">${blocked?'Blocked':online?'Online':'Offline'}</span></td><td>${esc(age(p.latest_handshake))}</td></tr>`;}).join(''):'<tr><td colspan="5" class="nx-empty">No peers yet. Create your first peer to get started.</td></tr>';
    put('nx-peer-summary',`${connected.length} online · ${peers.length-connected.length} offline or blocked`);
  }
  function subscriptions(rows){const active=rows.filter(s=>s.enabled!==false&&s.access?.allowed!==false);const soon=active.filter(s=>!s.unlimited&&number(s.ttl_seconds)!==null&&Number(s.ttl_seconds)>0&&Number(s.ttl_seconds)<=604800);const blocked=rows.length-active.length;
    put('nx-subscriptions',active.length);spark('sub',active.length);put('nx-sub-caption',`${rows.length} total access policies`);put('nx-attention-count',soon.length+blocked);
    put('nx-attention-title',soon.length?`${soon.length} subscription${soon.length===1?'':'s'} expire soon`:blocked?`${blocked} blocked or disabled polic${blocked===1?'y':'ies'}`:'No subscription alerts');
    put('nx-attention-copy',soon.length?`Expiring within 7 days.${blocked?` ${blocked} other policies are blocked or disabled.`:''}`:blocked?'Review expired, exhausted or manually disabled access.':'No active subscriptions expire within the next 7 days.');$('nx-attention').classList.toggle('is-clear',!soon.length&&!blocked);
  }
  function health(data){const counts=data.counts||{};const total=['healthy','review','attention','unknown'].reduce((n,k)=>n+(number(counts[k])||0),0);const good=number(counts.healthy)||0;const percent=total?Math.round(good/total*100):null;put('nx-health-percent',percent===null?'—':`${percent}%`);put('nx-health-label',{healthy:'Healthy',review:'Review',attention:'Attention',unknown:'Unknown'}[data.state]||'Unknown');put('nx-health-detail',total?`${good} of ${total} checks healthy`:'Health data unavailable');$('nx-health-ring').style.setProperty('--health',`${percent||0}%`);$('nx-health-ring').dataset.state=data.state||'unknown';$('nx-health-strip').dataset.state=data.state||'unknown';put('nx-health-headline',data.headline||'Health summary unavailable');}
  async function refreshDetails(){if(slowBusy||document.hidden)return;slowBusy=true;
    const tasks=[
      request('/api/peers').then(d=>{if(!Array.isArray(d.peers))throw Error();peerRows(d.peers);}).catch(()=>{put('nx-connected','—');put('nx-peer-caption','Peer data unavailable');$('nx-recent-peers').innerHTML='<tr><td colspan="5" class="nx-empty">Unable to load peers. Use Refresh to try again.</td></tr>';put('nx-peer-summary','Peer data unavailable');}),
      request('/api/subscriptions').then(d=>{if(!Array.isArray(d.subscriptions))throw Error();subscriptions(d.subscriptions);}).catch(()=>{put('nx-subscriptions','—');put('nx-sub-caption','Policy data unavailable');put('nx-attention-title','Subscription check unavailable');put('nx-attention-copy','Open subscriptions to inspect current access policies.');put('nx-attention-count','—');}),
      request('/api/telegram/status').then(d=>{put('nx-tg-state',d.bot_online?'Connected':'Offline');$('nx-tg-state').className=`nx-status-pill ${d.bot_online?'online':'offline'}`;put('nx-tg-note',d.bot_online?'Bot service is running': 'Bot is offline or has no recent heartbeat');}).catch(()=>{put('nx-tg-state','Unavailable');$('nx-tg-state').className='nx-status-pill';put('nx-tg-note','Unable to read bot status');})
    ];
    if(root.dataset.nodes==='1')tasks.push(request('/api/nodes').then(d=>{nodes=d.nodes||[];if(lastPeers)peerRows(lastPeers,false);put('nx-node-count',`${nodes.filter(n=>n.online).length} of ${nodes.length} nodes online`);}).catch(()=>put('nx-node-count','Node status unavailable')));else put('nx-node-count','Local server');
    if(root.dataset.admin==='1')tasks.push(request('/api/health-center').then(health).catch(()=>health({state:'unknown',headline:'Health check unavailable'})));else health({state:'unknown',headline:'Health details require administrator access'});
    await Promise.allSettled(tasks);slowBusy=false;clearTimeout(slowTimer);if(!document.hidden)slowTimer=setTimeout(refreshDetails,60000);
  }
  document.querySelectorAll('[data-nx-window]').forEach(b=>b.addEventListener('click',()=>{windowSeconds=Number(b.dataset.nxWindow);document.querySelectorAll('[data-nx-window]').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));drawTraffic();}));
  $('nx-refresh').addEventListener('click',()=>{refreshStats();refreshDetails();});
  $('nx-system-toggle').addEventListener('click',()=>{const details=$('nx-system-details');details.hidden=!details.hidden;$('nx-system-toggle').setAttribute('aria-expanded',String(!details.hidden));});
  window.addEventListener('wg-theme-change',themeCharts);
  document.addEventListener('visibilitychange',()=>{clearTimeout(fastTimer);clearTimeout(slowTimer);if(!document.hidden){refreshStats();refreshDetails();}});
  window.addEventListener('pagehide',()=>{clearTimeout(fastTimer);clearTimeout(slowTimer);});
  initCharts();Promise.resolve(window.WG_PANEL_TIMEZONE_READY).finally(()=>{refreshStats();refreshDetails();});
})();
