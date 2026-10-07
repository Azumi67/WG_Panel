(() => {
 'use strict';
 const dialog=document.getElementById('account-dialog');if(!dialog)return;
 const appearance=document.getElementById('account-auth-design');
 if(appearance){try{appearance.value=localStorage.getItem('wg-auth-design')||'follow';}catch(_){}appearance.onchange=()=>{try{localStorage.setItem('wg-auth-design',appearance.value);}catch(_){}};}
 const form=document.getElementById('account-profile-form'),status=document.getElementById('account-status'),save=document.getElementById('account-save');
 let profile={preset:'orbit',image:''},draft={...profile},loaded=false,busy=false;
 const icons={orbit:'fa-planet-ringed',mountain:'fa-mountain',wave:'fa-water',forest:'fa-tree',sunrise:'fa-sun',initials:'fa-user'};
 function art(el,data){el.replaceChildren();if(data.image){const img=document.createElement('img');img.src=data.image;img.alt='';el.append(img);}else{const img=document.createElement('img');img.src='/static/img/avatars/'+data.preset+'.svg';img.alt='';el.append(img);}}
 function render(){document.querySelectorAll('[data-account-avatar]').forEach(el=>art(el,profile));art(dialog.querySelector('[data-account-avatar]'),draft);dialog.querySelectorAll('[data-avatar-preset]').forEach(b=>b.setAttribute('aria-pressed',String(!draft.image&&draft.preset===b.dataset.avatarPreset)));}
 async function api(data){const response=await fetch('/api/account/profile',{method:data?'PUT':'GET',credentials:'same-origin',headers:{'Content-Type':'application/json',...window.csrfHeaders?.(true)},...(data?{body:JSON.stringify(data)}:{})});const result=await response.json();if(!response.ok)throw new Error(result.error||'Profile unavailable');return result;}
 document.querySelectorAll('[data-account-open]').forEach(el=>el.addEventListener('click',async e=>{e.preventDefault();draft={...profile};dialog.showModal();render();status.textContent=loaded?'':'Loading profile…';save.disabled=!loaded;try{profile=await api();draft={...profile};loaded=true;save.disabled=false;render();status.textContent='';}catch(error){status.textContent=error.message;}}));
 dialog.querySelector('[data-account-close]').onclick=()=>{if(!busy)dialog.close();};
 dialog.querySelectorAll('[data-avatar-art]').forEach(el=>art(el,{preset:el.dataset.avatarArt,image:''}));
 dialog.querySelectorAll('[data-avatar-preset]').forEach(el=>el.onclick=()=>{draft={preset:el.dataset.avatarPreset,image:''};render();status.textContent='Unsaved changes';});
 document.getElementById('account-image').onchange=async event=>{const file=event.target.files[0];if(!file)return;if(file.size>5*1024*1024||!['image/png','image/jpeg','image/webp'].includes(file.type)){status.textContent='Choose a PNG, JPEG or WebP image smaller than 5 MB.';return;}const url=URL.createObjectURL(file);try{const img=new Image();img.src=url;await img.decode();const canvas=document.createElement('canvas');canvas.width=canvas.height=192;const size=Math.min(img.width,img.height);canvas.getContext('2d').drawImage(img,(img.width-size)/2,(img.height-size)/2,size,size,0,0,192,192);draft.image=canvas.toDataURL('image/png');render();status.textContent='Picture ready. Save to apply.';}catch(_){status.textContent='This picture could not be opened.';}finally{URL.revokeObjectURL(url);event.target.value='';}};
 form.onsubmit=async e=>{e.preventDefault();if(!loaded||busy)return;busy=true;save.disabled=true;try{profile=await api(draft);draft={...profile};render();status.textContent='Profile saved.';}catch(error){status.textContent=error.message;}finally{busy=false;save.disabled=false;}};
 render();api().then(data=>{profile=data;draft={...data};loaded=true;render();}).catch(()=>{});
})();
