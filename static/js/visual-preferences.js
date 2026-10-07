(() => {
 'use strict';
 const choices={lighting:['subtle','aurora','none'],motion:['auto','off'],density:['comfortable','compact']};
 for(const [key,allowed] of Object.entries(choices)){
  const control=document.getElementById('workspace-'+key);let value=allowed[0];
  try{const saved=localStorage.getItem('wg-workspace-'+key);if(allowed.includes(saved))value=saved;}catch(_){}
  const apply=v=>document.documentElement.setAttribute('data-workspace-'+key,v);
  apply(value);if(control){control.value=value;control.addEventListener('change',()=>{if(!allowed.includes(control.value))return;apply(control.value);try{localStorage.setItem('wg-workspace-'+key,control.value);}catch(_){} });}
 }
})();
