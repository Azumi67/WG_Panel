(() => {
  'use strict';
  const previousHTML=new WeakMap();
  function text(node,value){if(!node)return;const next=String(value??'');if(node.textContent!==next)node.textContent=next;}
  function html(node,value){if(!node)return false;if(previousHTML.get(node)===value)return false;node.innerHTML=value;previousHTML.set(node,value);return true;}
  function patch(oldNode,newNode){
    if(oldNode.nodeType!==newNode.nodeType||oldNode.nodeName!==newNode.nodeName){oldNode.replaceWith(newNode);return;}
    if(oldNode.nodeType!==1){if(oldNode.nodeValue!==newNode.nodeValue)oldNode.nodeValue=newNode.nodeValue;return;}
    for(const attr of [...oldNode.attributes])if(!newNode.hasAttribute(attr.name))oldNode.removeAttribute(attr.name);
    for(const attr of [...newNode.attributes])if(oldNode.getAttribute(attr.name)!==attr.value)oldNode.setAttribute(attr.name,attr.value);
    const before=[...oldNode.childNodes],after=[...newNode.childNodes];
    for(let i=0;i<Math.max(before.length,after.length);i++){
      if(!after[i])before[i].remove();else if(!before[i])oldNode.append(after[i]);else patch(before[i],after[i]);
    }
  }
  function rows(list,markup,key,prepare){
    const template=document.createElement('template');template.innerHTML=markup;
    if(prepare)prepare(template.content);
    const existing=new Map([...list.children].filter(el=>key(el)).map(el=>[key(el),el]));
    const wanted=new Set();
    [...template.content.children].forEach((next,index)=>{
      let node=existing.get(key(next));
      if(node){patch(node,next);}else node=next;
      wanted.add(node);
      if(list.children[index]!==node)list.insertBefore(node,list.children[index]||null);
    });
    for(const node of [...list.children])if(!wanted.has(node))node.remove();
  }
  function options(select,items){
    if(!select)return;
    const signature=JSON.stringify(items.map(item=>[String(item.value),String(item.label)]));
    if(previousHTML.get(select)===signature)return;
    const selected=select.value;
    select.replaceChildren(...items.map(item=>new Option(item.label,item.value)));
    if([...select.options].some(option=>option.value===selected))select.value=selected;
    previousHTML.set(select,signature);
  }
  function live(node,state,caption){
    if(!node)return;
    node.dataset.liveState=state;
    text(node.querySelector('b'),state==='ready'?'Live':state==='loading'?'Updating':state==='paused'?'Paused':'Stale');
    text(node.querySelector('small'),caption);
  }
  window.WGWorkspace=Object.freeze({text,html,patch,rows,options,live});
})();
