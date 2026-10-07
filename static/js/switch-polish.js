(() => {
 const selectors='input[type="checkbox"] + .track,input[type="checkbox"] + .slider,input[type="checkbox"] + .switch-slider,input[type="checkbox"] + .studio8-toggle,input[type="checkbox"] + .auto-network-switch,input[type="checkbox"] + .iface-auto-up-switch,.peerx-switch > input[type="checkbox"] + span,input[type="checkbox"] + .pte-switch,input[type="checkbox"] + .adv8-switch,.subx-switch > input[type="checkbox"] + span,.studio16-reset-toggle > input[type="checkbox"] + span,.studio24-switch > input[type="checkbox"] + span';
 function decorate(root){if(root.nodeType!==1&&root!==document)return;root.querySelectorAll(selectors).forEach(el=>el.classList.add('ws-switch-track'));if(root.matches?.(selectors))root.classList.add('ws-switch-track');}
 decorate(document);
 new MutationObserver(records=>{for(const record of records)for(const node of record.addedNodes)decorate(node);}).observe(document.body,{childList:true,subtree:true});
})();
