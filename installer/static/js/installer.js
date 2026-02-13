let live = true;

async function gen(kind, targetId){
  const res = await fetch("/api/gen", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({kind})
  });
  const j = await res.json();
  if (j.value && targetId) {
    const el = document.getElementById(targetId);
    if (el) el.value = j.value;
  }
}

async function loadLog(){
  if (!live) return;
  try{
    const res = await fetch("/api/log-tail?n=220", {cache:"no-store"});
    const j = await res.json();
    const box = document.getElementById("liveLog");
    if (box && j.lines) {
      box.textContent = j.lines.join("\n");
      box.scrollTop = box.scrollHeight;
    }
  }catch(e){}
}

document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-gen]");
  if (b){
    gen(b.getAttribute("data-gen"), b.getAttribute("data-target"));
    return;
  }
  if (e.target.id === "btnPause") live = false;
  if (e.target.id === "btnResume") live = true;
});

setInterval(loadLog, 1000);
window.addEventListener("load", loadLog);
