let products = [];
let cart = [];
let discountIndex = null;
let currentUser = null;
const API_BASE = "https://cassacinemattarello.onrender.com";
const $ = id => document.getElementById(id);
let authToken = localStorage.getItem("cinematta_token") || "";
const money = n => new Intl.NumberFormat("it-IT", { style:"currency", currency:"EUR" }).format(Number(n || 0));
const esc = value => String(value).replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
async function api(url, options={}) {
  const response = await fetch(API_BASE + url, { ...options, credentials:"omit", headers:{ "Content-Type":"application/json", ...(authToken ? { Authorization:"Bearer " + authToken } : {}), ...(options.headers||{}) } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Errore nella richiesta.");
  return data;
}
function showError(message) { $("errorMsg").textContent = message || ""; }
function totalCart() { return cart.reduce((sum, item) => sum + item.price * item.quantity * (1-item.discount/100), 0); }

async function start() {
  try {
    const me = await api("/api/me");
    currentUser = me.user;
    $("loginOverlay").classList.add("hidden");
    $("posContainer").classList.remove("hidden");
    $("currentUser").textContent = `👤 ${currentUser.username} (${currentUser.role === "resocontista" ? "Resocontista" : currentUser.role})`;
    const reportOnly = currentUser.role === "resocontista";
    document.body.classList.toggle("report-view", reportOnly);
    $("showReports").classList.remove("hidden");
    if (reportOnly) {
      $("reportsPanel").classList.remove("hidden");
      await loadReports();
      return;
    }
    $("closeCash").classList.remove("hidden");
    if (currentUser.role === "admin") $("openAdmin").classList.remove("hidden");
    products = (await api("/api/products")).products;
    renderProducts();
    await refreshCash();
  } catch (_) {
    $("loginOverlay").classList.remove("hidden");
    $("posContainer").classList.add("hidden");
  }
}
$("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  $("loginError").textContent = "";
  try {
    const login = await api("/api/login", { method:"POST", body:JSON.stringify({ username:$("loginUser").value, password:$("loginPass").value }) });
    authToken = login.token;
    localStorage.setItem("cinematta_token", authToken);
    $("loginPass").value = "";
    await start();
  } catch (err) { $("loginError").textContent = err.message; }
});
$("logout").onclick = async () => { try { await api("/api/logout", { method:"POST", body:"{}" }); } finally { authToken = ""; localStorage.removeItem("cinematta_token"); location.reload(); } };

function renderProducts() {
  const grid = $("productGrid");
  grid.innerHTML = "";
  products.forEach(product => {
    const button = document.createElement("button");
    button.className = "product-btn";
    button.innerHTML = `<span class="product-name">${esc(product.name)}</span><span class="product-price">${money(product.price)}</span><span class="product-category">${esc(product.category)}</span>`;
    button.addEventListener("click", () => addProduct(product));
    grid.appendChild(button);
  });
}
function addProduct(product) {
  const found = cart.find(x => x.code === product.code && x.discount === 0);
  if (found) found.quantity++;
  else cart.push({ code:product.code, name:product.name, price:Number(product.price), quantity:1, discount:0 });
  renderCart();
}
$("barcodeScanInput").addEventListener("keydown", e => {
  if (e.key !== "Enter") return;
  const code = $("barcodeScanInput").value.trim();
  const product = products.find(p => p.code === code);
  if (product) { addProduct(product); $("barcodeScanInput").value = ""; showError(""); }
  else showError(`Codice "${code}" non trovato.`);
});
$("addTicket").onclick = () => {
  const price = Number($("ticketPriceInput").value);
  if (!Number.isFinite(price) || price <= 0) return showError("Inserisci un prezzo biglietto valido.");
  cart.push({ ticket:true, name:"Biglietto Cinema", price, quantity:1, discount:0 });
  $("ticketPriceInput").value = "";
  renderCart();
};
function renderCart() {
  $("cartTableBody").innerHTML = cart.map((item,i) => `
    <tr>
      <td>${esc(item.name)}${item.discount ? `<br><small>(-${item.discount}%)</small>` : ""}</td>
      <td><button data-action="minus" data-i="${i}">−</button> ${item.quantity} <button data-action="plus" data-i="${i}">+</button></td>
      <td>${money(item.price*item.quantity*(1-item.discount/100))}</td>
      <td><button data-action="discount" data-i="${i}">%</button> <button data-action="remove" data-i="${i}">X</button></td>
    </tr>`).join("");
  $("totalDisplay").textContent = money(totalCart());
  showError("");
}
$("cartTableBody").addEventListener("click", e => {
  const b = e.target.closest("button[data-action]");
  if (!b) return;
  const i = Number(b.dataset.i), action = b.dataset.action;
  if (action === "plus") cart[i].quantity++;
  if (action === "minus") { cart[i].quantity--; if (cart[i].quantity <= 0) cart.splice(i,1); }
  if (action === "remove") cart.splice(i,1);
  if (action === "discount") {
    discountIndex = i; $("discountInputVal").value = cart[i].discount || 10;
    $("discountModal").classList.remove("hidden"); return;
  }
  renderCart();
});
$("confirmDiscount").onclick = () => {
  const val = Number($("discountInputVal").value);
  if (!Number.isFinite(val) || val < 0 || val > 100 || discountIndex === null) return alert("Sconto non valido.");
  cart[discountIndex].discount = val;
  discountIndex = null; $("discountModal").classList.add("hidden"); renderCart();
};
$("cancelDiscount").onclick = () => $("discountModal").classList.add("hidden");
async function pay(method) {
  if (!cart.length) return showError("Il carrello è vuoto.");
  const cashReceived = Number($("cashInput").value);
  try {
    const items = cart.map(item => ({
      code:item.code || null, ticket:Boolean(item.ticket), price:item.ticket ? item.price : undefined,
      quantity:item.quantity, discount:item.discount
    }));
    const result = await api("/api/sales", { method:"POST", body:JSON.stringify({ paymentMethod:method, items, cashReceived }) });
    cart = []; $("cashInput").value = ""; renderCart(); await refreshCash();
    if (method === "Contanti") {
      $("modalChangeAmount").textContent = money(result.change);
      $("changeModal").classList.remove("hidden");
    } else alert(`Pagamento POS di ${money(result.total)} registrato.`);
  } catch (err) { showError(err.message); }
}
$("payCash").onclick = () => pay("Contanti");
$("payPos").onclick = () => pay("POS");
$("closeChange").onclick = () => $("changeModal").classList.add("hidden");

async function refreshCash() {
  const data = await api("/api/sales/current");
  $("fundStatus").textContent = `Fondo cassa iniziale: ${money(data.cashSession.opening_fund)}`;
  $("sessionTotal").textContent = `Incasso cassa: ${money(data.totals.revenue)}`;
  $("salesStatsList").innerHTML = data.items.length ? data.items.map(x => `<div>• ${x.quantity} di ${esc(x.name)}</div>`).join("") : "Nessuna vendita effettuata.";
}
async function loadReports() {
  const panel = $("reportsPanel");
  panel.textContent = "Caricamento resoconti...";
  try {
    const data = await api("/api/reports");
    panel.innerHTML = data.cashSessions.length ? data.cashSessions.map(c =>
      `<div class="report-row"><span><b>Cassa #${c.id}</b> · ${c.closed_at ? "Chiusa" : "Aperta"} · Aperta da: ${esc(c.opened_by_name || "Non registrato")} · Chiusa da: ${esc(c.closed_by_name || "—")} · Apertura: ${new Date(c.opened_at).toLocaleString("it-IT")} · ${money(c.revenue)} · ${c.transactions} vendite</span><span><button class="btn-action" data-sales="${c.id}">Transazioni</button> <button class="btn-action" data-pdf-id="${c.id}">Scarica PDF</button> ${["admin","resocontista"].includes(currentUser.role) ? `<button class="btn-action" data-report-id="${c.id}">Scarica CSV</button>` : ""} ${currentUser.role === "admin" && c.closed_at ? `<button class="btn-danger" data-delete-report="${c.id}">Elimina</button>` : ""}</span></div><div id="sales-${c.id}" class="sale-list hidden"></div>`
    ).join("") : "Nessun resoconto disponibile.";
  } catch (err) { panel.textContent = err.message; }
}
$("showReports").onclick = async () => { const p=$("reportsPanel"); p.classList.toggle("hidden"); if(!p.classList.contains("hidden")) await loadReports(); };
$("reportsPanel").addEventListener("click", async e => {
  const show=e.target.closest("button[data-sales]");
  const cancel=e.target.closest("button[data-void-sale]");
  const download=e.target.closest("button[data-report-id]");
  const pdf=e.target.closest("button[data-pdf-id]");
  const deleteReport=e.target.closest("button[data-delete-report]");
  if(show) {
    const id=show.dataset.sales, box=$("sales-"+id); box.classList.toggle("hidden"); if(box.classList.contains("hidden")) return;
    try { const d=await api("/api/reports/"+id+"/sales"); box.innerHTML=d.sales.length ? d.sales.map(x=>`<div class="sale-row"><span><b>Vendita #${x.id}</b> · ${new Date(x.created_at).toLocaleString("it-IT")} · ${esc(x.username)} · ${money(x.total)}<br><small>${esc(x.items||"")}${x.voided_at?" · ANNULLATA":""}</small></span>${x.voided_at || currentUser.role === "resocontista" ? "" : `<button class="btn-danger" data-void-sale="${x.id}">Annulla</button>`}</div>`).join("") : "Nessuna vendita."; } catch(err) { box.textContent=err.message; }
    return;
  }
  if(cancel) { if(!confirm("Annullare questa vendita? Sarà esclusa da incassi e classifica.")) return; const reason=prompt("Motivo (facoltativo):")||"Annullata"; try { await api("/api/sales/"+cancel.dataset.voidSale+"/void",{method:"POST",body:JSON.stringify({reason})}); await loadReports(); await refreshCash(); } catch(err) { alert(err.message); } return; }
  if(deleteReport) {
    const id=deleteReport.dataset.deleteReport;
    if(!confirm("Eliminare definitivamente il resoconto della cassa #"+id+" e tutte le sue vendite? L'operazione non si può annullare.")) return;
    try { await api("/api/admin/reports/"+id,{method:"DELETE"}); await loadReports(); await refreshAdmin(); }
    catch(err) { alert(err.message); }
    return;
  }
  if(pdf) {
    try { const response=await fetch(API_BASE+"/api/reports/"+pdf.dataset.pdfId+".pdf",{headers:authToken?{Authorization:"Bearer "+authToken}:{}}); if(!response.ok) throw new Error("Download PDF non riuscito."); const blob=await response.blob(); const url=URL.createObjectURL(blob); const link=document.createElement("a"); link.href=url; link.download="resoconto-cassa-"+pdf.dataset.pdfId+".pdf"; document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url); }
    catch(err) { alert(err.message); }
    return;
  }
  if(download) {
    try { const response=await fetch(API_BASE+"/api/reports/"+download.dataset.reportId+".csv",{headers:authToken?{Authorization:"Bearer "+authToken}:{}}); if(!response.ok) throw new Error("Download non riuscito."); const blob=await response.blob(); const url=URL.createObjectURL(blob); const link=document.createElement("a"); link.href=url; link.download="resoconto-cassa-"+download.dataset.reportId+".csv"; document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url); } catch(err) { alert(err.message); }
  }
});
$("showRanking").onclick = async () => {
  const panel = $("rankingPanel");
  panel.classList.toggle("hidden");
  if (panel.classList.contains("hidden")) return;
  try {
    const data = await api("/api/ranking");
    panel.innerHTML = `<strong>Classifica storica (unità vendute)</strong>` + (data.ranking.length
      ? data.ranking.map((x,i) => `<div class="ranking-row"><span>${i+1}. ${esc(x.name)}</span><b>${x.quantity}</b></div>`).join("")
      : `<p>Nessuna vendita registrata.</p>`);
  } catch (err) { panel.textContent = err.message; }
};
$("closeCash").onclick = async () => {
  if (!confirm("Confermi la chiusura della cassa corrente? Lo storico delle vendite resterà conservato.")) return;
  try {
    const current = await api("/api/sales/current");
    await api(`/api/cash/close/${current.cashSession.id}`, { method:"POST", body:"{}" });
    await refreshCash();
    alert("Cassa chiusa. È stata aperta una nuova sessione.");
  } catch (err) { showError(err.message); }
};

$("openAdmin").onclick = async () => {
  $("adminModal").classList.remove("hidden");
  await refreshAdmin();
};
$("closeAdmin").onclick = () => $("adminModal").classList.add("hidden");
async function refreshAdmin() {
  const [usersData, cashData] = await Promise.all([api("/api/admin/users"), api("/api/admin/cash-sessions")]);
  $("adminUsers").innerHTML = usersData.users.map(u => `
    <div class="admin-row"><span><b>${esc(u.username)}</b> · ${esc(u.role)} · ${u.active ? "Attivo" : "Disattivato"}</span>
    <button class="btn-danger" data-user-id="${u.id}" data-active="${u.active ? "false":"true"}">${u.active ? "Disattiva":"Riattiva"}</button></div>`).join("");
  $("adminCashSessions").innerHTML = cashData.cashSessions.map(c => `
    <div class="admin-row"><span><b>Cassa #${c.id}</b> · ${c.closed_at ? "Chiusa" : "Aperta"} · Aperta da: ${esc(c.opened_by_name || "Non registrato")} · Chiusa da: ${esc(c.closed_by_name || "—")} · ${money(c.revenue)} · ${c.transactions} transazioni</span>
    ${c.closed_at ? "" : `<button class="btn-danger" data-cash-id="${c.id}">Chiudi cassa</button>`}</div>`).join("");
}
$("newUserForm").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    await api("/api/admin/users", { method:"POST", body:JSON.stringify({ username:$("newUsername").value, password:$("newPassword").value, role:$("newRole").value }) });
    $("newUserForm").reset(); await refreshAdmin(); alert("Account creato.");
  } catch (err) { alert(err.message); }
});
$("adminUsers").addEventListener("click", async e => {
  const b = e.target.closest("button[data-user-id]");
  if (!b) return;
  try {
    await api(`/api/admin/users/${b.dataset.userId}`, { method:"PATCH", body:JSON.stringify({ active:b.dataset.active === "true" }) });
    await refreshAdmin();
  } catch (err) { alert(err.message); }
});
$("adminCashSessions").addEventListener("click", async e => {
  const b = e.target.closest("button[data-cash-id]");
  if (!b || !confirm(`Chiudere la cassa #${b.dataset.cashId}?`)) return;
  try { await api(`/api/cash/close/${b.dataset.cashId}`, { method:"POST", body:"{}" }); await refreshAdmin(); await refreshCash(); }
  catch (err) { alert(err.message); }
});

start();
