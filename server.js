const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
const PDFDocument = require("pdfkit");

const app = express();
app.set("trust proxy", 1); // Render: un proxy fidato davanti a Express
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === "production";

if (!process.env.DATABASE_URL) {
  console.error("ERRORE: DATABASE_URL non configurato. Crea un database PostgreSQL.");
  process.exit(1);
}
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("ERRORE: SESSION_SECRET deve contenere almeno 32 caratteri.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : undefined
});

const allowedOrigins = new Set(["https://thelissofficial.github.io"]);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const cookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: "strict",
  path: "/",
  maxAge: 7 * 24 * 60 * 60 * 1000
};

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function loadProducts() {
  const file = path.join(__dirname, "prodotti.txt");
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  const products = [];
  for (const line of lines) {
    const parts = line.trim().split(",");
    if (parts.length < 4) continue;
    const [code, name, rawPrice, category] = parts;
    const price = Number(String(rawPrice).replace(",", "."));
    if (code && name && Number.isFinite(price) && price >= 0) {
      products.push({ code: code.trim(), name: name.trim(), price, category: category.trim() });
    }
  }
  return products;
}
const products = loadProducts();
const productByCode = new Map();
for (const p of products) {
  if (!productByCode.has(p.code)) productByCode.set(p.code, p);
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','operatore','resocontista')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS user_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS cash_sessions (
      id BIGSERIAL PRIMARY KEY,
      opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      closed_at TIMESTAMPTZ,
      opened_by BIGINT REFERENCES app_users(id),
      closed_by BIGINT REFERENCES app_users(id),
      opening_fund NUMERIC(12,2) NOT NULL DEFAULT 250.00,
      closing_cash NUMERIC(12,2),
      closing_pos NUMERIC(12,2)
    );
    CREATE TABLE IF NOT EXISTS sales (
      id BIGSERIAL PRIMARY KEY,
      cash_session_id BIGINT NOT NULL REFERENCES cash_sessions(id),
      user_id BIGINT NOT NULL REFERENCES app_users(id),
      payment_method TEXT NOT NULL CHECK (payment_method IN ('Contanti','POS')),
      total NUMERIC(12,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sale_items (
      id BIGSERIAL PRIMARY KEY,
      sale_id BIGINT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
      product_code TEXT,
      product_name TEXT NOT NULL,
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      unit_price NUMERIC(12,2) NOT NULL,
      discount_percent NUMERIC(5,2) NOT NULL DEFAULT 0
    );
    ALTER TABLE app_users DROP CONSTRAINT IF EXISTS app_users_role_check;
    ALTER TABLE app_users ADD CONSTRAINT app_users_role_check CHECK (role IN ('admin','operatore','resocontista'));
    ALTER TABLE sales ADD COLUMN IF NOT EXISTS voided_at TIMESTAMPTZ;
    ALTER TABLE sales ADD COLUMN IF NOT EXISTS voided_by BIGINT REFERENCES app_users(id);
    ALTER TABLE sales ADD COLUMN IF NOT EXISTS void_reason TEXT;
    CREATE INDEX IF NOT EXISTS idx_sales_cash_session ON sales(cash_session_id);
    SELECT setval(pg_get_serial_sequence('cash_sessions','id'), GREATEST(COALESCE((SELECT MAX(id) FROM cash_sessions),1), (SELECT last_value FROM cash_sessions_id_seq)), (SELECT is_called FROM cash_sessions_id_seq) OR EXISTS (SELECT 1 FROM cash_sessions));
    CREATE INDEX IF NOT EXISTS idx_sale_items_product ON sale_items(product_code, product_name);
    CREATE INDEX IF NOT EXISTS idx_user_sessions_expiry ON user_sessions(expires_at);
  `);

  const username = (process.env.ADMIN_USERNAME || "").trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || "";
  if (username && password) {
    if (password.length < 12) throw new Error("ADMIN_PASSWORD deve avere almeno 12 caratteri.");
    const existing = await pool.query("SELECT id FROM app_users WHERE username=$1", [username]);
    if (!existing.rowCount) {
      const hash = await bcrypt.hash(password, 12);
      await pool.query(
        "INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,'admin')",
        [username, hash]
      );
      console.log("Account amministratore iniziale creato.");
    }
  } else {
    console.warn("ADMIN_USERNAME/ADMIN_PASSWORD non configurati: crea l'admin nelle variabili d'ambiente e riavvia.");
  }

}

async function auth(req, res, next) {
  try {
    const authHeader = String(req.headers.authorization || "");
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : req.cookies.cinematta_session;
    if (!token) return res.status(401).json({ error: "Accesso richiesto." });
    const result = await pool.query(`
      SELECT u.id, u.username, u.role, u.active
      FROM user_sessions s JOIN app_users u ON u.id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at > NOW()
    `, [sha256(token)]);
    if (!result.rowCount || !result.rows[0].active) {
      res.clearCookie("cinematta_session", { path: "/" });
      return res.status(401).json({ error: "Sessione non valida." });
    }
    req.user = result.rows[0];
    next();
  } catch (err) {
    next(err);
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Operazione riservata agli amministratori." });
  next();
}
function cashierOnly(req, res, next) {
  if (req.user.role === "resocontista") return res.status(403).json({ error: "Il ruolo Resocontista è in sola lettura." });
  next();
}
function reportReader(req, res, next) { next(); }
async function activeCashSession(client = pool) {
  const r = await client.query("SELECT * FROM cash_sessions WHERE closed_at IS NULL ORDER BY id DESC LIMIT 1");
  return r.rows[0] || null;
}

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
app.get("/api/health", (req, res) => res.json({ ok: true }));

const simulations = new Map();
function simulationFor(userId) {
  let sim=simulations.get(String(userId));
  if(!sim){sim={openedAt:null,closedAt:null,sales:[],nextSaleId:1};simulations.set(String(userId),sim);}
  return sim;
}
app.get("/api/sim/current",auth,adminOnly,(req,res)=>{
  const sim=simulationFor(req.user.id),active=!!sim.openedAt&&!sim.closedAt;
  const t=sim.sales.reduce((v,x)=>{v.revenue+=x.total;v[x.payment_method==="Contanti"?"cash":"pos"]+=x.total;v.transactions++;return v;},{revenue:0,cash:0,pos:0,transactions:0});
  const items={};sim.sales.forEach(x=>x.items.forEach(i=>items[i.name]=(items[i.name]||0)+i.quantity));
  res.json({cashSession:active?{id:"SIM",opened_at:sim.openedAt,opening_fund:"250.00"}:null,totals:{revenue:t.revenue.toFixed(2),cash:t.cash.toFixed(2),pos:t.pos.toFixed(2),transactions:t.transactions},items:Object.entries(items).map(([name,quantity])=>({name,quantity}))});
});
app.post("/api/sim/open",auth,adminOnly,(req,res)=>{
  const sim=simulationFor(req.user.id);if(sim.openedAt&&!sim.closedAt)return res.status(409).json({error:"La simulazione è già aperta."});
  sim.openedAt=new Date().toISOString();sim.closedAt=null;sim.sales=[];sim.nextSaleId=1;res.status(201).json({ok:true});
});
app.post("/api/sim/sales",auth,adminOnly,(req,res)=>{
  const sim=simulationFor(req.user.id);if(!sim.openedAt||sim.closedAt)return res.status(409).json({error:"Apri prima la cassa di simulazione."});
  const {paymentMethod,items,cashReceived}=req.body||{};
  if(!["Contanti","POS"].includes(paymentMethod)||!Array.isArray(items)||!items.length||items.length>100)return res.status(400).json({error:"Dati di vendita non validi."});
  let total=0;const normalized=[];
  for(const item of items){
    const quantity=Number(item.quantity),discount=Number(item.discount||0);
    if(!Number.isInteger(quantity)||quantity<1||quantity>999||!Number.isFinite(discount)||discount<0||discount>100)return res.status(400).json({error:"Quantità o sconto non validi."});
    let p;if(item.code)p=productByCode.get(String(item.code));else if(item.ticket===true){const price=Number(item.price);if(!Number.isFinite(price)||price<=0||price>1000)return res.status(400).json({error:"Prezzo biglietto non valido."});p={name:"Biglietto Cinema",price};}
    if(!p)return res.status(400).json({error:"Prodotto non valido."});
    total+=Number(p.price)*quantity*(1-discount/100);normalized.push({name:p.name,quantity,price:Number(p.price),discount});
  }
  total=Math.round((total+Number.EPSILON)*100)/100;
  if(paymentMethod==="Contanti"&&(!Number.isFinite(Number(cashReceived))||Number(cashReceived)<total))return res.status(400).json({error:"Contanti insufficienti o non validi."});
  sim.sales.push({id:sim.nextSaleId++,created_at:new Date().toISOString(),payment_method:paymentMethod,total,items:normalized});
  res.json({ok:true,total,change:paymentMethod==="Contanti"?Math.round((Number(cashReceived)-total+Number.EPSILON)*100)/100:0});
});
app.post("/api/sim/reset",auth,adminOnly,(req,res)=>{simulations.delete(String(req.user.id));res.json({ok:true});});
app.post("/api/sim/close",auth,adminOnly,(req,res)=>{
  const sim=simulationFor(req.user.id);if(!sim.openedAt||sim.closedAt)return res.status(409).json({error:"Nessuna cassa di simulazione aperta."});
  sim.closedAt=new Date().toISOString();res.json({ok:true});
});


app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!username || !password) return res.status(400).json({ error: "Inserisci utente e password." });
    const r = await pool.query("SELECT * FROM app_users WHERE username=$1 AND active=TRUE", [username]);
    const user = r.rows[0];
    const valid = user ? await bcrypt.compare(password, user.password_hash) : await bcrypt.hash(password, 10).then(() => false);
    if (!valid) return res.status(401).json({ error: "Credenziali non valide." });
    const token = crypto.randomBytes(32).toString("base64url");
    await pool.query("INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '7 days')", [sha256(token), user.id]);
    res.cookie("cinematta_session", token, cookieOptions);
    res.json({ token, user: { username: user.username, role: user.role } });
  } catch (err) { next(err); }
});

app.post("/api/logout", async (req, res, next) => {
  try {
    const authHeader = String(req.headers.authorization || "");
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : req.cookies.cinematta_session;
    if (token) await pool.query("DELETE FROM user_sessions WHERE token_hash=$1", [sha256(token)]);
    res.clearCookie("cinematta_session", { path: "/", secure: isProd, sameSite: "strict", httpOnly: true });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.get("/api/me", auth, (req, res) => res.json({ user: { username: req.user.username, role: req.user.role } }));
app.get("/api/products", auth, cashierOnly, (req, res) => res.json({ products }));

app.get("/api/ranking", auth, cashierOnly, async (req, res, next) => {
  try {
    const r = await pool.query(`
      SELECT si.product_code AS code, si.product_name AS name, SUM(si.quantity)::int AS quantity
      FROM sale_items si
      JOIN sales s ON s.id=si.sale_id
      WHERE si.product_code IS NOT NULL AND s.voided_at IS NULL
      GROUP BY si.product_code, si.product_name
      ORDER BY SUM(si.quantity) DESC, si.product_name ASC
    `);
    res.json({ ranking: r.rows });
  } catch (err) { next(err); }
});

app.get("/api/sales/current", auth, cashierOnly, async (req, res, next) => {
  try {
    const cash = await activeCashSession();
    if (!cash) return res.json({ cashSession: null, totals: { revenue: "0.00", cash: "0.00", pos: "0.00", transactions: 0 }, items: [] });
    const totals = await pool.query(`
      SELECT COALESCE(SUM(total),0)::numeric(12,2) AS revenue,
        COALESCE(SUM(total) FILTER (WHERE payment_method='Contanti'),0)::numeric(12,2) AS cash,
        COALESCE(SUM(total) FILTER (WHERE payment_method='POS'),0)::numeric(12,2) AS pos,
        COUNT(*)::int AS transactions
      FROM sales WHERE cash_session_id=$1 AND voided_at IS NULL
    `, [cash.id]);
    const items = await pool.query(`
      SELECT si.product_name AS name, SUM(si.quantity)::int AS quantity
      FROM sale_items si JOIN sales s ON s.id=si.sale_id
      WHERE s.cash_session_id=$1 AND s.voided_at IS NULL GROUP BY si.product_name ORDER BY SUM(si.quantity) DESC
    `, [cash.id]);
    res.json({ cashSession: cash, totals: totals.rows[0], items: items.rows });
  } catch (err) { next(err); }
});

app.post("/api/cash/open", auth, cashierOnly, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(72419381)");
    const existing = await activeCashSession(client);
    if (existing) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Esiste già una cassa aperta (#" + existing.id + ")." });
    }
    const created = await client.query("INSERT INTO cash_sessions(opened_by,opening_fund) VALUES($1,250.00) RETURNING *", [req.user.id]);
    await client.query("COMMIT");
    res.status(201).json({ ok: true, cashSession: created.rows[0] });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    next(err);
  } finally { client.release(); }
});

app.post("/api/sales", auth, cashierOnly, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { paymentMethod, items, cashReceived } = req.body || {};
    if (!["Contanti", "POS"].includes(paymentMethod) || !Array.isArray(items) || !items.length || items.length > 100) {
      return res.status(400).json({ error: "Dati di vendita non validi." });
    }
    let total = 0;
    const normalized = [];
    for (const item of items) {
      const quantity = Number(item.quantity);
      const discount = Number(item.discount || 0);
      if (!Number.isInteger(quantity) || quantity < 1 || quantity > 999 || !Number.isFinite(discount) || discount < 0 || discount > 100) {
        return res.status(400).json({ error: "Quantità o sconto non validi." });
      }
      let product;
      if (item.code) {
        product = productByCode.get(String(item.code));
        if (!product) return res.status(400).json({ error: "Prodotto non presente nel catalogo." });
      } else if (item.ticket === true) {
        const price = Number(item.price);
        if (!Number.isFinite(price) || price <= 0 || price > 1000) return res.status(400).json({ error: "Prezzo biglietto non valido." });
        product = { code: null, name: "Biglietto Cinema", price };
      } else {
        return res.status(400).json({ error: "Riga vendita non valida." });
      }
      const unitPrice = Number(product.price);
      total += unitPrice * quantity * (1 - discount / 100);
      normalized.push({ code: product.code, name: product.name, quantity, unitPrice, discount });
    }
    total = Math.round((total + Number.EPSILON) * 100) / 100;
    if (paymentMethod === "Contanti") {
      const received = Number(cashReceived);
      if (!Number.isFinite(received) || received < total) return res.status(400).json({ error: "Contanti insufficienti o non validi." });
    }

    await client.query("BEGIN");
    const cash = await activeCashSession(client);
    if (!cash) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Nessuna cassa aperta. Premi prima APRI CASSA." });
    }
    const sale = await client.query(
      "INSERT INTO sales(cash_session_id,user_id,payment_method,total) VALUES($1,$2,$3,$4) RETURNING id",
      [cash.id, req.user.id, paymentMethod, total]
    );
    for (const item of normalized) {
      await client.query(
        "INSERT INTO sale_items(sale_id,product_code,product_name,quantity,unit_price,discount_percent) VALUES($1,$2,$3,$4,$5,$6)",
        [sale.rows[0].id, item.code, item.name, item.quantity, item.unitPrice, item.discount]
      );
    }
    await client.query("COMMIT");
    res.json({ ok: true, total, change: paymentMethod === "Contanti" ? Math.round((Number(cashReceived) - total + Number.EPSILON) * 100) / 100 : 0 });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    next(err);
  } finally { client.release(); }
});

app.post("/api/cash/close/:id", auth, cashierOnly, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const id = Number(req.params.id);
    const current = await client.query("SELECT * FROM cash_sessions WHERE id=$1 AND closed_at IS NULL FOR UPDATE", [id]);
    if (!current.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Cassa non aperta o già chiusa." });
    }
    const sums = await client.query(`
      SELECT
        COALESCE(SUM(total) FILTER (WHERE payment_method='Contanti'),0)::numeric(12,2) AS cash,
        COALESCE(SUM(total) FILTER (WHERE payment_method='POS'),0)::numeric(12,2) AS pos
      FROM sales WHERE cash_session_id=$1 AND voided_at IS NULL
    `, [id]);
    await client.query(
      "UPDATE cash_sessions SET closed_at=NOW(), closed_by=$2, closing_cash=$3, closing_pos=$4 WHERE id=$1",
      [id, req.user.id, sums.rows[0].cash, sums.rows[0].pos]
    );
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    next(err);
  } finally { client.release(); }
});

app.get("/api/reports", auth, async (req, res, next) => {
  try {
    const params = [];
    let where = "";
    let salesJoin = "LEFT JOIN sales s ON s.cash_session_id=c.id";
    if (req.user.role === "operatore") {
      params.push(req.user.id);
      salesJoin = "LEFT JOIN sales s ON s.cash_session_id=c.id AND s.user_id=$1";
      where = "WHERE EXISTS (SELECT 1 FROM sales sx WHERE sx.cash_session_id=c.id AND sx.user_id=$1)";
    }
    const r = await pool.query(`
      SELECT c.id,c.opened_at,c.closed_at,c.opening_fund,c.closing_cash,c.closing_pos,
              (SELECT COUNT(*) FROM cash_sessions c2 WHERE (c2.opened_at AT TIME ZONE 'Europe/Rome')::date = (c.opened_at AT TIME ZONE 'Europe/Rome')::date AND (c2.opened_at,c2.id) <= (c.opened_at,c.id))::int AS daily_number,
             COALESCE(SUM(s.total) FILTER (WHERE s.voided_at IS NULL),0)::numeric(12,2) AS revenue,
             COUNT(DISTINCT s.id) FILTER (WHERE s.voided_at IS NULL)::int AS transactions,
             opener.username AS opened_by_name, closer.username AS closed_by_name
      FROM cash_sessions c
      ${salesJoin}
      LEFT JOIN app_users opener ON opener.id=c.opened_by
      LEFT JOIN app_users closer ON closer.id=c.closed_by
      ${where}
      GROUP BY c.id,opener.username,closer.username
      ORDER BY c.id DESC LIMIT 200
    `, params);
    res.json({ cashSessions: r.rows });
  } catch (err) { next(err); }
});

app.get("/api/reports/:id/sales", auth, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Cassa non valida." });
    const params = [id];
    let own = "";
    if (req.user.role === "operatore") { params.push(req.user.id); own = "AND s.user_id=$2"; }
    const r = await pool.query("SELECT s.id,s.created_at,s.total,s.payment_method,s.voided_at,s.void_reason,u.username, COALESCE(string_agg(si.product_name || ' × ' || si.quantity, ', ' ORDER BY si.id), '') AS items FROM sales s JOIN app_users u ON u.id=s.user_id LEFT JOIN sale_items si ON si.sale_id=s.id WHERE s.cash_session_id=$1 " + own + " GROUP BY s.id,u.username ORDER BY s.created_at DESC", params);
    res.json({ sales: r.rows });
  } catch (err) { next(err); }
});
app.post("/api/sales/:id/void", auth, cashierOnly, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Transazione non valida." });
    const reason = String(req.body.reason || "Annullata").trim().slice(0,200);
    const owner = req.user.role === "admin" ? "" : "AND user_id=$2";
    const r = await pool.query("UPDATE sales SET voided_at=NOW(),voided_by=$2,void_reason=$3 WHERE id=$1 AND voided_at IS NULL " + owner + " RETURNING id", [id,req.user.id,reason]);
    if (!r.rowCount) return res.status(404).json({ error: "Transazione non trovata, già annullata o non appartenente al tuo account." });
    res.json({ ok:true });
  } catch (err) { next(err); }
});
app.get("/api/reports/:id.pdf", auth, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Cassa non valida." });
    const params = [id];
    let ownerFilter = "";
    if (req.user.role === "operatore") { params.push(req.user.id); ownerFilter = "AND s.user_id=$2"; }

    const sessionResult = await pool.query(`
      SELECT c.id,c.opened_at,c.closed_at,c.opening_fund,c.closing_cash,c.closing_pos,
        (SELECT COUNT(*) FROM cash_sessions c2
         WHERE (c2.opened_at AT TIME ZONE 'Europe/Rome')::date=(c.opened_at AT TIME ZONE 'Europe/Rome')::date
         AND (c2.opened_at,c2.id)<=(c.opened_at,c.id))::int AS daily_number,
        opener.username AS opened_by_name,closer.username AS closed_by_name
      FROM cash_sessions c
      LEFT JOIN app_users opener ON opener.id=c.opened_by
      LEFT JOIN app_users closer ON closer.id=c.closed_by
      WHERE c.id=$1
    `, [id]);
    if (!sessionResult.rowCount) return res.status(404).json({ error: "Cassa non trovata." });

    const salesResult = await pool.query(`
      SELECT s.id,s.created_at,s.payment_method,s.total,s.voided_at,s.void_reason,u.username
      FROM sales s JOIN app_users u ON u.id=s.user_id
      WHERE s.cash_session_id=$1 ` + ownerFilter + `
      ORDER BY s.created_at,s.id
    `, params);
    const itemsResult = await pool.query(`
      SELECT s.id AS sale_id,s.voided_at,si.product_code,si.product_name,si.quantity,
        si.unit_price,si.discount_percent,
        (si.unit_price*si.quantity) AS gross_total,
        (si.unit_price*si.quantity*si.discount_percent/100) AS discount_total,
        (si.unit_price*si.quantity*(1-si.discount_percent/100)) AS net_total
      FROM sales s JOIN sale_items si ON si.sale_id=s.id
      WHERE s.cash_session_id=$1 ` + ownerFilter + `
      ORDER BY s.created_at,s.id,si.id
    `, params);

    const cash = sessionResult.rows[0];
    const sales = salesResult.rows;
    const valid = sales.filter(x => !x.voided_at);
    const voided = sales.filter(x => x.voided_at);
    const validItems = itemsResult.rows.filter(x => !x.voided_at);
    const euro = value => new Intl.NumberFormat("it-IT",{style:"currency",currency:"EUR"}).format(Number(value || 0));
    const date = value => value ? new Date(value).toLocaleString("it-IT",{timeZone:"Europe/Rome"}) : "—";
    const money = value => Number(value || 0);
    const sum = (list,key) => list.reduce((v,x)=>v+money(x[key]),0);
    const total = sum(valid,"total");
    const cashSales = valid.filter(x=>x.payment_method==="Contanti");
    const posSales = valid.filter(x=>x.payment_method==="POS");
    const cashTotal = sum(cashSales,"total");
    const posTotal = sum(posSales,"total");
    const grossTotal = sum(validItems,"gross_total");
    const discountTotal = sum(validItems,"discount_total");
    const openingFund = money(cash.opening_fund);
    const closingCashSales = cash.closed_at ? money(cash.closing_cash) : cashTotal;
    const closingPosSales = cash.closed_at ? money(cash.closing_pos) : posTotal;
    const expectedCash = openingFund + closingCashSales;
    const avgTicket = valid.length ? total / valid.length : 0;

    const productMap = new Map();
    for (const item of validItems) {
      const key = String(item.product_code || "") + "|" + item.product_name;
      const p = productMap.get(key) || {code:item.product_code,name:item.product_name,quantity:0,gross:0,discount:0,net:0};
      p.quantity += Number(item.quantity);
      p.gross += money(item.gross_total);
      p.discount += money(item.discount_total);
      p.net += money(item.net_total);
      productMap.set(key,p);
    }
    const productRows = Array.from(productMap.values()).sort((a,b)=>b.quantity-a.quantity || a.name.localeCompare(b.name,"it"));
    const byCashier = new Map();
    for (const sale of valid) {
      const v = byCashier.get(sale.username) || {count:0,total:0,cash:0,pos:0};
      v.count++;
      v.total += money(sale.total);
      v[sale.payment_method==="Contanti"?"cash":"pos"] += money(sale.total);
      byCashier.set(sale.username,v);
    }
    const itemsBySale = new Map();
    for (const item of itemsResult.rows) {
      if (!itemsBySale.has(String(item.sale_id))) itemsBySale.set(String(item.sale_id),[]);
      itemsBySale.get(String(item.sale_id)).push(item);
    }

    const doc = new PDFDocument({
      size:"A4",margin:42,bufferPages:true,
      info:{Title:"Resoconto cassa #" + cash.daily_number + " - " + new Date(cash.opened_at).toLocaleDateString("it-IT"),Author:"Cinematta POS"}
    });
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition",'attachment; filename="resoconto-cassa-' + id + '.pdf"');
    doc.pipe(res);

    const left=42, right=553, width=511;
    const navy="#172B46", muted="#5C6878", line="#D7DEE6", pale="#F2F5F8", paleBlue="#EAF0F6", red="#A83232";
    const rule=y=>doc.moveTo(left,y).lineTo(right,y).lineWidth(.65).strokeColor(line).stroke();
    const ensure=height=>{if(doc.y+height>748) doc.addPage();};
    const section=label=>{
      ensure(35);
      doc.moveDown(.45);
      doc.font("Helvetica-Bold").fontSize(11).fillColor(navy).text(label,left,doc.y,{width});
      rule(doc.y+5);
      doc.y+=17;
    };
    const cell=(value,x,y,w,opts={})=>{
      doc.font(opts.bold?"Helvetica-Bold":"Helvetica").fontSize(opts.size||8).fillColor(opts.color||"#263445")
        .text(String(value==null?"—":value),x,y,{width:w,align:opts.align||"left",lineBreak:false,ellipsis:true});
    };
    const tableHeader=(labels,widths)=>{
      ensure(25);
      const y=doc.y;
      doc.rect(left,y,width,21).fill(navy);
      let x=left;
      labels.forEach((label,i)=>{cell(label,x+5,y+6,widths[i]-10,{bold:true,size:7,color:"#FFFFFF",align:i===0?"left":"right"});x+=widths[i];});
      doc.y=y+25;
    };
    const tableRow=(values,widths,opts={})=>{
      const h=opts.height||22;
      ensure(h+3);
      const y=doc.y;
      if(opts.fill) doc.rect(left,y,width,h).fill(opts.fill);
      let x=left;
      values.forEach((value,i)=>{cell(value,x+5,y+6,widths[i]-10,{bold:!!opts.bold,size:opts.size||7.5,color:opts.color,align:i===0?"left":"right"});x+=widths[i];});
      doc.y=y+h;
      if(opts.rule!==false) rule(doc.y);
    };
    const keyValue=(label,value,x,y,w)=>{
      doc.roundedRect(x,y,w,34,3).fill(pale);
      cell(label.toUpperCase(),x+8,y+6,w-16,{size:6.8,color:muted});
      cell(value,x+8,y+18,w-16,{size:9,bold:true,color:navy});
    };

    doc.rect(0,0,595,88).fill(navy);
    doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(19).text("CINEMATTA POS",left,19);
    doc.font("Helvetica").fontSize(10).fillColor("#E0E8F1").text("RESOCONTO DI CASSA",left,46);
    doc.font("Helvetica-Bold").fontSize(15).fillColor("#FFFFFF").text("CASSA #" + cash.daily_number,390,27,{width:163,align:"right"});
    doc.y=104;
    doc.font("Helvetica-Bold").fontSize(15).fillColor(navy).text("Resoconto di Cassa",left,doc.y);
    doc.moveDown(.25);
    doc.font("Helvetica").fontSize(8).fillColor(muted).text("Generato il " + date(new Date()),left,doc.y);
    doc.moveDown(.7);

    section("Dati della sessione");
    const meta=[
      ["Data apertura",date(cash.opened_at)],
      ["Data chiusura",cash.closed_at?date(cash.closed_at):"Cassa ancora aperta"],
      ["Cassiere apertura",cash.opened_by_name||"Non registrato"],
      ["Cassiere chiusura",cash.closed_by_name||"—"],
      ["Fondo cassa iniziale",euro(openingFund)],
      ["Durata sessione",cash.closed_at?Math.max(0,Math.round((new Date(cash.closed_at)-new Date(cash.opened_at))/60000))+" minuti":"In corso"]
    ];
    for(let i=0;i<meta.length;i+=2){
      const y=doc.y;
      keyValue(meta[i][0],meta[i][1],left,y,250);
      if(meta[i+1]) keyValue(meta[i+1][0],meta[i+1][1],left+261,y,250);
      doc.y=y+40;
    }

    section("Riepilogo");
    const summary=[
      ["Fondo iniziale",euro(openingFund)],
      ["Incasso contanti",euro(cashTotal)],
      ["Incasso POS",euro(posTotal)],
      ["Incasso totale",euro(total)],
      ["Sconti concessi",euro(discountTotal)],
      ["Fondo contanti previsto",euro(expectedCash)],
      ["Transazioni valide",String(valid.length)],
      ["Transazioni annullate",String(voided.length)],
      ["Scontrino medio",euro(avgTicket)]
    ];
    const sumW=width/3;
    for(let i=0;i<summary.length;i+=3){
      const y=doc.y;
      for(let j=0;j<3;j++) if(summary[i+j]) keyValue(summary[i+j][0],summary[i+j][1],left+j*(sumW+0.5),y,sumW-5);
      doc.y=y+40;
    }
    doc.font("Helvetica").fontSize(7).fillColor(muted).text("Il fondo contanti previsto è calcolato sommando il fondo iniziale agli incassi in contanti registrati; non rappresenta una verifica fisica del denaro presente.",left,doc.y,{width});
    doc.moveDown(.5);

    section("Prodotti venduti");
    if(!productRows.length) {
      doc.font("Helvetica").fontSize(8).fillColor(muted).text("Nessun prodotto venduto.",left,doc.y);
      doc.moveDown();
    } else {
      const widths=[155,52,76,72,76,80];
      tableHeader(["Articolo","Quantità","Prezzo medio","Lordo","Sconti","Incasso"],widths);
      for(const p of productRows){
        const avg=p.quantity?p.gross/p.quantity:0;
        tableRow([p.name,String(p.quantity),euro(avg),euro(p.gross),euro(p.discount),euro(p.net)],widths);
      }
      tableRow(["TOTALE",String(validItems.reduce((v,x)=>v+Number(x.quantity),0)),"",euro(grossTotal),euro(discountTotal),euro(total)],widths,{bold:true,fill:paleBlue,height:24});
    }

    section("Riepilogo per metodo di pagamento");
    const payWidths=[150,120,120,121];
    tableHeader(["Metodo","Transazioni","Incasso","Incidenza"],payWidths);
    const pct=v=>total?((v/total)*100).toLocaleString("it-IT",{maximumFractionDigits:1})+"%":"0%";
    tableRow(["Contanti",String(cashSales.length),euro(cashTotal),pct(cashTotal)],payWidths);
    tableRow(["POS",String(posSales.length),euro(posTotal),pct(posTotal)],payWidths);
    tableRow(["TOTALE",String(valid.length),euro(total),pct(total)],payWidths,{bold:true,fill:paleBlue,height:24});

    section("Riepilogo per cassiere");
    if(!byCashier.size) doc.font("Helvetica").fontSize(8).fillColor(muted).text("Nessuna transazione valida.",left,doc.y);
    else {
      const widths=[150,100,100,80,81];
      tableHeader(["Cassiere","Transazioni","Incasso","Contanti","POS"],widths);
      for(const [username,v] of byCashier) tableRow([username,String(v.count),euro(v.total),euro(v.cash),euro(v.pos)],widths);
    }

    section("Dettaglio transazioni");
    if(!sales.length) {
      doc.font("Helvetica").fontSize(8).fillColor(muted).text("Nessuna transazione registrata.",left,doc.y);
    }
    for(const sale of sales){
      const saleItems=itemsBySale.get(String(sale.id))||[];
      const cancelled=!!sale.voided_at;
      ensure(75);
      const y=doc.y;
      doc.roundedRect(left,y,width,Math.max(62,48+saleItems.length*15+(cancelled?18:0)),3).fill(cancelled?"#FFF1F0":pale);
      cell("TRANSAZIONE #" + sale.id,left+9,y+8,170,{bold:true,size:9,color:cancelled?red:navy});
      cell(date(sale.created_at),left+180,y+9,205,{size:7.5,color:muted});
      cell(sale.payment_method,left+390,y+8,110,{bold:true,size:8,align:"right"});
      cell("Cassiere: " + sale.username,left+9,y+25,245,{size:7.5});
      cell("Totale: " + euro(sale.total),left+260,y+25,240,{bold:true,size:8,align:"right"});
      let iy=y+43;
      for(const item of saleItems){
        const lineLabel=item.product_name+" · "+item.quantity+" × "+euro(item.unit_price)+" · sconto "+money(item.discount_percent).toLocaleString("it-IT")+"%";
        cell(lineLabel,left+14,iy,365,{size:7,color:"#39485A"});
        cell(euro(item.net_total),left+390,iy,105,{size:7,bold:true,align:"right"});
        iy+=15;
      }
      if(cancelled) {
        cell("ANNULLATA il " + date(sale.voided_at) + " · Motivo: " + (sale.void_reason||"Non specificato"),left+9,iy+2,width-18,{bold:true,size:7,color:red});
        iy+=17;
      }
      doc.y=Math.max(iy+7,y+62);
      rule(doc.y-3);
    }

    section("Controllo di chiusura");
    const closeRows=[
      ["Contanti registrati alla chiusura",cash.closed_at?euro(closingCashSales):"Cassa ancora aperta"],
      ["POS registrato alla chiusura",cash.closed_at?euro(closingPosSales):"Cassa ancora aperta"],
      ["Fondo contanti previsto (fondo iniziale + contanti)",euro(expectedCash)],
      ["Incasso complessivo registrato",euro(total)]
    ];
    for(const row of closeRows){
      ensure(19);
      cell(row[0],left,doc.y,width-130,{size:8});
      cell(row[1],left+width-125,doc.y,125,{size:8,bold:true,align:"right"});
      doc.y+=16;
    }

    const range=doc.bufferedPageRange();
    for(let i=0;i<range.count;i++){
      doc.switchToPage(range.start+i);
      doc.moveTo(left,780).lineTo(right,780).lineWidth(.6).strokeColor(line).stroke();
      doc.fillColor(muted).font("Helvetica").fontSize(7).text("Cinematta POS · Cassa #" + cash.daily_number + " · " + new Date(cash.opened_at).toLocaleDateString("it-IT"),left,788,{width:350});
      doc.text("Pagina " + (i+1) + " di " + range.count,left+350,788,{width:161,align:"right"});
    }
    doc.end();
  } catch(err) { next(err); }
});
app.get("/api/reports/:id.csv", auth, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Cassa non valida." });
    const params = [id];
    let ownerFilter = "";
    if (req.user.role === "operatore") {
      params.push(req.user.id);
      ownerFilter = "AND s.user_id=$2";
    }
    const r = await pool.query(`
      SELECT s.id AS sale_id,s.created_at,s.payment_method,s.total,
             u.username,si.product_code,si.product_name,si.quantity,si.unit_price,si.discount_percent
      FROM sales s
      JOIN sale_items si ON si.sale_id=s.id
      JOIN app_users u ON u.id=s.user_id
      WHERE s.cash_session_id=$1 AND s.voided_at IS NULL ${ownerFilter}
      ORDER BY s.created_at,s.id,si.id
    `, params);
    const session = await pool.query("SELECT id FROM cash_sessions WHERE id=$1", [id]);
    if (!session.rowCount) return res.status(404).json({ error: "Cassa non trovata." });
    const quote = value => '"' + String(value ?? "").replace(/"/g, '""') + '"';
    const rows = [["Vendita","Data","Cassiere","Pagamento","Codice","Prodotto","Quantità","Prezzo unitario","Sconto %","Totale riga"]];
    for (const x of r.rows) {
      const lineTotal = Number(x.unit_price) * Number(x.quantity) * (1 - Number(x.discount_percent) / 100);
      rows.push([x.sale_id,new Date(x.created_at).toISOString(),x.username,x.payment_method,x.product_code,x.product_name,x.quantity,x.unit_price,x.discount_percent,lineTotal.toFixed(2)]);
    }
    const csv = "\uFEFF" + rows.map(row => row.map(quote).join(";")).join("\r\n");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="resoconto-cassa-${id}.csv"`);
    res.send(csv);
  } catch (err) { next(err); }
});

app.delete("/api/admin/reports/:id", auth, adminOnly, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Cassa non valida." });
    await client.query("BEGIN");
    const session = await client.query("SELECT id,closed_at FROM cash_sessions WHERE id=$1 FOR UPDATE", [id]);
    if (!session.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Resoconto non trovato." }); }
    if (!session.rows[0].closed_at) { await client.query("ROLLBACK"); return res.status(409).json({ error: "Non puoi eliminare una cassa ancora aperta." }); }
    await client.query("DELETE FROM sale_items WHERE sale_id IN (SELECT id FROM sales WHERE cash_session_id=$1)", [id]);
    await client.query("DELETE FROM sales WHERE cash_session_id=$1", [id]);
    await client.query("DELETE FROM cash_sessions WHERE id=$1", [id]);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) { await client.query("ROLLBACK").catch(() => {}); next(err); }
  finally { client.release(); }
});

app.get("/api/admin/users", auth, adminOnly, async (req, res, next) => {
  try {
    const r = await pool.query("SELECT id,username,role,active,created_at FROM app_users ORDER BY created_at DESC");
    res.json({ users: r.rows });
  } catch (err) { next(err); }
});
app.post("/api/admin/users", auth, adminOnly, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const role = ["admin","operatore","resocontista"].includes(req.body.role) ? req.body.role : "operatore";
    if (!/^[a-z0-9._-]{3,32}$/.test(username)) return res.status(400).json({ error: "Username: 3-32 caratteri, lettere, numeri, punto, trattino o underscore." });
    if (password.length < 12) return res.status(400).json({ error: "La password deve avere almeno 12 caratteri." });
    const hash = await bcrypt.hash(password, 12);
    await pool.query("INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,$3)", [username, hash, role]);
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Username già esistente." });
    next(err);
  }
});
app.patch("/api/admin/users/:id", auth, adminOnly, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const active = Boolean(req.body.active);
    if (id === req.user.id && !active) return res.status(400).json({ error: "Non puoi disattivare il tuo account mentre lo stai usando." });
    const r = await pool.query("UPDATE app_users SET active=$2 WHERE id=$1 RETURNING id", [id, active]);
    if (!r.rowCount) return res.status(404).json({ error: "Account non trovato." });
    if (!active) await pool.query("DELETE FROM user_sessions WHERE user_id=$1", [id]);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.delete("/api/admin/users/:id",auth,adminOnly,async(req,res,next)=>{
 try{
  const id=Number(req.params.id);if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Account non valido."});
  if(id===req.user.id)return res.status(400).json({error:"Non puoi eliminare l'account che stai usando."});
  const refs=await pool.query("SELECT EXISTS(SELECT 1 FROM sales WHERE user_id=$1) OR EXISTS(SELECT 1 FROM cash_sessions WHERE opened_by=$1 OR closed_by=$1) AS has_history",[id]);
  if(refs.rows[0]?.has_history)return res.status(409).json({error:"Account con attività nello storico: disattivalo per conservare la tracciabilità."});
  const r=await pool.query("DELETE FROM app_users WHERE id=$1 RETURNING id",[id]);if(!r.rowCount)return res.status(404).json({error:"Account non trovato."});
  res.json({ok:true});
 }catch(err){next(err);}
});

app.get("/api/admin/cash-sessions", auth, adminOnly, async (req, res, next) => {
  try {
    const r = await pool.query(`
      SELECT c.id,c.opened_at,c.closed_at,c.opening_fund,c.closing_cash,c.closing_pos,
              (SELECT COUNT(*) FROM cash_sessions c2 WHERE (c2.opened_at AT TIME ZONE 'Europe/Rome')::date = (c.opened_at AT TIME ZONE 'Europe/Rome')::date AND (c2.opened_at,c2.id) <= (c.opened_at,c.id))::int AS daily_number,
             COALESCE(SUM(s.total) FILTER (WHERE s.voided_at IS NULL),0)::numeric(12,2) AS revenue,
             COUNT(s.id) FILTER (WHERE s.voided_at IS NULL)::int AS transactions,
             opener.username AS opened_by_name, closer.username AS closed_by_name
      FROM cash_sessions c
      LEFT JOIN sales s ON s.cash_session_id=c.id
      LEFT JOIN app_users opener ON opener.id=c.opened_by
      LEFT JOIN app_users closer ON closer.id=c.closed_by
      GROUP BY c.id,opener.username,closer.username
      ORDER BY c.id DESC LIMIT 100
    `);
    res.json({ cashSessions: r.rows });
  } catch (err) { next(err); }
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Errore interno del server." });
});

initDb().then(() => {
  app.listen(PORT, () => console.log(`Cinematta POS attivo sulla porta ${PORT}`));
}).catch(err => {
  console.error("Errore inizializzazione:", err);
  process.exit(1);
});
