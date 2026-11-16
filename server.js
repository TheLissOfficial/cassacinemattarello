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
const productByCode = new Map(products.map(p => [p.code, p]));

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

  const open = await pool.query("SELECT id FROM cash_sessions WHERE closed_at IS NULL ORDER BY id DESC LIMIT 1");
  if (!open.rowCount) {
    await pool.query("INSERT INTO cash_sessions(opening_fund) VALUES(250.00)");
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
  if (r.rowCount) return r.rows[0];
  const created = await client.query("INSERT INTO cash_sessions(opening_fund) VALUES(250.00) RETURNING *");
  return created.rows[0];
}

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
app.get("/api/health", (req, res) => res.json({ ok: true }));

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
      SELECT product_code AS code, product_name AS name, SUM(quantity)::int AS quantity
      FROM sale_items
      JOIN sales s ON s.id=si.sale_id
      WHERE product_code IS NOT NULL AND s.voided_at IS NULL
      GROUP BY product_code, product_name
      ORDER BY SUM(quantity) DESC, product_name ASC
    `);
    res.json({ ranking: r.rows });
  } catch (err) { next(err); }
});

app.get("/api/sales/current", auth, cashierOnly, async (req, res, next) => {
  try {
    let cash = await activeCashSession();
    const assigned = await pool.query("UPDATE cash_sessions SET opened_by=COALESCE(opened_by,$2) WHERE id=$1 RETURNING *", [cash.id, req.user.id]);
    cash = assigned.rows[0];
    const totals = await pool.query(`
      SELECT
        COALESCE(SUM(total),0)::numeric(12,2) AS revenue,
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
    await client.query("UPDATE cash_sessions SET opened_by=COALESCE(opened_by,$2) WHERE id=$1", [cash.id, req.user.id]);
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
    await client.query("INSERT INTO cash_sessions(opened_by,opening_fund) VALUES($1,250.00)", [req.user.id]);
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
    const session = await pool.query("SELECT c.id,c.opened_at,c.closed_at,c.opening_fund,c.closing_cash,c.closing_pos,opener.username AS opened_by_name,closer.username AS closed_by_name FROM cash_sessions c LEFT JOIN app_users opener ON opener.id=c.opened_by LEFT JOIN app_users closer ON closer.id=c.closed_by WHERE c.id=$1", [id]);
    if (!session.rowCount) return res.status(404).json({ error: "Cassa non trovata." });
    const rows = await pool.query(`
      SELECT s.id,s.created_at,s.payment_method,s.total,s.voided_at,s.void_reason,u.username,
             COALESCE(string_agg(si.product_name || ' x ' || si.quantity || ' @ EUR ' || si.unit_price || ' sconto ' || si.discount_percent || '%', ', ' ORDER BY si.id), '') AS items
      FROM sales s JOIN app_users u ON u.id=s.user_id
      LEFT JOIN sale_items si ON si.sale_id=s.id
      WHERE s.cash_session_id=$1 ${ownerFilter}
      GROUP BY s.id,u.username ORDER BY s.created_at,s.id
    `, params);
    const cash = session.rows[0];
    const valid = rows.rows.filter(x => !x.voided_at);
    const total = valid.reduce((sum,x) => sum + Number(x.total),0);
    const byCashier = new Map();
    for (const sale of valid) {
      const v = byCashier.get(sale.username) || {count:0,total:0};
      v.count++; v.total += Number(sale.total); byCashier.set(sale.username,v);
    }
    const euro = value => new Intl.NumberFormat("it-IT",{style:"currency",currency:"EUR"}).format(Number(value || 0));
    const date = value => value ? new Date(value).toLocaleString("it-IT") : "—";
    const doc = new PDFDocument({size:"A4",margin:44,bufferPages:true,info:{Title:"Resoconto cassa #"+id,Author:"Cinematta POS"}});
    doc.on("pageAdded",()=>{doc.save();doc.rect(0,0,595,48).fill("#14243A");doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(10).text("CINEMATTA  ·  RESOCONTO CASSA #"+id,44,18);doc.restore();doc.y=62;});
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition",`attachment; filename="resoconto-cassa-${id}.pdf"`);
    doc.pipe(res);
    const left=44, right=551, width=507;
    const rule=(y)=>{doc.moveTo(left,y).lineTo(right,y).lineWidth(.7).strokeColor("#D7DEE8").stroke();};
    const section=(label)=>{
      if(doc.y>700) doc.addPage();
      doc.moveDown(.5); doc.font("Helvetica-Bold").fontSize(11).fillColor("#183153").text(label.toUpperCase(),left,doc.y,{width});
      const y=doc.y+5; rule(y); doc.y=y+12;
    };
    const header=()=>{
      doc.save();
      doc.rect(0,0,595,92).fill("#14243A");
      doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(19).text("CINEMATTA",left,24);
      doc.font("Helvetica").fontSize(9).fillColor("#D8E3F0").text("REPORT CASSA  ·  DOCUMENTO DI RIEPILOGO",left,52);
      doc.font("Helvetica-Bold").fontSize(17).fillColor("#FFFFFF").text("#"+id,460,32,{width:90,align:"right"});
      doc.restore();
      doc.y=112;
    };
    header();
    doc.fillColor("#17243A").font("Helvetica-Bold").fontSize(16).text("Resoconto della cassa");
    doc.moveDown(.2).fillColor("#66758A").font("Helvetica").fontSize(9).text("Generato il "+date(new Date()));
    section("Dati della sessione");
    const meta=[
      ["Apertura",date(cash.opened_at)],["Cassiere apertura",cash.opened_by_name||"Non registrato"],
      ["Chiusura",cash.closed_at?date(cash.closed_at):"Sessione ancora aperta"],["Cassiere chiusura",cash.closed_by_name||"—"],
      ["Fondo iniziale",euro(cash.opening_fund)]
    ];
    if(req.user.role!=="operatore") meta.push(["Contanti a chiusura",euro(cash.closing_cash)],["POS a chiusura",euro(cash.closing_pos)]);
    meta.forEach((item,i)=>{
      const col=i%2, row=Math.floor(i/2), x=left+col*258, y=doc.y+row*39;
      doc.roundedRect(x,y,246,32,4).fill("#F1F5F9");
      doc.fillColor("#68778B").font("Helvetica").fontSize(7.5).text(item[0].toUpperCase(),x+9,y+5,{width:225});
      doc.fillColor("#17243A").font("Helvetica-Bold").fontSize(9).text(item[1],x+9,y+16,{width:225});
    });
    doc.y += Math.ceil(meta.length/2)*39+5;
    section("Riepilogo economico");
    const stats=[["Transazioni valide",String(valid.length)],["Transazioni annullate",String(rows.rows.length-valid.length)],["Incasso valido",euro(total)]];
    const statW=width/3;
    stats.forEach((v,i)=>{
      const x=left+i*statW;
      doc.roundedRect(x+2,doc.y,statW-8,48,4).fill("#EAF0F7");
      doc.fillColor("#65758A").font("Helvetica").fontSize(7.5).text(v[0].toUpperCase(),x+10,doc.y+8,{width:statW-20});
      doc.fillColor("#183153").font("Helvetica-Bold").fontSize(i===2?12:13).text(v[1],x+10,doc.y+23,{width:statW-20});
    });
    doc.y+=60;
    section("Riepilogo per cassiere");
    if(!byCashier.size) doc.font("Helvetica").fontSize(9).fillColor("#596579").text("Nessuna transazione valida.");
    for(const [username,v] of byCashier){
      doc.font("Helvetica-Bold").fontSize(9).fillColor("#17243A").text(username,left,doc.y,{continued:true});
      doc.font("Helvetica").fillColor("#596579").text("   ·   "+v.count+" transazioni   ·   "+euro(v.total));
    }
    section("Dettaglio transazioni");
    if(!rows.rows.length) doc.font("Helvetica").fontSize(9).fillColor("#596579").text("Nessuna transazione registrata.");
    for(const sale of rows.rows){
      const detail=(sale.items||"Articoli non disponibili");
      const estimated=78+doc.heightOfString(detail,{width:width-18,fontSize:8.2})+((sale.voided_at)?24:0);
      if(doc.y+estimated>745) doc.addPage();
      const y=doc.y;
      doc.roundedRect(left,y,width,Math.min(estimated,180),4).fill(sale.voided_at?"#FFF1F0":"#F4F7FA");
      doc.fillColor("#17243A").font("Helvetica-Bold").fontSize(9).text("Vendita #"+sale.id,left+10,y+8,{width:150});
      doc.font("Helvetica").fontSize(8).fillColor("#4E5D70").text(date(sale.created_at)+"   ·   "+sale.payment_method,left+155,y+8,{width:width-175,align:"right"});
      doc.fillColor("#17243A").font("Helvetica-Bold").fontSize(9).text(euro(sale.total),left+10,y+24,{width:width-20,align:"right"});
      doc.font("Helvetica").fontSize(8.2).fillColor("#35445A").text("Cassiere: "+sale.username,left+10,y+25,{width:width-100});
      doc.font("Helvetica").fontSize(8.2).fillColor("#35445A").text("Articoli: "+detail,left+10,y+43,{width:width-20});
      if(sale.voided_at) doc.font("Helvetica-Bold").fontSize(7.8).fillColor("#A83232").text("ANNULLATA · "+date(sale.voided_at)+" · Motivo: "+(sale.void_reason||"—"),left+10,doc.y+4,{width:width-20});
      doc.y=y+estimated+7;
    }
    const range=doc.bufferedPageRange();
    for(let i=0;i<range.count;i++){
      doc.switchToPage(range.start+i);
      doc.moveTo(left,780).lineTo(right,780).lineWidth(.6).strokeColor("#D7DEE8").stroke();
      doc.fillColor("#778397").font("Helvetica").fontSize(8).text("Documento gestionale · Cassa #"+id,left,788,{width:330});
      doc.text("Pagina "+(i+1)+" di "+range.count,left+350,788,{width:157,align:"right"});
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
    const rows = [["Vendita","Data","Operatore","Pagamento","Codice","Prodotto","Quantità","Prezzo unitario","Sconto %","Totale riga"]];
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
app.get("/api/admin/cash-sessions", auth, adminOnly, async (req, res, next) => {
  try {
    const r = await pool.query(`
      SELECT c.id,c.opened_at,c.closed_at,c.opening_fund,c.closing_cash,c.closing_pos,
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
