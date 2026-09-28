require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const { body, validationResult } = require("express-validator");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const q = (t, p) => pool.query(t, p);            // parameterised queries only: no SQL injection
const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL }));
app.use(express.json({ limit: "100kb" }));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60e3, max: 30 }));

/* ---------- helpers ---------- */
const sign = u => jwt.sign({ id: u.id, role: u.role }, process.env.JWT_SECRET, { expiresIn: "2h" });
const audit = (req, action, entity, id) =>
  q("INSERT INTO audit_logs(user_id,action,entity,entity_id,ip) VALUES($1,$2,$3,$4,$5)",
    [req.user?.id ?? null, action, entity, id ?? null, req.ip]);
const notify = (uid, msg) => q("INSERT INTO notifications(user_id,message) VALUES($1,$2)", [uid, msg]);
const check = (req, res, next) => {
  const e = validationResult(req);
  return e.isEmpty() ? next() : res.status(422).json({ errors: e.array() });
};
const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Sign in again" }); }
};
const allow = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: "Not allowed for your role" });
const emi = (p, r, m) => { const i = r / 1200; return p * i * (1 + i) ** m / ((1 + i) ** m - 1); };

/* ---------- auth ---------- */
app.post("/api/auth/register",
  body("email").isEmail().normalizeEmail(), body("password").isLength({ min: 8 }),
  body("full_name").trim().escape().notEmpty(), check,
  async (req, res) => {
    const { email, password, full_name, phone } = req.body;
    const hash = await bcrypt.hash(password, 12);
    try {
      const r = await q(`INSERT INTO users(role_id,full_name,email,phone,password_hash)
        VALUES((SELECT id FROM roles WHERE name='applicant'),$1,$2,$3,$4) RETURNING id`, [full_name, email, phone, hash]);
      res.status(201).json({ id: r.rows[0].id });
    } catch { res.status(409).json({ error: "Email already registered" }); }
  });

app.post("/api/auth/login", body("email").isEmail(), body("password").notEmpty(), check, async (req, res) => {
  const r = await q(`SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id=u.role_id WHERE email=$1 AND active`, [req.body.email]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(req.body.password, u.password_hash))) return res.status(401).json({ error: "Wrong email or password" });
  req.user = u; audit(req, "login", "user", u.id);
  res.json({ token: sign(u), role: u.role, name: u.full_name });
});

/* ---------- applications ---------- */
app.post("/api/applications", auth, allow("applicant"),
  body("product_id").isInt(), body("amount").isFloat({ min: 10000 }),
  body("months").isInt({ min: 6, max: 360 }), body("monthly_income").isFloat({ gt: 0 }),
  body("liabilities").optional().isFloat({ min: 0 }), check,
  async (req, res) => {
    const b = req.body;
    const r = await q(`INSERT INTO loan_applications(applicant_id,product_id,dob,gender,address,employment_status,employer,
      monthly_income,liabilities,amount,purpose,months,preferred_emi) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
      [req.user.id, b.product_id, b.dob, b.gender, b.address, b.employment_status, b.employer,
       b.monthly_income, b.liabilities || 0, b.amount, b.purpose, b.months, b.preferred_emi]);
    await audit(req, "application submitted", "application", r.rows[0].id);
    await notify(req.user.id, `Application #${r.rows[0].id} submitted`);
    res.status(201).json({ id: r.rows[0].id, status: "Submitted" });
  });

app.get("/api/applications", auth, async (req, res) => {
  const { status, product_id, from, to, name, min_amount, min_risk, page = 1 } = req.query;
  const w = [], p = [];
  const add = (sql, v) => { p.push(v); w.push(sql.replace("?", "$" + p.length)); };
  if (req.user.role === "applicant") add("a.applicant_id = ?", req.user.id);
  if (status) add("a.status = ?", status);
  if (product_id) add("a.product_id = ?", product_id);
  if (from) add("a.created_at >= ?", from);
  if (to) add("a.created_at <= ?", to);
  if (name) add("u.full_name ILIKE ?", `%${name}%`);
  if (min_amount) add("a.amount >= ?", min_amount);
  if (min_risk) add("ca.risk_score >= ?", min_risk);
  p.push(10, (Math.max(1, +page) - 1) * 10);
  const r = await q(`SELECT a.id,u.full_name,lp.name AS product,a.amount,a.months,a.status,a.created_at,ca.risk_score
    FROM loan_applications a JOIN users u ON u.id=a.applicant_id JOIN loan_products lp ON lp.id=a.product_id
    LEFT JOIN LATERAL (SELECT risk_score FROM credit_assessments WHERE application_id=a.id ORDER BY id DESC LIMIT 1) ca ON TRUE
    ${w.length ? "WHERE " + w.join(" AND ") : ""} ORDER BY a.created_at DESC LIMIT $${p.length - 1} OFFSET $${p.length}`, p);
  res.json(r.rows);
});

/* ---------- documents (type and size checked, random stored name) ---------- */
const upload = multer({
  storage: multer.diskStorage({
    destination: process.env.UPLOAD_DIR || "uploads",
    filename: (_r, f, cb) => cb(null, crypto.randomUUID() + path.extname(f.originalname).toLowerCase())
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_r, f, cb) => cb(null, ["application/pdf", "image/jpeg", "image/png"].includes(f.mimetype))
});
app.post("/api/applications/:id/documents", auth, allow("applicant"), upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Upload a PDF, JPG or PNG under 5 MB" });
  const own = await q("SELECT 1 FROM loan_applications WHERE id=$1 AND applicant_id=$2", [req.params.id, req.user.id]);
  if (!own.rowCount) return res.status(404).json({ error: "Application not found" });
  await q("INSERT INTO documents(application_id,doc_type,file_name,stored_path,mime) VALUES($1,$2,$3,$4,$5)",
    [req.params.id, req.body.doc_type || "Additional", req.file.originalname, req.file.path, req.file.mimetype]);
  await audit(req, "document uploaded", "application", +req.params.id);
  res.status(201).json({ ok: true });
});

/* ---------- workflow engine ---------- */
const TRANSITIONS = {   // action: [role, from, to]
  start_verification: ["officer", "Submitted", "Under Verification"],
  forward:            ["officer", "Under Verification", "Credit Assessment"],
  approve:            ["manager", "Credit Assessment", "Approved"],
  reject:             ["manager", "Credit Assessment", "Rejected"],
  disburse:           ["manager", "Approved", "Disbursed"],
  close:              ["manager", "Disbursed", "Closed"]
};
app.post("/api/applications/:id/:action", auth, async (req, res, next) => {
  const t = TRANSITIONS[req.params.action];
  if (!t) return next();
  if (![t[0], "admin"].includes(req.user.role)) return res.status(403).json({ error: "Not allowed for your role" });
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const a = (await c.query("SELECT * FROM loan_applications WHERE id=$1 FOR UPDATE", [req.params.id])).rows[0];
    if (!a) { await c.query("ROLLBACK"); return res.status(404).json({ error: "Not found" }); }
    if (a.status !== t[1]) { await c.query("ROLLBACK"); return res.status(409).json({ error: `Application is ${a.status}, not ${t[1]}` }); }
    if (["approve", "reject"].includes(req.params.action)) {
      const ca = await c.query("SELECT 1 FROM credit_assessments WHERE application_id=$1", [a.id]);
      if (!ca.rowCount) { await c.query("ROLLBACK"); return res.status(409).json({ error: "Credit assessment required first" }); }
      await c.query("INSERT INTO approvals(application_id,approver_id,decision,comment) VALUES($1,$2,$3,$4)",
        [a.id, req.user.id, t[2], req.body.comment]);
    }
    await c.query("UPDATE loan_applications SET status=$1, updated_at=now() WHERE id=$2", [t[2], a.id]);
    await c.query("COMMIT");
    await audit(req, `status → ${t[2]}`, "application", a.id);
    await notify(a.applicant_id, `Application #${a.id} is now ${t[2]}`);
    res.json({ status: t[2] });
  } catch (e) { await c.query("ROLLBACK"); next(e); } finally { c.release(); }
});

app.post("/api/applications/:id/request-documents", auth, allow("officer"), body("message").trim().notEmpty(), check, async (req, res) => {
  const r = await q("UPDATE loan_applications SET docs_requested=$1 WHERE id=$2 RETURNING applicant_id", [req.body.message, req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: "Not found" });
  await notify(r.rows[0].applicant_id, `Documents requested for #${req.params.id}: ${req.body.message}`);
  await audit(req, "documents requested", "application", +req.params.id);
  res.json({ ok: true });
});

app.post("/api/applications/:id/assess", auth, allow("analyst"), async (req, res) => {
  const r = await q(`SELECT a.*, lp.annual_rate FROM loan_applications a JOIN loan_products lp ON lp.id=a.product_id
    WHERE a.id=$1 AND a.status='Credit Assessment'`, [req.params.id]);
  const a = r.rows[0];
  if (!a) return res.status(409).json({ error: "Application is not in Credit Assessment" });
  const dti = (+a.liabilities + emi(+a.amount, +a.annual_rate, a.months)) / +a.monthly_income;
  const risk = Math.max(5, Math.min(98, Math.round(dti * 85 + (a.amount / (a.monthly_income * 12)) * 6)));
  const rec = risk < 50 ? "Approve" : "Reject";
  await q("INSERT INTO credit_assessments(application_id,analyst_id,risk_score,recommendation,notes) VALUES($1,$2,$3,$4,$5)",
    [a.id, req.user.id, risk, rec, req.body.notes]);
  await audit(req, `risk score ${risk}`, "application", a.id);
  res.json({ risk_score: risk, recommendation: rec });
});

/* ---------- notifications, admin ---------- */
app.get("/api/notifications", auth, async (req, res) =>
  res.json((await q("SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50", [req.user.id])).rows));

app.get("/api/admin/audit-logs", auth, allow("admin"), async (_req, res) =>
  res.json((await q("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200")).rows));

app.get("/api/admin/metrics", auth, allow("manager", "admin"), async (_req, res) =>
  res.json((await q(`SELECT status, COUNT(*)::int AS count, COALESCE(SUM(amount),0) AS volume
    FROM loan_applications GROUP BY status`)).rows));

app.use((e, _req, res, _next) => { console.error(e); res.status(500).json({ error: "Something went wrong" }); });
app.listen(process.env.PORT || 4000, () => console.log("API ready"));
