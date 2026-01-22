require("dotenv").config();

// app.js
const express = require("express");
const sql = require("mssql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

/* ---------------------------------------------
   CORS
--------------------------------------------- */
const corsOptions = {
  origin: function (origin, callback) {
    // Postman / server-to-server
    if (!origin) return callback(null, true);

    // Local dev
    if (origin === "http://localhost:5173") return callback(null, true);

    // Allow your Netlify domain + any Netlify deploy subdomains
    if (/^https:\/\/(.+\.)?lottii\.netlify\.app$/.test(origin)) return callback(null, true);

    return callback(null, false);
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(express.json());

/* ---------------------------------------------
   DATABASE CONFIG (Azure SQL)
--------------------------------------------- */
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  server: process.env.DB_HOST,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT) || 1433,

  // ✅ Important for Azure / cold starts / transient network hiccups
  connectionTimeout: 60000,
  requestTimeout: 60000,

  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000,
  },

  options: {
    encrypt: true,
    enableArithAbort: true,
  },
};

// ✅ Reconnect-on-demand pool (prevents "stuck null pool" after one failure)
let pool = null;
let poolConnecting = null;

async function getPoolOr503(res) {
  try {
    if (pool) return pool;

    if (poolConnecting) {
      pool = await poolConnecting;
      return pool;
    }

    poolConnecting = new sql.ConnectionPool(dbConfig).connect();
    pool = await poolConnecting;

    console.log("✅ Connected to Azure SQL");
    return pool;
  } catch (err) {
    console.error("❌ DB connection failed:", err);

    // allow retry on next request
    pool = null;
    poolConnecting = null;

    if (res) {
      res.status(503).json({
        message: "Базата данни не е налична (DB not ready)",
        hint: err?.code || err?.message || "unknown",
      });
    }
    return null;
  }
}

/* ---------------------------------------------
   JWT MIDDLEWARE
--------------------------------------------- */
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Неоторизиран достъп" });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.provider_id = decoded.provider_id;
    next();
  } catch {
    return res.status(401).json({ message: "Невалиден токен" });
  }
}

/* ---------------------------------------------
   TEST ROUTE
--------------------------------------------- */
app.get("/", (req, res) => {
  res.send("🚀 Backend работи в Azure!");
});

/* ---------------------------------------------
   HEALTH CHECK (DB)
--------------------------------------------- */
app.get("/healthz", async (req, res) => {
  try {
    const p = await getPoolOr503(null);
    if (!p) {
      return res.status(503).json({ status: "degraded", db: "down" });
    }
    await p.request().query("SELECT 1");
    return res.json({ status: "ok", db: "up" });
  } catch (e) {
    return res.status(503).json({ status: "degraded", db: "down", error: e.message });
  }
});

/* ---------------------------------------------
   PROVIDERS (public list)
--------------------------------------------- */
app.get("/providers", async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const result = await p.request().query("SELECT id, name, email, phone FROM Providers");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ---------------------------------------------
   REGISTER PROVIDER
--------------------------------------------- */
app.post("/providers/register", async (req, res) => {
  const { name, email, phone, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Липсват задължителни полета" });
  }

  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const existing = await p.request()
      .input("email", sql.NVarChar, email)
      .query("SELECT id FROM Providers WHERE email = @email");

    if (existing.recordset.length > 0) {
      return res.status(400).json({ message: "Имейлът вече съществува" });
    }

    const hash = await bcrypt.hash(password, 10);

    await p.request()
      .input("name", sql.NVarChar, name)
      .input("email", sql.NVarChar, email)
      .input("phone", sql.NVarChar, phone || null)
      .input("password_hash", sql.NVarChar, hash)
      .query(`
        INSERT INTO Providers (name, email, phone, password_hash)
        VALUES (@name, @email, @phone, @password_hash)
      `);

    res.status(201).json({ message: "Регистрацията е успешна" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ---------------------------------------------
   LOGIN PROVIDER
--------------------------------------------- */
app.post("/providers/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const result = await p.request()
      .input("email", sql.NVarChar, email)
      .query("SELECT * FROM Providers WHERE email = @email");

    if (result.recordset.length === 0) {
      return res.status(400).json({ message: "Грешни данни" });
    }

    const provider = result.recordset[0];
    const match = await bcrypt.compare(password, provider.password_hash);

    if (!match) {
      return res.status(400).json({ message: "Грешни данни" });
    }

    const token = jwt.sign(
      { provider_id: provider.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ---------------------------------------------
   SERVICES (dashboard)
--------------------------------------------- */
app.get("/my/services", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const result = await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .query(`
        SELECT 
          s.*,
          st.full_name AS staff_name,
          st.role AS staff_role
        FROM services s
        LEFT JOIN staff st ON st.id = s.staff_id
        WHERE s.provider_id = @provider_id
        ORDER BY s.id DESC
      `);

    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/my/services", auth, async (req, res) => {
  const { name, price, duration_min, staff_id } = req.body;

  if (!name || price == null) {
    return res.status(400).json({ message: "Липсват задължителни полета" });
  }

  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .input("name", sql.NVarChar, name)
      .input("price", sql.Decimal(10, 2), price)
      .input("duration_min", sql.Int, duration_min || 60)
      .input("staff_id", sql.Int, staff_id ?? null)
      .query(`
        INSERT INTO services (provider_id, name, price, duration_min, staff_id)
        VALUES (@provider_id, @name, @price, @duration_min, @staff_id)
      `);

    res.status(201).json({ message: "Услугата е добавена" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
/* ---------------------------------------------
   SERVICES (edit/delete) - auth
--------------------------------------------- */
app.put("/my/services/:id", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const serviceId = parseInt(req.params.id, 10);
    if (!serviceId) return res.status(400).json({ message: "Invalid service id" });

    const { name, price, duration_min, staff_id } = req.body;

    // basic validation (allow partial updates? here we expect full payload)
    if (!name || price == null) {
      return res.status(400).json({ message: "Липсват задължителни полета" });
    }

    const upd = await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .input("id", sql.Int, serviceId)
      .input("name", sql.NVarChar, name)
      .input("price", sql.Decimal(10, 2), price)
      .input("duration_min", sql.Int, duration_min || 60)
      .input("staff_id", sql.Int, staff_id ?? null)
      .query(`
        UPDATE services
        SET name = @name,
            price = @price,
            duration_min = @duration_min,
            staff_id = @staff_id
        WHERE id = @id AND provider_id = @provider_id;

        SELECT @@ROWCOUNT AS affected;
      `);

    const affected = upd.recordset?.[0]?.affected || 0;
    if (!affected) return res.status(404).json({ message: "Service not found" });

    return res.json({ message: "Услугата е обновена" });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.delete("/my/services/:id", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const serviceId = parseInt(req.params.id, 10);
    if (!serviceId) return res.status(400).json({ message: "Invalid service id" });

    // Optional guard: if there are future bookings for this service, refuse delete.
    // If you prefer hard-delete always, remove this check.
    const future = await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .input("sid", sql.Int, serviceId)
      .query(`
        SELECT TOP (1) b.id
        FROM bookings b
        WHERE b.provider_id = @provider_id
          AND b.service_id = @sid
          AND b.status <> 'cancelled'
          AND b.start_at >= SYSUTCDATETIME()
      `);

    if (future.recordset.length) {
      return res.status(409).json({ message: "Има бъдещи резервации за тази услуга. Първо ги отмени/премести." });
    }

    const del = await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .input("id", sql.Int, serviceId)
      .query(`
        DELETE FROM services
        WHERE id = @id AND provider_id = @provider_id;

        SELECT @@ROWCOUNT AS affected;
      `);

    const affected = del.recordset?.[0]?.affected || 0;
    if (!affected) return res.status(404).json({ message: "Service not found" });

    return res.json({ message: "Услугата е изтрита" });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});
/* ---------------------------------------------
   STAFF (dashboard)
--------------------------------------------- */
app.get("/my/staff", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const result = await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .query(`
        SELECT id, provider_id, full_name, role, phone, is_active, created_at
        FROM staff
        WHERE provider_id = @provider_id
        ORDER BY is_active DESC, full_name ASC
      `);

    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/my/staff", auth, async (req, res) => {
  const { full_name, role, phone } = req.body;

  if (!full_name || !role) {
    return res.status(400).json({ message: "Липсват име и роля" });
  }

  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const ins = await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .input("full_name", sql.NVarChar(200), full_name)
      .input("role", sql.NVarChar(50), role)
      .input("phone", sql.NVarChar(50), phone || null)
      .query(`
        INSERT INTO staff (provider_id, full_name, role, phone, is_active)
        OUTPUT INSERTED.id
        VALUES (@provider_id, @full_name, @role, @phone, 1)
      `);

    res.status(201).json({ message: "Специалистът е добавен", id: ins.recordset[0].id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ---------------------------------------------
   SERVICES (public – client catalog)
   /providers/:id/services
--------------------------------------------- */
app.get("/providers/:id/services", async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const providerId = parseInt(req.params.id, 10);
    if (!providerId) {
      return res.status(400).json({ message: "Invalid provider id" });
    }

    const result = await p.request()
      .input("pid", sql.Int, providerId)
      .query(`
        SELECT id, provider_id, name, price, duration_min
        FROM services
        WHERE provider_id = @pid
        ORDER BY id DESC
      `);

    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ---------------------------------------------
   AVAILABILITY (public)
--------------------------------------------- */
app.get("/providers/:id/availability", async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const providerId = parseInt(req.params.id, 10);
    const { date, serviceId } = req.query;

    if (!providerId || !date || !serviceId) {
      return res.status(400).json({ message: "Missing providerId/date/serviceId" });
    }

    const s = await p.request()
      .input("sid", sql.Int, parseInt(serviceId, 10))
      .query("SELECT duration_min FROM services WHERE id=@sid");

    if (!s.recordset.length) return res.status(404).json({ message: "Service not found" });
    const durationMin = parseInt(s.recordset[0].duration_min, 10) || 60;

    const dayOfWeek = new Date(`${date}T00:00:00`).getDay();

    const wh = await p.request()
      .input("pid", sql.Int, providerId)
      .input("dow", sql.Int, dayOfWeek)
      .query(`
        SELECT 
          CONVERT(varchar(5), start_time, 108) AS start_time,
          CONVERT(varchar(5), end_time, 108) AS end_time
        FROM provider_working_hours
        WHERE provider_id=@pid AND day_of_week=@dow
      `);

    if (!wh.recordset.length) {
      return res.json({ providerId, serviceId: parseInt(serviceId, 10), date, durationMin, slots: [] });
    }

    const startTime = wh.recordset[0].start_time;
    const endTime = wh.recordset[0].end_time;

    const b = await p.request()
      .input("pid", sql.Int, providerId)
      .input("d", sql.Date, new Date(`${date}T00:00:00`))
      .query(`
        SELECT start_at, end_at
        FROM bookings
        WHERE provider_id=@pid
          AND CAST(start_at AS date) = @d
          AND status <> 'cancelled'
      `);

    const bookings = b.recordset.map((r) => ({
      start: new Date(r.start_at).getTime(),
      end: new Date(r.end_at).getTime(),
    }));

    const dayStart = new Date(`${date}T${startTime}:00`);
    const dayEnd = new Date(`${date}T${endTime}:00`);

    const stepMin = 30;
    const slots = [];

    for (let t = dayStart.getTime(); t + durationMin * 60000 <= dayEnd.getTime(); t += stepMin * 60000) {
      const slotStart = t;
      const slotEnd = t + durationMin * 60000;

      const overlaps = bookings.some((bk) => slotStart < bk.end && slotEnd > bk.start);
      if (!overlaps) slots.push(new Date(slotStart).toISOString());
    }

    return res.json({ providerId, serviceId: parseInt(serviceId, 10), date, durationMin, slots });
  } catch (e) {
    console.error("availability error:", e);
    return res.status(500).json({ message: e.message });
  }
});

/* ---------------------------------------------
   BOOKINGS (client creates booking) - public
--------------------------------------------- */
app.post("/bookings", async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const { providerId, serviceId, startAt, customerName, customerPhone } = req.body;

    if (!providerId || !serviceId || !startAt || !customerName || !customerPhone) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const pid = parseInt(providerId, 10);
    const sid = parseInt(serviceId, 10);

    const s = await p.request()
      .input("sid", sql.Int, sid)
      .query("SELECT duration_min FROM services WHERE id=@sid");

    if (!s.recordset.length) return res.status(404).json({ message: "Service not found" });

    const durationMin = parseInt(s.recordset[0].duration_min, 10) || 60;

    const start = new Date(startAt);
    if (isNaN(start.getTime())) return res.status(400).json({ message: "Invalid startAt" });

    const end = new Date(start.getTime() + durationMin * 60000);

    const overlap = await p.request()
      .input("pid", sql.Int, pid)
      .input("startAt", sql.DateTime2, start)
      .input("endAt", sql.DateTime2, end)
      .query(`
        SELECT TOP (1) id
        FROM bookings
        WHERE provider_id = @pid
          AND status <> 'cancelled'
          AND start_at < @endAt
          AND end_at > @startAt
      `);

    if (overlap.recordset.length) {
      return res.status(409).json({ message: "Slot not available" });
    }

    await p.request()
      .input("pid", sql.Int, pid)
      .input("sid", sql.Int, sid)
      .input("customerName", sql.NVarChar(200), customerName)
      .input("customerPhone", sql.NVarChar(50), customerPhone)
      .input("startAt", sql.DateTime2, start)
      .input("endAt", sql.DateTime2, end)
      .input("status", sql.NVarChar(20), "confirmed")
      .query(`
        INSERT INTO bookings (provider_id, service_id, customer_name, customer_phone, start_at, end_at, status)
        VALUES (@pid, @sid, @customerName, @customerPhone, @startAt, @endAt, @status)
      `);

    return res.status(201).json({ message: "Резервацията е създадена" });
  } catch (e) {
    console.error("create booking error:", e);
    return res.status(500).json({ message: e.message });
  }
});

/* ---------------------------------------------
   BOOKINGS (dashboard list) - auth
--------------------------------------------- */
app.get("/my/bookings", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const { from, to } = req.query;

    const fromDt = from ? new Date(`${from}T00:00:00`) : null;
    const toDt = to ? new Date(`${to}T23:59:59`) : null;

    const result = await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .input("fromDt", sql.DateTime2, fromDt)
      .input("toDt", sql.DateTime2, toDt)
      .query(`
        SELECT
          b.id,
          b.service_id,
          s.name AS service_name,
          s.price,
          s.duration_min,
          b.customer_name,
          b.customer_phone,
          b.start_at,
          b.end_at,
          b.status
        FROM bookings b
        JOIN services s ON s.id = b.service_id
        WHERE b.provider_id = @provider_id
          AND (@fromDt IS NULL OR b.start_at >= @fromDt)
          AND (@toDt IS NULL OR b.start_at <= @toDt)
        ORDER BY b.start_at DESC
      `);

    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
/* ---------------------------------------------
   BOOKINGS (dashboard creates booking) - auth
   manual endAt
--------------------------------------------- */
app.post("/my/bookings", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const { serviceId, startAt, endAt, customerName, customerPhone } = req.body;

    if (!serviceId || !startAt || !endAt || !customerName || !customerPhone) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const sid = parseInt(serviceId, 10);
    if (!sid) return res.status(400).json({ message: "Invalid serviceId" });

    const start = new Date(startAt);
    const end = new Date(endAt);

    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return res.status(400).json({ message: "Invalid startAt/endAt" });
    }

    if (end <= start) {
      return res.status(400).json({ message: "endAt must be after startAt" });
    }

    // ✅ ensure service belongs to this provider (security)
    const svc = await p.request()
      .input("sid", sql.Int, sid)
      .input("pid", sql.Int, req.provider_id)
      .query(`
        SELECT TOP (1) id
        FROM services
        WHERE id = @sid AND provider_id = @pid
      `);

    if (!svc.recordset.length) {
      return res.status(404).json({ message: "Service not found for this provider" });
    }

    // ✅ overlap check (ignore cancelled)
    const overlap = await p.request()
      .input("pid", sql.Int, req.provider_id)
      .input("startAt", sql.DateTime2, start)
      .input("endAt", sql.DateTime2, end)
      .query(`
        SELECT TOP (1) id
        FROM bookings
        WHERE provider_id = @pid
          AND status <> 'cancelled'
          AND start_at < @endAt
          AND end_at > @startAt
      `);

    if (overlap.recordset.length) {
      return res.status(409).json({ message: "Slot not available" });
    }

    const ins = await p.request()
      .input("pid", sql.Int, req.provider_id)
      .input("sid", sql.Int, sid)
      .input("customerName", sql.NVarChar(200), String(customerName).trim())
      .input("customerPhone", sql.NVarChar(50), String(customerPhone).trim())
      .input("startAt", sql.DateTime2, start)
      .input("endAt", sql.DateTime2, end)
      .input("status", sql.NVarChar(20), "confirmed")
      .query(`
        INSERT INTO bookings (provider_id, service_id, customer_name, customer_phone, start_at, end_at, status)
        OUTPUT INSERTED.id
        VALUES (@pid, @sid, @customerName, @customerPhone, @startAt, @endAt, @status)
      `);

    return res.status(201).json({ message: "Часът е записан", id: ins.recordset[0].id });
  } catch (e) {
    console.error("dashboard create booking error:", e);
    return res.status(500).json({ message: e.message });
  }
});
/* ---------------------------------------------
   BOOKINGS (edit) - auth
   PATCH /my/bookings/:id
--------------------------------------------- */
app.patch("/my/bookings/:id", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const bookingId = parseInt(req.params.id, 10);
    if (!bookingId) return res.status(400).json({ message: "Invalid booking id" });

    const {
      serviceId,
      startAt,
      endAt,
      customerName,
      customerPhone,
      status,
    } = req.body || {};

    // fetch + ownership check
    const cur = await p.request()
      .input("id", sql.Int, bookingId)
      .input("pid", sql.Int, req.provider_id)
      .query(`
        SELECT TOP(1) *
        FROM bookings
        WHERE id=@id AND provider_id=@pid
      `);

    if (!cur.recordset.length) return res.status(404).json({ message: "Booking not found" });

    // if changing serviceId -> verify ownership
    let sid = null;
    if (serviceId != null) {
      sid = parseInt(serviceId, 10);
      if (!sid) return res.status(400).json({ message: "Invalid serviceId" });

      const s = await p.request()
        .input("sid", sql.Int, sid)
        .input("pid", sql.Int, req.provider_id)
        .query("SELECT TOP(1) id FROM services WHERE id=@sid AND provider_id=@pid");

      if (!s.recordset.length) return res.status(404).json({ message: "Service not found for this provider" });
    }

    // dates
    let start = null;
    let end = null;
    if (startAt != null || endAt != null) {
      start = startAt != null ? new Date(startAt) : new Date(cur.recordset[0].start_at);
      end = endAt != null ? new Date(endAt) : new Date(cur.recordset[0].end_at);

      if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        return res.status(400).json({ message: "Invalid startAt/endAt" });
      }
      if (end <= start) return res.status(400).json({ message: "endAt must be after startAt" });

      // overlap check (excluding this booking)
      const overlap = await p.request()
        .input("pid", sql.Int, req.provider_id)
        .input("id", sql.Int, bookingId)
        .input("startAt", sql.DateTime2, start)
        .input("endAt", sql.DateTime2, end)
        .query(`
          SELECT TOP (1) id
          FROM bookings
          WHERE provider_id = @pid
            AND id <> @id
            AND status <> 'cancelled'
            AND start_at < @endAt
            AND end_at > @startAt
        `);

      if (overlap.recordset.length) {
        return res.status(409).json({ message: "Slot not available" });
      }
    }

    const newStatus = status ? String(status).slice(0, 20) : null;
    const newName = customerName != null ? String(customerName).slice(0, 200) : null;
    const newPhone = customerPhone != null ? String(customerPhone).slice(0, 50) : null;

    await p.request()
      .input("id", sql.Int, bookingId)
      .input("pid", sql.Int, req.provider_id)
      .input("sid", sql.Int, sid ?? cur.recordset[0].service_id)
      .input("customerName", sql.NVarChar(200), newName ?? cur.recordset[0].customer_name)
      .input("customerPhone", sql.NVarChar(50), newPhone ?? cur.recordset[0].customer_phone)
      .input("startAt", sql.DateTime2, start ?? cur.recordset[0].start_at)
      .input("endAt", sql.DateTime2, end ?? cur.recordset[0].end_at)
      .input("status", sql.NVarChar(20), newStatus ?? cur.recordset[0].status)
      .query(`
        UPDATE bookings
        SET service_id=@sid,
            customer_name=@customerName,
            customer_phone=@customerPhone,
            start_at=@startAt,
            end_at=@endAt,
            status=@status
        WHERE id=@id AND provider_id=@pid
      `);

    return res.json({ message: "Резервацията е обновена" });
  } catch (e) {
    console.error("edit booking error:", e);
    return res.status(500).json({ message: e.message });
  }
});
/* ---------------------------------------------
   SERVICES (edit) - auth
--------------------------------------------- */
app.put("/my/services/:id", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ message: "Invalid service id" });

    const { name, price, duration_min, staff_id } = req.body || {};
    if (!name || price == null) return res.status(400).json({ message: "Missing name/price" });

    // ownership check
    const check = await p.request()
      .input("id", sql.Int, id)
      .input("pid", sql.Int, req.provider_id)
      .query("SELECT TOP(1) id FROM services WHERE id=@id AND provider_id=@pid");

    if (!check.recordset.length) return res.status(404).json({ message: "Service not found" });

    await p.request()
      .input("id", sql.Int, id)
      .input("pid", sql.Int, req.provider_id)
      .input("name", sql.NVarChar(200), String(name).slice(0, 200))
      .input("price", sql.Decimal(10, 2), price)
      .input("duration_min", sql.Int, Number(duration_min || 60))
      .input("staff_id", sql.Int, staff_id ?? null)
      .query(`
        UPDATE services
        SET name=@name, price=@price, duration_min=@duration_min, staff_id=@staff_id
        WHERE id=@id AND provider_id=@pid
      `);

    return res.json({ message: "Услугата е обновена" });
  } catch (e) {
    console.error("edit service error:", e);
    return res.status(500).json({ message: e.message });
  }
});

/* ---------------------------------------------
   SERVICES (delete) - auth
--------------------------------------------- */
app.delete("/my/services/:id", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ message: "Invalid service id" });

    // ownership check
    const check = await p.request()
      .input("id", sql.Int, id)
      .input("pid", sql.Int, req.provider_id)
      .query("SELECT TOP(1) id FROM services WHERE id=@id AND provider_id=@pid");

    if (!check.recordset.length) return res.status(404).json({ message: "Service not found" });

    await p.request()
      .input("id", sql.Int, id)
      .input("pid", sql.Int, req.provider_id)
      .query("DELETE FROM services WHERE id=@id AND provider_id=@pid");

    return res.json({ message: "Услугата е изтрита" });
  } catch (e) {
    console.error("delete service error:", e);
    return res.status(500).json({ message: e.message });
  }
});
/* ---------------------------------------------
   BOOKINGS (cancel) - auth
--------------------------------------------- */
app.patch("/my/bookings/:id/cancel", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const bookingId = parseInt(req.params.id, 10);
    if (!bookingId) {
      return res.status(400).json({ message: "Invalid booking id" });
    }

    const reason = String(req.body?.reason || "").slice(0, 255);

    const check = await p.request()
      .input("id", sql.Int, bookingId)
      .input("provider_id", sql.Int, req.provider_id)
      .query(`
        SELECT TOP (1) id, status
        FROM bookings
        WHERE id = @id AND provider_id = @provider_id
      `);

    if (!check.recordset.length) {
      return res.status(404).json({ message: "Booking not found" });
    }

    await p.request()
      .input("id", sql.Int, bookingId)
      .input("provider_id", sql.Int, req.provider_id)
      .input("reason", sql.NVarChar(255), reason || null)
      .input("by", sql.NVarChar(100), `provider:${req.provider_id}`)
      .query(`
        UPDATE bookings
        SET status = 'cancelled',
            cancelled_at = SYSUTCDATETIME(),
            cancelled_reason = @reason,
            cancelled_by = @by
        WHERE id = @id AND provider_id = @provider_id
      `);

    return res.json({ message: "Резервацията е отменена" });
  } catch (e) {
    console.error("cancel booking error:", e);
    return res.status(500).json({ message: e.message });
  }
});

/* ---------------------------------------------
   WORKING HOURS (dashboard) - auth
--------------------------------------------- */
app.get("/my/working-hours", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const result = await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .query(`
        SELECT day_of_week, start_time, end_time
        FROM provider_working_hours
        WHERE provider_id = @provider_id
        ORDER BY day_of_week
      `);

    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/my/working-hours", auth, async (req, res) => {
  try {
    const p = await getPoolOr503(res);
    if (!p) return;

    const { hours } = req.body;

    if (!Array.isArray(hours)) {
      return res.status(400).json({ message: "Invalid payload" });
    }

    await p.request()
      .input("provider_id", sql.Int, req.provider_id)
      .query(`DELETE FROM provider_working_hours WHERE provider_id=@provider_id`);

    for (const h of hours) {
      const dow = Number(h.day_of_week);
      const st = String(h.start_time || "");
      const et = String(h.end_time || "");

      if (!(dow >= 0 && dow <= 6)) continue;
      if (!st || !et) continue;

      await p.request()
        .input("provider_id", sql.Int, req.provider_id)
        .input("dow", sql.Int, dow)
        .input("st", sql.VarChar(5), st)
        .input("et", sql.VarChar(5), et)
        .query(`
          INSERT INTO provider_working_hours (provider_id, day_of_week, start_time, end_time)
          VALUES (@provider_id, @dow, @st, @et)
        `);
    }

    res.json({ message: "Работното време е запазено" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ---------------------------------------------
   START SERVER (Azure)
--------------------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 API running on port ${PORT}`);
});

