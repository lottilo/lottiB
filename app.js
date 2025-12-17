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
const allowedOrigins = [
  "https://cute-lolly-f257a5.netlify.app"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // Postman / server-to-server
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.options("*", cors());

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
  options: {
    encrypt: true,
    enableArithAbort: true,
  },
};

let pool;

/* ---------------------------------------------
   CONNECT TO DATABASE ON START
--------------------------------------------- */
async function connectDB() {
  try {
    pool = await sql.connect(dbConfig);
    console.log("✅ Connected to Azure SQL");
  } catch (err) {
    console.error("❌ DB connection failed:", err);
  }
}
connectDB();

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
   PROVIDERS (public list)
--------------------------------------------- */
app.get("/providers", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT id, name, email, phone FROM Providers");
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
    const existing = await pool.request()
      .input("email", sql.NVarChar, email)
      .query("SELECT id FROM Providers WHERE email = @email");

    if (existing.recordset.length > 0) {
      return res.status(400).json({ message: "Имейлът вече съществува" });
    }

    const hash = await bcrypt.hash(password, 10);

    await pool.request()
      .input("name", sql.NVarChar, name)
      .input("email", sql.NVarChar, email)
      .input("phone", sql.NVarChar, phone)
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
    const result = await pool.request()
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
    const result = await pool.request()
      .input("provider_id", sql.Int, req.provider_id)
      .query("SELECT * FROM Services WHERE provider_id = @provider_id");

    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/my/services", auth, async (req, res) => {
  const { name, price, duration_min } = req.body;

  if (!name || price == null) {
    return res.status(400).json({ message: "Липсват задължителни полета" });
  }

  try {
    await pool.request()
      .input("provider_id", sql.Int, req.provider_id)
      .input("name", sql.NVarChar, name)
      .input("price", sql.Decimal(10, 2), price)
      .input("duration_min", sql.Int, duration_min || 60)
      .query(`
        INSERT INTO Services (provider_id, name, price, duration_min)
        VALUES (@provider_id, @name, @price, @duration_min)
      `);

    res.status(201).json({ message: "Услугата е добавена" });
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
    const providerId = parseInt(req.params.id, 10);
    if (!providerId) {
      return res.status(400).json({ message: "Invalid provider id" });
    }

    const result = await pool.request()
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
   /providers/:id/availability?date=YYYY-MM-DD&serviceId=1
--------------------------------------------- */
app.get("/providers/:id/availability", async (req, res) => {
  try {
    const providerId = parseInt(req.params.id, 10);
    const { date, serviceId } = req.query;

    if (!providerId || !date || !serviceId) {
      return res.status(400).json({ message: "Missing providerId/date/serviceId" });
    }

    // 1) service duration
    const s = await pool.request()
      .input("sid", sql.Int, parseInt(serviceId, 10))
      .query("SELECT duration_min FROM services WHERE id=@sid");

    if (!s.recordset.length) return res.status(404).json({ message: "Service not found" });
    const durationMin = parseInt(s.recordset[0].duration_min, 10) || 60;

    // 2) day of week (0=Sun..6=Sat)
    const dayOfWeek = new Date(`${date}T00:00:00`).getDay();

    // 3) working hours for that day (return time as 'HH:mm')
    const wh = await pool.request()
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

    const startTime = wh.recordset[0].start_time; // '09:00'
    const endTime = wh.recordset[0].end_time;     // '18:00'

    // 4) existing bookings for that date
    const b = await pool.request()
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

    for (
      let t = dayStart.getTime();
      t + durationMin * 60000 <= dayEnd.getTime();
      t += stepMin * 60000
    ) {
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
    const { providerId, serviceId, startAt, customerName, customerPhone } = req.body;

    if (!providerId || !serviceId || !startAt || !customerName || !customerPhone) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const pid = parseInt(providerId, 10);
    const sid = parseInt(serviceId, 10);

    // duration
    const s = await pool.request()
      .input("sid", sql.Int, sid)
      .query("SELECT duration_min FROM services WHERE id=@sid");

    if (!s.recordset.length) return res.status(404).json({ message: "Service not found" });

    const durationMin = parseInt(s.recordset[0].duration_min, 10) || 60;

    const start = new Date(startAt);
    if (isNaN(start.getTime())) return res.status(400).json({ message: "Invalid startAt" });

    const end = new Date(start.getTime() + durationMin * 60000);

    // overlap check
    const overlap = await pool.request()
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

    // insert
    await pool.request()
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
   /my/bookings?from=YYYY-MM-DD&to=YYYY-MM-DD
--------------------------------------------- */
app.get("/my/bookings", auth, async (req, res) => {
  try {
    const { from, to } = req.query;

    const fromDt = from ? new Date(`${from}T00:00:00`) : null;
    const toDt = to ? new Date(`${to}T23:59:59`) : null;

    const result = await pool.request()
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
   START SERVER (Azure)
--------------------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 API running on port ${PORT}`);
});

