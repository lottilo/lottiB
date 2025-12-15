// app.js
const express = require('express');
const sql = require('mssql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

/* ---------------------------------------------
   CORS
--------------------------------------------- */
app.use(cors({
    origin: process.env.FRONTEND_URL || "*",
    credentials: true
}));

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
        enableArithAbort: true
    }
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
   PROVIDERS
--------------------------------------------- */
app.get("/providers", async (req, res) => {
    try {
        const result = await pool.request()
            .query("SELECT id, name, email, phone FROM Providers");
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
            .input("password", sql.NVarChar, hash)
            .query(`
                INSERT INTO Providers (name, email, phone, password_hash)
                VALUES (@name, @email, @phone, @password)
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
   SERVICES
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
    const { name, price } = req.body;

    try {
        await pool.request()
            .input("provider_id", sql.Int, req.provider_id)
            .input("name", sql.NVarChar, name)
            .input("price", sql.Decimal(10, 2), price)
            .query(`
                INSERT INTO Services (provider_id, name, price)
                VALUES (@provider_id, @name, @price)
            `);

        res.status(201).json({ message: "Услугата е добавена" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

/* ---------------------------------------------
   BOOKINGS
--------------------------------------------- */
app.post("/bookings", async (req, res) => {
    const { service_id, customer_name, customer_phone, booking_date } = req.body;

    try {
        await pool.request()
            .input("service_id", sql.Int, service_id)
            .input("customer_name", sql.NVarChar, customer_name)
            .input("customer_phone", sql.NVarChar, customer_phone)
            .input("booking_date", sql.DateTime, booking_date)
            .query(`
                INSERT INTO Bookings (service_id, customer_name, customer_phone, booking_date)
                VALUES (@service_id, @customer_name, @customer_phone, @booking_date)
            `);

        res.status(201).json({ message: "Резервацията е създадена" });
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

