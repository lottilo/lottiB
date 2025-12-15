require('dotenv').config();
const sql = require('mssql');

const config = {
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    server: process.env.DB_HOST,
    database: process.env.DB_NAME,
    port: parseInt(process.env.DB_PORT),
    options: {
        encrypt: true,
        enableArithAbort: true
    }
};

async function testConnection() {
    try {
        let pool = await sql.connect(config);
        console.log("Свързването е успешно!");
        await pool.close();
    } catch (err) {
        console.error("Грешка при свързване:", err.message);
    }
}

testConnection();
