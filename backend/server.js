const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'donation-app-secret-key-2024';

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 100 
});
app.use(limiter);

const pool = new Pool({ 
  user: 'postgres', 
  host: 'localhost', 
  database: 'postgres', 
  password: 'postgres123', 
  port: 5432 
});

const upload = multer({ 
  dest: 'C:/DonationApp/uploads/', 
  limits: { fileSize: 50 * 1024 * 1024 } 
});

async function initDatabase() {
  try {
    console.log('מכין מסד נתונים...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, 
        username VARCHAR(50) UNIQUE NOT NULL, 
        password VARCHAR(255) NOT NULL, 
        role VARCHAR(20) DEFAULT 'operator', 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS donors (
        id SERIAL PRIMARY KEY, 
        phone VARCHAR(20), 
        name VARCHAR(100), 
        email VARCHAR(100), 
        address TEXT, 
        additional_info JSONB, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    const adminExists = await pool.query('SELECT id FROM users WHERE username = $1', ['admin']);
    
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(
        'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', 
        ['admin', hashedPassword, 'admin']
      );
      console.log('משתמש אדמין נוצר: admin/admin123');
    }
    
    console.log('מסד הנתונים מוכן');
  } catch (err) { 
    console.error('שגיאה:', err); 
  }
}

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'נדרש טוקן' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'טוקן לא תקין' });
    req.user = user; 
    next();
  });
};

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) { 
    res.status(500).json({ error: 'שגיאה בשרת' }); 
  }
});

app.get('/api/search/:phone', authenticateToken, async (req, res) => {
  try {
    const { phone } = req.params;
    const cleanPhone = phone.replace(/[-\s()]/g, '');
    const result = await pool.query(`
      SELECT * FROM donors WHERE 
      REPLACE(REPLACE(REPLACE(phone, '-', ''), ' ', ''), '()', '') ILIKE $1
    `, [`%${cleanPhone}%`]);
    res.json(result.rows);
  } catch (error) { 
    res.status(500).json({ error: 'שגיאה בחיפוש' }); 
  }
});

// הוספת נתיב להעלאת CSV (פשוט)
app.post('/api/upload-csv', authenticateToken, upload.single('csvFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'לא נבחר קובץ' });
    }
    
    const filePath = req.file.path;
    const donors = [];
    
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (row) => {
        donors.push(row);
      })
      .on('end', async () => {
        try {
          // ניקוי טבלה קיימת
          await pool.query('DELETE FROM donors');
          
          // הכנסת נתונים חדשים
          for (const donor of donors) {
            const phone = donor.phone || donor.Phone || '';
            const name = donor.name || donor.Name || '';
            const email = donor.email || donor.Email || '';
            const address = donor.address || donor.Address || '';
            
            await pool.query(
              'INSERT INTO donors (phone, name, email, address) VALUES ($1, $2, $3, $4)',
              [phone, name, email, address]
            );
          }
          
          // מחיקת קובץ זמני
          fs.unlinkSync(filePath);
          
          res.json({ message: `הועלו בהצלחה ${donors.length} תורמים` });
        } catch (error) {
          console.error('שגיאה בעיבוד CSV:', error);
          res.status(500).json({ error: 'שגיאה בעיבוד הקובץ' });
        }
      });
  } catch (error) {
    console.error('שגיאה בהעלאת CSV:', error);
    res.status(500).json({ error: 'שגיאה בהעלאת קובץ' });
  }
});

app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));

app.listen(PORT, async () => {
  console.log(`השרת פועל על http://localhost:${PORT}`);
  await initDatabase();
});