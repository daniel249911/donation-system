const express = require('express');
const sqlite3 = require('sqlite3').verbose();
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

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 100 
});
app.use(limiter);

// יצירת מסד נתונים SQLite
const db = new sqlite3.Database('C:/DonationApp/database.sqlite', (err) => {
  if (err) {
    console.error('שגיאה בחיבור למסד נתונים:', err.message);
  } else {
    console.log('מחובר למסד נתונים SQLite');
  }
});

const upload = multer({ 
  dest: 'C:/DonationApp/uploads/', 
  limits: { fileSize: 50 * 1024 * 1024 } 
});

async function initDatabase() {
  return new Promise((resolve, reject) => {
    console.log('מכין מסד נתונים...');
    
    // יצירת טבלת משתמשים
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'operator',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) {
        console.error('שגיאה ביצירת טבלת משתמשים:', err);
        return reject(err);
      }
      
      // יצירת טבלת תורמים
      db.run(`
        CREATE TABLE IF NOT EXISTS donors (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          phone TEXT,
          name TEXT,
          email TEXT,
          address TEXT,
          additional_info TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת תורמים:', err);
          return reject(err);
        }
        
        // בדיקה אם משתמש אדמין קיים
        db.get('SELECT id FROM users WHERE username = ?', ['admin'], async (err, row) => {
          if (err) {
            console.error('שגיאה בבדיקת אדמין:', err);
            return reject(err);
          }
          
          if (!row) {
            // יצירת משתמש אדמין
            const hashedPassword = await bcrypt.hash('admin123', 10);
            db.run(
              'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
              ['admin', hashedPassword, 'admin'],
              (err) => {
                if (err) {
                  console.error('שגיאה ביצירת אדמין:', err);
                  return reject(err);
                }
                console.log('משתמש אדמין נוצר: admin/admin123');
                console.log('מסד הנתונים מוכן!');
                resolve();
              }
            );
          } else {
            console.log('מסד הנתונים מוכן!');
            resolve();
          }
        });
      });
    });
  });
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

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error('שגיאה בחיפוש משתמש:', err);
      return res.status(500).json({ error: 'שגיאה בשרת' });
    }
    
    if (!user) {
      return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
    }
    
    try {
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
      }
      
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role }, 
        JWT_SECRET, 
        { expiresIn: '8h' }
      );
      
      res.json({ 
        token, 
        user: { id: user.id, username: user.username, role: user.role } 
      });
    } catch (error) {
      console.error('שגיאה בהשוואת סיסמה:', error);
      res.status(500).json({ error: 'שגיאה בשרת' });
    }
  });
});

app.get('/api/search/:phone', authenticateToken, (req, res) => {
  const { phone } = req.params;
  const cleanPhone = phone.replace(/[-\s()]/g, '');
  
  db.all(`
    SELECT * FROM donors WHERE 
    REPLACE(REPLACE(REPLACE(phone, '-', ''), ' ', ''), '()', '') LIKE ?
  `, [`%${cleanPhone}%`], (err, rows) => {
    if (err) {
      console.error('שגיאה בחיפוש:', err);
      return res.status(500).json({ error: 'שגיאה בחיפוש' });
    }
    res.json(rows);
  });
});

app.post('/api/upload-csv', authenticateToken, upload.single('csvFile'), (req, res) => {
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
    .on('end', () => {
      // ניקוי טבלה קיימת
      db.run('DELETE FROM donors', (err) => {
        if (err) {
          console.error('שגיאה בניקוי טבלה:', err);
          return res.status(500).json({ error: 'שגיאה בעיבוד' });
        }
        
        // הכנסת נתונים חדשים
        const stmt = db.prepare('INSERT INTO donors (phone, name, email, address) VALUES (?, ?, ?, ?)');
        
        let completed = 0;
        for (const donor of donors) {
          const phone = donor.phone || donor.Phone || '';
          const name = donor.name || donor.Name || '';
          const email = donor.email || donor.Email || '';
          const address = donor.address || donor.Address || '';
          
          stmt.run([phone, name, email, address], (err) => {
            if (err) {
              console.error('שגיאה בהכנסת נתון:', err);
            }
            completed++;
            if (completed === donors.length) {
              stmt.finalize();
              fs.unlinkSync(filePath);
              res.json({ message: `הועלו בהצלחה ${donors.length} תורמים` });
            }
          });
        }
        
        if (donors.length === 0) {
          stmt.finalize();
          fs.unlinkSync(filePath);
          res.json({ message: 'קובץ ריק' });
        }
      });
    });
});

// הוספת endpoint לסטטיסטיקות
app.get('/api/stats', authenticateToken, (req, res) => {
  db.get('SELECT COUNT(*) as totalDonors FROM donors', (err, row) => {
    if (err) {
      console.error('שגיאה בסטטיסטיקות:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
    }
    res.json({ totalDonors: row.totalDonors });
  });
});

app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));

app.listen(PORT, async () => {
  console.log(`השרת פועל על http://localhost:${PORT}`);
  try {
    await initDatabase();
  } catch (error) {
    console.error('שגיאה באתחול מסד נתונים:', error);
  }
});