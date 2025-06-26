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
const Airtable = require('airtable');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'donation-app-advanced-secret-2024';
// הגדרות Airtable - **החלף עם הנתונים שלך**
const AIRTABLE_API_KEY = 'pat1srYTtKXtTo3DH.464caa2a2a8f98b22e012b515be1a9e0ebfc3281812fdbc265450bb903298e82'; // המפתח שלך מ-Airtable
const AIRTABLE_BASE_ID = 'app8aGPrsarmKVPD4'; // ה-Base ID שלך
const AIRTABLE_TABLE_NAME = 'שמות שנמסרו אתר חדש'; // שם הטבלה שלך

// בדיקה שהמפתחות מוגדרים
if (!AIRTABLE_API_KEY.startsWith('pat') || !AIRTABLE_BASE_ID.startsWith('app')) {
    console.warn('⚠️ אנא עדכן את מפתחות Airtable ב-advanced-server.js');
}

// אתחול Airtable
let base = null;
try {
    base = new Airtable({ apiKey: AIRTABLE_API_KEY }).base(AIRTABLE_BASE_ID);
    console.log('✅ Airtable מאותחל בהצלחה');
} catch (error) {
    console.error('❌ שגיאה באתחול Airtable:', error.message);
}

// הגדרות אבטחה
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      frameSrc: ["'self'", "https:"],
    },
  },
}));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 200 
});
app.use(limiter);

// יצירת מסד נתונים
const db = new sqlite3.Database('./advanced_database.sqlite', (err) => {
  if (err) {
    console.error('שגיאה בחיבור למסד נתונים:', err.message);
  } else {
    console.log('מחובר למסד נתונים SQLite מתקדם');
  }
});

const upload = multer({ 
  dest: 'C:/DonationApp/uploads/', 
  limits: { fileSize: 50 * 1024 * 1024 } 
});

// יצירת כל הטבלאות// יצירת כל הטבלאות - גרסה מתוקנת
async function initDatabase() {
  return new Promise((resolve, reject) => {
    console.log('מכין מסד נתונים מתקדם...');
    
    db.serialize(() => {
      // טבלת משתמשים מורחבת
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          role TEXT DEFAULT 'operator',
          full_name TEXT,
          email TEXT,
          phone TEXT,
          department TEXT,
          is_active INTEGER DEFAULT 1,
          last_login DATETIME,
          login_count INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          created_by INTEGER,
          notes TEXT
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת משתמשים:', err);
          return reject(err);
        }
        console.log('✅ טבלת משתמשים נוצרה');
      });

      // טבלת תורמים מורחבת - עם כל השדות החדשים
      db.run(`
        CREATE TABLE IF NOT EXISTS donors (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          phone TEXT,
          name TEXT,
          email TEXT,
          address TEXT,
          city TEXT,
          area TEXT,
          donation_amount REAL,
          last_contact DATE,
          donor_type TEXT,
          status TEXT DEFAULT 'active',
          notes TEXT,
          additional_info TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          created_by INTEGER,
          updated_by INTEGER,
          order_number TEXT,
          project_name TEXT,
          prayer_name TEXT,
          first_name TEXT,
          last_name TEXT,
          delivery_date TEXT,
          fix_date TEXT,
          death_date_month TEXT,
          death_date_day TEXT,
          comments TEXT,
          payment_status TEXT,
          quantity INTEGER DEFAULT 1,
          phone_copy TEXT,
          payment_amount TEXT,
          payment_method TEXT,
          marketing_source TEXT,
          traffic_source TEXT,
          campaign_name TEXT,
          type_field TEXT,
          keywords TEXT,
          content_field TEXT,
          datetime_field TEXT,
          created_field TEXT,
          last_modified TEXT,
          project_id TEXT,
          street TEXT,
          building TEXT,
          apartment TEXT
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת תורמים:', err);
          return reject(err);
        }
        console.log('✅ טבלת תורמים נוצרה');
      });

      // יצירת אינדקסים
      db.run(`CREATE INDEX IF NOT EXISTS idx_donors_name_phone ON donors(name, phone)`, (err) => {
        if (err && !err.message.includes('already exists')) {
          console.error('שגיאה ביצירת אינדקס:', err);
        }
      });

      db.run(`CREATE INDEX IF NOT EXISTS idx_donors_first_last_phone ON donors(first_name, last_name, phone)`, (err) => {
        if (err && !err.message.includes('already exists')) {
          console.error('שגיאה ביצירת אינדקס:', err);
        }
      });

      // שאר הטבלאות הקיימות...
      db.run(`
        CREATE TABLE IF NOT EXISTS activity_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          action TEXT,
          target_type TEXT,
          target_id INTEGER,
          details TEXT,
          ip_address TEXT,
          user_agent TEXT,
          session_id TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת לוגים:', err);
          return reject(err);
        }
        console.log('✅ טבלת לוגים נוצרה');
      });

      // המשך עם שאר הטבלאות...
      db.run(`
        CREATE TABLE IF NOT EXISTS system_messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          type TEXT DEFAULT 'info',
          target_role TEXT,
          target_user_id INTEGER,
          is_active INTEGER DEFAULT 1,
          priority INTEGER DEFAULT 1,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME,
          FOREIGN KEY (created_by) REFERENCES users (id)
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת הודעות:', err);
          return reject(err);
        }
        console.log('✅ טבלת הודעות נוצרה');
      });

      db.run(`
        CREATE TABLE IF NOT EXISTS support_tickets (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          description TEXT NOT NULL,
          category TEXT,
          priority TEXT DEFAULT 'medium',
          status TEXT DEFAULT 'open',
          created_by INTEGER,
          assigned_to INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          resolved_at DATETIME,
          user_read_admin_response INTEGER DEFAULT 0,
          FOREIGN KEY (created_by) REFERENCES users (id),
          FOREIGN KEY (assigned_to) REFERENCES users (id)
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת כרטיסים:', err);
          return reject(err);
        }
        console.log('✅ טבלת כרטיסים נוצרה');
      });

      db.run(`
        CREATE TABLE IF NOT EXISTS ticket_responses (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ticket_id INTEGER,
          user_id INTEGER,
          content TEXT NOT NULL,
          is_internal INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (ticket_id) REFERENCES support_tickets (id),
          FOREIGN KEY (user_id) REFERENCES users (id)
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת תגובות:', err);
          return reject(err);
        }
        console.log('✅ טבלת תגובות נוצרה');
      });

      db.run(`
        CREATE TABLE IF NOT EXISTS search_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          search_term TEXT,
          search_type TEXT DEFAULT 'phone',
          results_count INTEGER,
          ip_address TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת היסטוריה:', err);
          return reject(err);
        }
        console.log('✅ טבלת היסטוריה נוצרה');
      });

      db.run(`
        CREATE TABLE IF NOT EXISTS user_notes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          donor_id INTEGER,
          note TEXT NOT NULL,
          is_private INTEGER DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id),
          FOREIGN KEY (donor_id) REFERENCES donors (id)
        )
      `, (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת הערות:', err);
          return reject(err);
        }
        console.log('✅ טבלת הערות נוצרה');
      });

      db.run(`
        CREATE TABLE IF NOT EXISTS daily_reports (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          report_date DATE,
          searches_count INTEGER DEFAULT 0,
          unique_searches INTEGER DEFAULT 0,
          work_hours REAL DEFAULT 0,
          notes TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )
      `, async (err) => {
        if (err) {
          console.error('שגיאה ביצירת טבלת דוחות:', err);
          return reject(err);
        }
console.log('✅ טבלת דוחות נוצרה');
        
        // הוספת עמודות חסרות לטבלת users
        const userColumns = [
          'notes TEXT',
          'department TEXT', 
          'phone TEXT',
          'email TEXT'
        ];

        userColumns.forEach(column => {
          const columnName = column.split(' ')[0];
          db.run(`ALTER TABLE users ADD COLUMN ${column}`, (err) => {
            if (err && !err.message.includes('duplicate column name')) {
              console.error(`שגיאה בהוספת עמודת ${columnName}:`, err);
            } else {
              console.log(`✅ עמודת ${columnName} נוספה לטבלת users`);
            }
          });
        });

        // הוספת עמודת updated_at בנפרד (ללא default value)
        db.run(`ALTER TABLE users ADD COLUMN updated_at DATETIME`, (err) => {
          if (err && !err.message.includes('duplicate column name')) {
            console.error('שגיאה בהוספת עמודת updated_at:', err);
          } else {
            console.log('✅ עמודת updated_at נוספה לטבלת users');
            
            // עדכון כל הרשומות הקיימות עם זמן נוכחי
            db.run(`UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL`, (err) => {
              if (err) {
                console.error('שגיאה בעדכון updated_at:', err);
              } else {
                console.log('✅ עמודת updated_at עודכנה לכל המשתמשים');
              }
            });
          }
        });
        
        // טבלת סוגי תרומות
        db.run(`
          CREATE TABLE IF NOT EXISTS donation_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            start_date DATE,
            end_date DATE,
            no_expiry INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            description TEXT,
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
          )
        `, (err) => {
          if (err) {
            console.error('שגיאה ביצירת טבלת סוגי תרומות:', err);
            return reject(err);
          }
          console.log('✅ טבלת סוגי תרומות נוצרה');
        });

     // טבלת לוגי גישה לתרומות
     db.run(`
       CREATE TABLE IF NOT EXISTS donation_access_logs (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         user_id INTEGER,
         donation_type_id INTEGER,
         action TEXT DEFAULT 'VIEW',
         ip_address TEXT,
         user_agent TEXT,
         created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
         FOREIGN KEY (user_id) REFERENCES users (id),
         FOREIGN KEY (donation_type_id) REFERENCES donation_types (id)
       )
     `, async (err) => {
       if (err) {
         console.error('שגיאה ביצירת טבלת לוגי תרומות:', err);
         return reject(err);
       }
       console.log('✅ טבלת לוגי תרומות נוצרה');
		
        // בדיקת אדמין
        try {
          console.log('🔍 בודק משתמש אדמין...');
          
          db.get('SELECT id FROM users WHERE username = ?', ['admin'], async (err, row) => {
            if (err) {
              console.error('שגיאה בבדיקת אדמין:', err);
              return reject(err);
            }
            
            if (!row) {
              console.log('👤 יוצר משתמש אדמין...');
              try {
                const hashedPassword = await bcrypt.hash('admin123', 10);
                
                db.run(
                  `INSERT INTO users (username, password, role, full_name, email) 
                   VALUES (?, ?, ?, ?, ?)`,
                  ['admin', hashedPassword, 'admin', 'מנהל ראשי', 'admin@donation.org'],
                  function(err) {
                    if (err) {
                      console.error('שגיאה ביצירת אדמין:', err);
                      return reject(err);
                    }
                    
                    console.log('✅ משתמש אדמין נוצר: admin/admin123');
                    
                    db.run(
                      `INSERT INTO system_messages (title, content, type, target_role, created_by)
                       VALUES (?, ?, ?, ?, ?)`,
                      [
                        'ברוכים הבאים למערכת',
                        'המערכת הותקנה בהצלחה! ראשית העלו קובץ CSV עם נתוני התורמים.',
                        'success',
                        'admin',
                        this.lastID
                      ],
                      (err) => {
                        if (err) {
                          console.error('שגיאה ביצירת הודעה:', err);
                        } else {
                          console.log('✅ הודעת ברוכים הבאים נוצרה');
                        }
                        
                        console.log('🎉 מסד הנתונים המתקדם מוכן!');
                        resolve();
                      }
                    );
                  }
                );
              } catch (hashError) {
                console.error('שגיאה בהצפנת סיסמה:', hashError);
                reject(hashError);
              }
            } else {
              console.log('✅ משתמש אדמין כבר קיים');
              console.log('🎉 מסד הנתונים המתקדם מוכן!');
              resolve();
            }
          });
        } catch (adminError) {
          console.error('שגיאה ביצירת אדמין:', adminError);
          reject(adminError);
        }
        });
      });
    }); // סוגר של db.serialize
  });   // סוגר של Promise
}       // סוגר של async function initDatabase




// פונקציית לוג מתקדמת
function logActivity(userId, action, targetType = null, targetId = null, details = null, req = null) {
  const ipAddress = req ? req.ip : null;
  const userAgent = req ? req.get('User-Agent') : null;
  const sessionId = req ? req.sessionID : null;
  
  db.run(
    `INSERT INTO activity_logs (user_id, action, target_type, target_id, details, ip_address, user_agent, session_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [userId, action, targetType, targetId, details, ipAddress, userAgent, sessionId],
    (err) => {
      if (err) console.error('שגיאה בשמירת לוג:', err);
    }
  );
}

// middleware לאימות
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'נדרש טוקן גישה' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'טוקן לא תקין' });
    req.user = user;
    next();
  });
};

// middleware לבדיקת הרשאות אדמין
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'נדרשות הרשאות אדמין' });
  }
  next();
};

// נתיב התחברות מתקדם
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ? AND is_active = 1', [username], async (err, user) => {
      if (err) {
        console.error('שגיאה בחיפוש משתמש:', err);
        return res.status(500).json({ error: 'שגיאה בשרת' });
      }
      
      if (!user) {
        logActivity(null, 'התחברות_נכשלה', 'user', null, `ניסיון התחברות נכשל: ${username}`, req);
        return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
      }
      
      try {
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
          logActivity(user.id, 'התחברות_נכשלה', 'user', user.id, 'סיסמה שגויה', req);
          return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
        }
        
        // עדכון פרטי התחברות
        db.run(
          'UPDATE users SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE id = ?',
          [user.id]
        );
        
        const token = jwt.sign(
          { 
            id: user.id, 
            username: user.username, 
            role: user.role,
            full_name: user.full_name 
          }, 
          JWT_SECRET, 
          { expiresIn: '8h' }
        );
        
        logActivity(user.id, 'התחברות', 'user', user.id, 'התחבר בהצלחה', req);
        
        res.json({ 
          token, 
          user: { 
            id: user.id, 
            username: user.username, 
            role: user.role,
            full_name: user.full_name,
            email: user.email
          } 
        });
      } catch (error) {
        console.error('שגיאה בהשוואת סיסמה:', error);
        res.status(500).json({ error: 'שגיאה בשרת' });
      }
    });
  } catch (error) {
    console.error('שגיאה כללית בהתחברות:', error);
    res.status(500).json({ error: 'שגיאה בשרת' });
  }
});

// חיפוש מתקדם עם לוג
app.get('/api/search/:phone', authenticateToken, (req, res) => {
    const { phone } = req.params;
    const cleanPhone = phone.replace(/[-\s()]/g, '');
    
    // וידוא מינימום 7 תווים
    if (cleanPhone.length < 7) {
        return res.status(400).json({ error: 'נדרשים לפחות 7 תווים לחיפוש' });
    }
    
    // שאילתה מתוקנת - חיפוש ראשוני של תורמים ייחודיים
    const mainQuery = `
        SELECT 
            MIN(id) as main_id,
            COALESCE(name, first_name || ' ' || last_name) as full_name,
            phone,
            MAX(email) as email,
            MAX(city) as city,
            MAX(street) as street,
            MAX(building) as building,
            MAX(apartment) as apartment
        FROM donors
        WHERE REPLACE(REPLACE(REPLACE(phone, '-', ''), ' ', ''), '()', '') LIKE ?
        GROUP BY 
            COALESCE(name, first_name || ' ' || last_name),
            phone
        ORDER BY MIN(created_at) DESC
    `;
    
    db.all(mainQuery, [`%${cleanPhone}%`], (err, uniqueDonors) => {
        if (err) {
            console.error('שגיאה בחיפוש תורמים:', err);
            return res.status(500).json({ error: 'שגיאה בחיפוש' });
        }
        
        if (uniqueDonors.length === 0) {
            // שמירת חיפוש בהיסטוריה
            db.run(
                `INSERT INTO search_history (user_id, search_term, search_type, results_count, ip_address)
                 VALUES (?, ?, ?, ?, ?)`,
                [req.user.id, phone, 'phone', 0, req.ip]
            );
            
            logActivity(req.user.id, 'SEARCH', 'donor', null, `Search for: ${phone}, Results: 0`, req);
            return res.json([]);
        }
        
        // עבור כל תורם ייחודי, קבל את כל התרומות שלו
        const promises = uniqueDonors.map(donor => {
            return new Promise((resolve, reject) => {
                const donationsQuery = `
                    SELECT 
                        id,
                        order_number,
                        project_name,
                        prayer_name,
                        payment_amount,
                        payment_method,
                        payment_status,
                        created_at,
                        comments,
                        delivery_date,
                        fix_date,
                        death_date_month,
                        death_date_day,
                        marketing_source,
                        campaign_name,
                        donation_amount
                    FROM donors
                    WHERE COALESCE(name, first_name || ' ' || last_name) = ?
                    AND phone = ?
                    ORDER BY created_at DESC
                `;
                
                db.all(donationsQuery, [donor.full_name, donor.phone], (err, donations) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    
                    // חישוב סה"כ תרומות
                    let totalDonated = 0;
                    donations.forEach(donation => {
                        let amount = 0;
                        if (donation.payment_amount && donation.payment_amount.includes('₪')) {
                            const cleanAmount = donation.payment_amount.replace(/[₪,\s]/g, '');
                            amount = parseFloat(cleanAmount) || 0;
                        } else if (donation.donation_amount) {
                            amount = parseFloat(donation.donation_amount) || 0;
                        }
                        totalDonated += amount;
                    });
                    
                    resolve({
                        ...donor,
                        donations_count: donations.length,
                        total_donated: totalDonated,
                        first_donation: donations[donations.length - 1]?.created_at,
                        last_donation: donations[0]?.created_at,
                        donations: donations,
                        user_notes: null // נוסיף אם נדרש
                    });
                });
            });
        });
        
        Promise.all(promises)
            .then(results => {
                // שמירת חיפוש בהיסטוריה
                db.run(
                    `INSERT INTO search_history (user_id, search_term, search_type, results_count, ip_address)
                     VALUES (?, ?, ?, ?, ?)`,
                    [req.user.id, phone, 'phone', results.length, req.ip]
                );
                
                logActivity(req.user.id, 'SEARCH', 'donor', null, 
                    `Search for: ${phone}, Results: ${results.length}`, req);
                
                res.json(results);
            })
            .catch(error => {
                console.error('שגיאה בעיבוד תרומות:', error);
                res.status(500).json({ error: 'שגיאה בעיבוד נתונים' });
            });
    });
});

// קבלת היסטוריית חיפושים אישית
app.get('/api/my-search-history', authenticateToken, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  
  db.all(`
    SELECT search_term, results_count, created_at
    FROM search_history 
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT ?
  `, [req.user.id, limit], (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת היסטוריה:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
    }
    res.json(rows);
  });
});

// הוספת הערה אישית לתורם
app.post('/api/donor/:id/note', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { note } = req.body;
    
    if (!note || note.trim().length === 0) {
        return res.status(400).json({ error: 'תוכן ההערה נדרש' });
    }
    
    db.run(
        `INSERT INTO user_notes (user_id, donor_id, note, is_private) VALUES (?, ?, ?, ?)`,
        [req.user.id, id, note.trim(), 0], // is_private = 0 כדי שכולם יראו
        function(err) {
            if (err) {
                console.error('שגיאה בשמירת הערה:', err);
                return res.status(500).json({ error: 'שגיאה בשמירת הערה' });
            }
            
            logActivity(req.user.id, 'ADD_NOTE', 'donor', id, `Added note to donor ${id}`, req);
            res.json({ message: 'הערה נשמרה בהצלחה', noteId: this.lastID });
        }
    );
});


// === ניהול הודעות מערכת ===

// קבלת הודעות לטלפן הנוכחי
app.get('/api/my-messages', authenticateToken, (req, res) => {
  db.all(`
    SELECT * FROM system_messages 
    WHERE is_active = 1 
    AND (target_role IS NULL OR target_role = ? OR target_user_id = ?)
    AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
    ORDER BY priority DESC, created_at DESC
  `, [req.user.role, req.user.id], (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת הודעות:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת הודעות' });
    }
    res.json(rows);
  });
});

// יצירת הודעה חדשה (אדמין)
app.post('/api/admin/messages', authenticateToken, requireAdmin, (req, res) => {
  const { title, content, type, target_role, target_user_id, expires_at } = req.body;
  
  if (!title || !content) {
    return res.status(400).json({ error: 'כותרת ותוכן נדרשים' });
  }
  
  db.run(`
    INSERT INTO system_messages (title, content, type, target_role, target_user_id, expires_at, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [title, content, type || 'info', target_role, target_user_id, expires_at, req.user.id], function(err) {
    if (err) {
      console.error('שגיאה ביצירת הודעה:', err);
      return res.status(500).json({ error: 'שגיאה ביצירת הודעה' });
    }
    
    logActivity(req.user.id, 'יצירת_הודעה', 'message', this.lastID, `יצר הודעה: ${title}`, req);
    res.json({ message: 'הודעה נוצרה בהצלחה', messageId: this.lastID });
  });
});

// === מערכת כרטיסי תמיכה ===

// קבלת כרטיסי התמיכה שלי
// החלף את ה-endpoint /api/my-tickets ב-advanced-server.js
app.get('/api/my-tickets', authenticateToken, (req, res) => {
  db.all(`
    SELECT t.*, 
           u.full_name as creator_name, 
           a.full_name as assigned_name,
           CASE WHEN EXISTS (
             SELECT 1 FROM ticket_responses tr 
             WHERE tr.ticket_id = t.id 
             AND tr.user_id != t.created_by 
             AND tr.is_internal = 0
             AND tr.created_at > COALESCE(
               (SELECT MAX(tr2.created_at) 
                FROM ticket_responses tr2 
                WHERE tr2.ticket_id = t.id 
                AND tr2.user_id = t.created_by), 
               t.created_at
             )
           ) THEN 1 ELSE 0 END as has_admin_response,
           COALESCE(t.user_read_admin_response, 0) as user_read_admin_response
    FROM support_tickets t
    LEFT JOIN users u ON t.created_by = u.id
    LEFT JOIN users a ON t.assigned_to = a.id
    WHERE t.created_by = ?
    ORDER BY 
      CASE WHEN t.status != 'closed' AND has_admin_response = 1 AND COALESCE(t.user_read_admin_response, 0) = 0 THEN 0 ELSE 1 END,
      t.updated_at DESC
  `, [req.user.id], (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת כרטיסים:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת כרטיסים' });
    }
    res.json(rows);
  });
});

// החלף את ה-endpoint mark-read ב-advanced-server.js
app.post('/api/tickets/:id/mark-read', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  // בדיקה שהמשתמש הוא הבעלים של הכרטיס
  db.get('SELECT * FROM support_tickets WHERE id = ? AND created_by = ?', [id, req.user.id], (err, ticket) => {
    if (err) {
      return res.status(500).json({ error: 'שגיאה בשרת' });
    }
    
    if (!ticket) {
      return res.status(404).json({ error: 'כרטיס לא נמצא' });
    }
    
    // עדכון הכרטיס כנקרא
    db.run('UPDATE support_tickets SET user_read_admin_response = 1 WHERE id = ?', [id], (err) => {
      if (err) {
        return res.status(500).json({ error: 'שגיאה בעדכון' });
      }
      
      res.json({ message: 'כרטיס סומן כנקרא' });
    });
  });
});


// קבלת כל הכרטיסים (אדמין) - גרסה מתוקנת
app.get('/api/admin/tickets', authenticateToken, requireAdmin, (req, res) => {
  const { status, category, priority } = req.query;
  
  let whereClause = '';
  let params = [];
  
  if (status) {
    whereClause += ' WHERE t.status = ?';
    params.push(status);
  }
  
  if (category) {
    whereClause += whereClause ? ' AND t.category = ?' : ' WHERE t.category = ?';
    params.push(category);
  }
  
  if (priority) {
    whereClause += whereClause ? ' AND t.priority = ?' : ' WHERE t.priority = ?';
    params.push(priority);
  }
  
  db.all(`
    SELECT t.*, 
           u.full_name as creator_name, 
           a.full_name as assigned_name,
           COUNT(tr.id) as responses_count
    FROM support_tickets t
    LEFT JOIN users u ON t.created_by = u.id
    LEFT JOIN users a ON t.assigned_to = a.id
    LEFT JOIN ticket_responses tr ON t.id = tr.ticket_id
    ${whereClause}
    GROUP BY t.id
    ORDER BY 
      CASE t.priority 
        WHEN 'urgent' THEN 4
        WHEN 'high' THEN 3
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 1
        ELSE 0
      END DESC,
      t.created_at DESC
  `, params, (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת כרטיסים:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת כרטיסים' });
    }
    res.json(rows);
  });
});

// הוסף אחרי ה-endpoint של /api/admin/tickets

// פרטי כרטיס מלאים עם תגובות
app.get('/api/admin/tickets/:id/details', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  
  // קבלת פרטי הכרטיס
  db.get(`
    SELECT t.*, 
           u.full_name as creator_name, 
           a.full_name as assigned_name
    FROM support_tickets t
    LEFT JOIN users u ON t.created_by = u.id
    LEFT JOIN users a ON t.assigned_to = a.id
    WHERE t.id = ?
  `, [id], (err, ticket) => {
    if (err) {
      console.error('שגיאה בטעינת כרטיס:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת כרטיס' });
    }
    
    if (!ticket) {
      return res.status(404).json({ error: 'כרטיס לא נמצא' });
    }
    
    // קבלת תגובות לכרטיס
    db.all(`
      SELECT tr.*, u.full_name as user_name
      FROM ticket_responses tr
      LEFT JOIN users u ON tr.user_id = u.id
      WHERE tr.ticket_id = ?
      ORDER BY tr.created_at ASC
    `, [id], (err, responses) => {
      if (err) {
        console.error('שגיאה בטעינת תגובות:', err);
        return res.status(500).json({ error: 'שגיאה בטעינת תגובות' });
      }
      
      ticket.responses = responses;
      res.json(ticket);
    });
  });
});

// יצירת כרטיס תמיכה חדש
app.post('/api/tickets', authenticateToken, (req, res) => {
  const { title, description, category, priority } = req.body;
  
  if (!title || !description) {
    return res.status(400).json({ error: 'כותרת ותיאור נדרשים' });
  }
  
  db.run(`
    INSERT INTO support_tickets (title, description, category, priority, created_by)
    VALUES (?, ?, ?, ?, ?)
  `, [title, description, category || 'general', priority || 'medium', req.user.id], function(err) {
    if (err) {
      console.error('שגיאה ביצירת כרטיס:', err);
      return res.status(500).json({ error: 'שגיאה ביצירת כרטיס' });
    }
    
    logActivity(req.user.id, 'יצירת_כרטיס_תמיכה', 'ticket', this.lastID, `פתח כרטיס תמיכה: ${title}`, req);
    res.json({ message: 'כרטיס נוצר בהצלחה', ticketId: this.lastID });
  });
});

// קבלת תגובות לכרטיס (עבור טלפנים)
app.get('/api/tickets/:id/responses', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  
  // בדיקה שהמשתמש הוא הבעלים של הכרטיס או אדמין
  db.get(`
    SELECT * FROM support_tickets 
    WHERE id = ? AND (created_by = ? OR ? = 'admin')
  `, [id, req.user.id, req.user.role], (err, ticket) => {
    if (err) {
      console.error('שגיאה בבדיקת כרטיס:', err);
      return res.status(500).json({ error: 'שגיאה בשרת' });
    }
    
    if (!ticket) {
      console.log('❌ כרטיס לא נמצא או אין הרשאה');
      return res.status(404).json({ error: 'כרטיס לא נמצא או אין הרשאה' });
    }
    
    console.log('✅ כרטיס נמצא, טוען תגובות...');
    
    // קבלת תגובות (רק תגובות לא פנימיות למשתמשים רגילים)
    const query = req.user.role === 'admin' ? 
      `SELECT tr.*, u.full_name as user_name
       FROM ticket_responses tr
       LEFT JOIN users u ON tr.user_id = u.id
       WHERE tr.ticket_id = ?
       ORDER BY tr.created_at ASC` :
      `SELECT tr.*, u.full_name as user_name
       FROM ticket_responses tr
       LEFT JOIN users u ON tr.user_id = u.id
       WHERE tr.ticket_id = ? AND tr.is_internal = 0
       ORDER BY tr.created_at ASC`;
    
    db.all(query, [id], (err, responses) => {
      if (err) {
        console.error('שגיאה בטעינת תגובות:', err);
        return res.status(500).json({ error: 'שגיאה בטעינת תגובות' });
      }
      
      res.json(responses);
    });
  });
});

// הוסף את זה ב-advanced-server.js אחרי ה-endpoints האחרים של tickets

// סגירת כרטיס על ידי המשתמש
app.post('/api/tickets/:id/close', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { feedback, user_closed } = req.body;
  
  // בדיקה שהמשתמש הוא הבעלים של הכרטיס
  db.get('SELECT * FROM support_tickets WHERE id = ? AND created_by = ?', [id, req.user.id], (err, ticket) => {
    if (err) {
      console.error('שגיאה בבדיקת כרטיס:', err);
      return res.status(500).json({ error: 'שגיאה בשרת' });
    }
    
    if (!ticket) {
      return res.status(404).json({ error: 'כרטיס לא נמצא או אין הרשאה' });
    }
    
    // עדכון הכרטיס לסגור
    db.run(`
      UPDATE support_tickets 
      SET status = 'closed', 
          updated_at = CURRENT_TIMESTAMP,
          resolved_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [id], function(err) {
      if (err) {
        console.error('שגיאה בסגירת כרטיס:', err);
        return res.status(500).json({ error: 'שגיאה בסגירת כרטיס' });
      }
      
      // הוספת תגובת סגירה עם משוב
      const closureMessage = user_closed ? 
        `✅ הכרטיס נסגר על ידי המשתמש\n\n📝 משוב: ${feedback || 'ללא משוב נוסף'}` :
        'הכרטיס נסגר על ידי המשתמש';
      
      db.run(`
        INSERT INTO ticket_responses (ticket_id, user_id, content, is_internal)
        VALUES (?, ?, ?, ?)
      `, [id, req.user.id, closureMessage, 0], (err) => {
        if (err) {
          console.error('שגיאה בהוספת תגובת סגירה:', err);
        }
        
        logActivity(req.user.id, 'סגירת_כרטיס_תמיכה', 'ticket', id, `סגר את כרטיס התמיכה ${id}`, req);
        res.json({ message: 'כרטיס נסגר בהצלחה' });
      });
    });
  });
});

// הוספת תגובה לכרטיס
app.post('/api/tickets/:id/responses', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { content, is_internal } = req.body;
  
  if (!content) {
    return res.status(400).json({ error: 'תוכן התגובה נדרש' });
  }
  
  
  // בדיקה שהכרטיס קיים ושהמשתמש מורשה
  db.get(`
    SELECT * FROM support_tickets 
    WHERE id = ? AND (created_by = ? OR ? = 'admin')
  `, [id, req.user.id, req.user.role], (err, ticket) => {
    if (err) {
      console.error('שגיאה בבדיקת כרטיס:', err);
      return res.status(500).json({ error: 'שגיאה בשרת' });
    }
    
    if (!ticket) {
      return res.status(404).json({ error: 'כרטיס לא נמצא או אין הרשאה' });
    }
    
    db.run(`
      INSERT INTO ticket_responses (ticket_id, user_id, content, is_internal)
      VALUES (?, ?, ?, ?)
    `, [id, req.user.id, content, is_internal || 0], function(err) {
      if (err) {
        console.error('שגיאה בהוספת תגובה:', err);
        return res.status(500).json({ error: 'שגיאה בהוספת תגובה' });
      }
      
      // עדכון זמן העדכון של הכרטיס
      db.run('UPDATE support_tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?', [id]);
      
      logActivity(req.user.id, 'הוספת_תגובה_כרטיס_תמיכה', 'ticket', id, `הגיב לכרטיס התמיכה ${id}`, req);
      res.json({ message: 'תגובה נוספה בהצלחה', responseId: this.lastID });
    });
  });
});

// === ניהול משתמשים (אדמין) ===

// קבלת רשימת משתמשים
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  db.all(`
    SELECT id, username, full_name, email, phone, department, role, is_active, 
           last_login, login_count, created_at, notes
    FROM users
    ORDER BY created_at DESC
  `, (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת משתמשים:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת משתמשים' });
    }
    res.json(rows);
  });
});

// יצירת משתמש חדש
app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  const { username, password, full_name, email, phone, department, role } = req.body;
  
  if (!username || !password || !full_name) {
    return res.status(400).json({ error: 'שם משתמש, סיסמה ושם מלא נדרשים' });
  }
  
  // בדיקה אם שם המשתמש כבר קיים
  db.get('SELECT id FROM users WHERE username = ?', [username], async (err, existingUser) => {
    if (err) {
      console.error('שגיאה בבדיקת משתמש קיים:', err);
      return res.status(500).json({ error: 'שגיאה בשרת' });
    }
    
    if (existingUser) {
      return res.status(400).json({ error: 'שם המשתמש כבר קיים במערכת' });
    }
    
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      
      db.run(`
        INSERT INTO users (username, password, full_name, email, phone, department, role, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [username, hashedPassword, full_name, email, phone, department, role || 'operator', req.user.id], function(err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(400).json({ error: 'שם המשתמש כבר קיים במערכת' });
          }
          console.error('שגיאה ביצירת משתמש:', err);
          return res.status(500).json({ error: 'שגיאה ביצירת משתמש' });
        }
        
        logActivity(req.user.id, 'CREATE_USER', 'user', this.lastID, `Created user: ${username}`, req);
        res.json({ message: 'משתמש נוצר בהצלחה', userId: this.lastID });
      });
    } catch (error) {
      console.error('שגיאה בהצפנת סיסמה:', error);
      res.status(500).json({ error: 'שגיאה בשרת' });
    }
  });
});

app.get('/api/admin/check-username/:username', authenticateToken, requireAdmin, (req, res) => {
  const { username } = req.params;
  
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('שגיאה בבדיקת שם משתמש:', err);
      return res.status(500).json({ error: 'שגיאה בשרת' });
    }
    
    res.json({ available: !user });
  });
});

// עדכון משתמש
app.put('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { full_name, email, phone, department, role, is_active, password, notes } = req.body;
  
  let updateFields = [];
  let updateValues = [];
  
  if (full_name) {
    updateFields.push('full_name = ?');
    updateValues.push(full_name);
  }
  if (email) {
    updateFields.push('email = ?');
    updateValues.push(email);
  }
  if (phone) {
    updateFields.push('phone = ?');
    updateValues.push(phone);
  }
  if (department) {
    updateFields.push('department = ?');
    updateValues.push(department);
  }
  if (role) {
    updateFields.push('role = ?');
    updateValues.push(role);
  }
  if (typeof is_active !== 'undefined') {
    updateFields.push('is_active = ?');
    updateValues.push(is_active ? 1 : 0);
  }
  if (notes !== undefined) {  // ← הוסף את הבדיקה הזו
    updateFields.push('notes = ?');
    updateValues.push(notes);
  }
  
  if (password) {
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateFields.push('password = ?');
      updateValues.push(hashedPassword);
    } catch (error) {
      return res.status(500).json({ error: 'שגיאה בעדכון סיסמה' });
    }
  }
  
if (updateFields.length === 0) {
   return res.status(400).json({ error: 'לא צוינו שדות לעדכון' });
 }
 
 updateValues.push(id);
 
 db.run(
   `UPDATE users SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
   updateValues,
   function(err) {
     if (err) {
       console.error('שגיאה בעדכון משתמש:', err);
       return res.status(500).json({ error: 'שגיאה בעדכון משתמש' });
     }
     
     if (this.changes === 0) {
       return res.status(404).json({ error: 'משתמש לא נמצא' });
     }
     
     logActivity(req.user.id, 'עדכון_משתמש', 'user', id, `עדכן משתמש ${id}`, req);
     res.json({ message: 'משתמש עודכן בהצלחה' });
   }
 );
});

// === ניהול תורמים מתקדם ===

// קבלת רשימת תורמים עם סינון
app.get('/api/admin/donors', authenticateToken, requireAdmin, (req, res) => {
  const { page = 1, limit = 50, search, city, donor_type } = req.query;
  const offset = (page - 1) * limit;
  
  let whereClause = '';
  let params = [];
  
  if (search) {
    whereClause += ' WHERE (COALESCE(name, first_name || " " || last_name) LIKE ? OR phone LIKE ? OR email LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  
  if (city) {
    whereClause += whereClause ? ' AND city LIKE ?' : ' WHERE city LIKE ?';
    params.push(`%${city}%`);
  }
  
  if (donor_type) {
    whereClause += whereClause ? ' AND donor_type = ?' : ' WHERE donor_type = ?';
    params.push(donor_type);
  }
  
  // שינוי - שאילתה שמקבצת תורמים
  const query = `
    SELECT 
      MIN(id) as id,
      COALESCE(name, first_name || ' ' || last_name) as name,
      phone,
      email,
      city,
      COUNT(*) as donations_count,
      SUM(
        CASE 
          WHEN payment_amount LIKE '%₪%' 
          THEN CAST(REPLACE(REPLACE(payment_amount, '₪', ''), ' ', '') AS DECIMAL)
          WHEN donation_amount IS NOT NULL
          THEN CAST(donation_amount AS DECIMAL)
          ELSE 0
        END
      ) as total_amount,
      MIN(created_at) as created_at,
      MAX(updated_at) as updated_at,
      GROUP_CONCAT(DISTINCT donor_type) as donor_type,
      'active' as status
    FROM donors 
    ${whereClause}
    GROUP BY 
      COALESCE(name, first_name || ' ' || last_name),
      phone
    ORDER BY MAX(updated_at) DESC
    LIMIT ? OFFSET ?
  `;
  
  db.all(query, [...params, limit, offset], (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת תורמים:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת תורמים' });
    }
    
    // ספירת סה"כ תוצאות
    const countQuery = `
      SELECT COUNT(*) as total FROM (
        SELECT 
          COALESCE(name, first_name || ' ' || last_name) as name,
          phone
        FROM donors 
        ${whereClause}
        GROUP BY 
          COALESCE(name, first_name || ' ' || last_name),
          phone
      )
    `;
    
    db.get(countQuery, params, (err, countRow) => {
      if (err) {
        console.error('שגיאה בספירת תורמים:', err);
        return res.status(500).json({ error: 'שגיאה בספירת תורמים' });
      }
      
      res.json({
        donors: rows,
        total: countRow.total,
        page: parseInt(page),
        totalPages: Math.ceil(countRow.total / limit)
      });
    });
  });
});

// הוספת תורם חדש
app.post('/api/admin/donors', authenticateToken, requireAdmin, (req, res) => {
 const { name, phone, email, address, city, area, donation_amount, donor_type, notes } = req.body;
 
 if (!name || !phone) {
   return res.status(400).json({ error: 'שם וטלפון נדרשים' });
 }
 
 db.run(`
   INSERT INTO donors (name, phone, email, address, city, area, donation_amount, donor_type, notes, created_by)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
 `, [name, phone, email, address, city, area, donation_amount, donor_type, notes, req.user.id], function(err) {
   if (err) {
     console.error('שגיאה בהוספת תורם:', err);
     return res.status(500).json({ error: 'שגיאה בהוספת תורם' });
   }
   
   logActivity(req.user.id, 'הוספת_תורם', 'donor', this.lastID, `הוסיף תורם : ${name}`, req);
   res.json({ message: 'תורם נוסף בהצלחה', donorId: this.lastID });
 });
});

// עדכון תורם
app.put('/api/admin/donors/:id', authenticateToken, requireAdmin, (req, res) => {
 const { id } = req.params;
 const { name, phone, email, address, city, area, donation_amount, donor_type, status, notes } = req.body;
 
 db.run(`
   UPDATE donors 
   SET name = ?, phone = ?, email = ?, address = ?, city = ?, area = ?, 
       donation_amount = ?, donor_type = ?, status = ?, notes = ?, 
       updated_by = ?, updated_at = CURRENT_TIMESTAMP
   WHERE id = ?
 `, [name, phone, email, address, city, area, donation_amount, donor_type, status, notes, req.user.id, id], function(err) {
   if (err) {
     console.error('שגיאה בעדכון תורם:', err);
     return res.status(500).json({ error: 'שגיאה בעדכון תורם' });
   }
   
   if (this.changes === 0) {
     return res.status(404).json({ error: 'תורם לא נמצא' });
   }
   
   logActivity(req.user.id, 'עדכון_פרטי_תורם', 'donor', id, `עדכן פרטי תורם ${id}`, req);
   res.json({ message: 'תורם עודכן בהצלחה' });
 });
});

// מחיקת תורם
app.delete('/api/admin/donors/:id', authenticateToken, requireAdmin, (req, res) => {
 const { id } = req.params;
 
 db.run('DELETE FROM donors WHERE id = ?', [id], function(err) {
   if (err) {
     console.error('שגיאה במחיקת תורם:', err);
     return res.status(500).json({ error: 'שגיאה במחיקת תורם' });
   }
   
   if (this.changes === 0) {
     return res.status(404).json({ error: 'תורם לא נמצא' });
   }
   
   logActivity(req.user.id, 'מחיקת_תורם', 'donor', id, `מחק את התורם מהרשימה ${id}`, req);
   res.json({ message: 'תורם נמחק בהצלחה' });
 });
});

// === דוחות וסטטיסטיקות ===

// דוח פעילות כללי
app.get('/api/admin/reports/activity', authenticateToken, requireAdmin, (req, res) => {
 const { from_date, to_date, user_id } = req.query;
 
 let whereClause = '';
 let params = [];
 
 if (from_date) {
   whereClause += ' WHERE created_at >= ?';
   params.push(from_date);
 }
 
 if (to_date) {
   whereClause += whereClause ? ' AND created_at <= ?' : ' WHERE created_at <= ?';
   params.push(to_date);
 }
 
 if (user_id) {
   whereClause += whereClause ? ' AND user_id = ?' : ' WHERE user_id = ?';
   params.push(user_id);
 }
 
 db.all(`
   SELECT 
     DATE(created_at) as date,
     action,
     COUNT(*) as count,
     user_id
   FROM activity_logs
   ${whereClause}
   GROUP BY DATE(created_at), action, user_id
   ORDER BY date DESC, count DESC
 `, params, (err, rows) => {
   if (err) {
     console.error('שגיאה בדוח פעילות:', err);
     return res.status(500).json({ error: 'שגיאה ביצירת דוח' });
   }
   res.json(rows);
 });
});

// סטטיסטיקות חיפושים
app.get('/api/admin/reports/searches', authenticateToken, requireAdmin, (req, res) => {
 const { from_date, to_date } = req.query;
 
 let whereClause = '';
 let params = [];
 
 if (from_date) {
   whereClause += ' WHERE created_at >= ?';
   params.push(from_date);
 }
 
 if (to_date) {
   whereClause += whereClause ? ' AND created_at <= ?' : ' WHERE created_at <= ?';
   params.push(to_date);
 }
 
 db.all(`
   SELECT 
     u.username,
     u.full_name,
     COUNT(sh.id) as total_searches,
     COUNT(DISTINCT sh.search_term) as unique_searches,
     AVG(sh.results_count) as avg_results,
     DATE(sh.created_at) as search_date
   FROM search_history sh
   JOIN users u ON sh.user_id = u.id
   ${whereClause}
   GROUP BY u.id, DATE(sh.created_at)
   ORDER BY search_date DESC, total_searches DESC
 `, params, (err, rows) => {
   if (err) {
     console.error('שגיאה בדוח חיפושים:', err);
     return res.status(500).json({ error: 'שגיאה ביצירת דוח' });
   }
   res.json(rows);
 });
});

// דפוסי עבודה של טלפנים
app.get('/api/admin/reports/work-patterns', authenticateToken, requireAdmin, (req, res) => {
 db.all(`
   SELECT 
     u.username,
     u.full_name,
     strftime('%H', al.created_at) as hour,
     COUNT(*) as activity_count
   FROM activity_logs al
   JOIN users u ON al.user_id = u.id
   WHERE al.action = 'SEARCH'
   AND al.created_at >= date('now', '-30 days')
   GROUP BY u.id, strftime('%H', al.created_at)
   ORDER BY u.username, hour
 `, (err, rows) => {
   if (err) {
     console.error('שגיאה בדוח דפוסי עבודה:', err);
     return res.status(500).json({ error: 'שגיאה ביצירת דוח' });
   }
   res.json(rows);
 });
});

// === העלאת CSV מתקדמת ===

app.post('/api/admin/upload-csv', authenticateToken, requireAdmin, upload.single('csvFile'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'לא נבחר קובץ' });
  }
  
  const filePath = req.file.path;
  const fileName = req.file.originalname; // שמירת שם הקובץ המקורי
  const donors = [];
  let processed = 0;
  let duplicates = 0;
  let errors = [];
  
  console.log(`📁 מעבד קובץ: ${fileName}`);
  
  fs.createReadStream(filePath, { encoding: 'utf8' })
    .pipe(csv({
      skipEmptyLines: true
    }))
    .on('data', (row) => {
      donors.push(row);
    })
    .on('end', () => {
      console.log(`📊 נמצאו ${donors.length} שורות בקובץ`);
      
      const batchSize = 100;
      
      const processBatch = (startIndex) => {
        const batch = donors.slice(startIndex, startIndex + batchSize);
        
        if (batch.length === 0) {
          fs.unlinkSync(filePath);
          
          // רישום בהיסטוריית העלאות עם הנתונים הנכונים
          db.run(`
            INSERT INTO activity_logs (user_id, action, target_type, target_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
          `, [
            req.user.id, 
            'CSV_UPLOAD', 
            'donor', 
            null, 
            `File: ${fileName}, Uploaded ${processed} donors, ${duplicates} duplicates, ${errors.length} errors`,
            req.ip
          ]);
          
          res.json({
            message: `הועלו בהצלחה ${processed} תרומות מהקובץ ${fileName}`,
            processed: processed,
            duplicates: duplicates,
            errors: errors.length,
            errorDetails: errors.slice(0, 10)
          });
          return;
        }
        
        batch.forEach((donor, index) => {
          try {
            const fullName = `${donor['שם'] || ''} ${donor['משפחה'] || ''}`.trim();
            const orderNumber = donor['מספר הזמנה'] || '';
            const phone = donor['טלפון'] || '';
            
            // בדיקת כפילויות - רק אם יש בדיוק אותו מספר הזמנה
            if (orderNumber) {
              db.get(
                'SELECT id FROM donors WHERE order_number = ?',
                [orderNumber],
                (err, existingDonor) => {
                  if (err) {
                    errors.push(`שורה ${startIndex + index + 1}: שגיאה בבדיקת כפילויות - ${err.message}`);
                    return;
                  }
                  
                  if (existingDonor) {
                    duplicates++;
                    console.log(`🔄 כפילות נמצאה: הזמנה ${orderNumber}`);
                    return;
                  }
                  
                  // הוספת הרשומה החדשה
                  insertDonor();
                }
              );
            } else {
              insertDonor();
            }
            
            function insertDonor() {
              db.run(`
                INSERT INTO donors (
                  order_number, project_name, prayer_name, first_name, last_name,
                  name, phone, email, city, street, building, apartment,
                  payment_amount, payment_method, payment_status, comments,
                  delivery_date, fix_date, death_date_month, death_date_day,
                  marketing_source, traffic_source, campaign_name, type_field,
                  keywords, content_field, datetime_field, created_field,
                  last_modified, project_id, quantity, phone_copy, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `, [
                orderNumber,
                donor['שם הפרויקט'] || '',
                donor['השם לתפילה'] || '',
                donor['שם'] || '',
                donor['משפחה'] || '',
                fullName || null,
                phone,
                donor['מייל'] || '',
                donor['עיר'] || '',
                donor['רחוב'] || '',
                donor['בניין'] || '',
                donor['דירה'] || '',
                donor['כמה שולם/מחיר לשם'] || '',
                donor['צורת תשלום'] || '',
                donor['סטטוס'] || '',
                donor['הערות'] || '',
                donor['תאריך מסירה'] || '',
                donor['תאריך התיקון'] || '',
                donor['תאריך פטירה חודש'] || '',
                donor['תאריך פטירה יום'] || '',
                donor['אמצעי שיווקי'] || '',
                donor['מקור תנועה'] || '',
                donor['שם הקמפין'] || '',
                donor['סוג'] || '',
                donor['מילות מפתח'] || '',
                donor['תוכן'] || '',
                donor['תאריך ושעה'] || '',
                donor['נוצר'] || '',
                donor['שונה לאחרונה'] || '',
                donor['מזהה פרויקט'] || '',
                parseInt(donor['כמות']) || 1,
                donor['טלפון copy'] || '',
                req.user.id
              ], function(err) {
                if (err) {
                  errors.push(`שורה ${startIndex + index + 1}: ${err.message}`);
                } else {
                  processed++;
                  console.log(`✅ נוסף תורם: ${fullName}, הזמנה: ${orderNumber}`);
                }
              });
            }
            
          } catch (error) {
            errors.push(`שורה ${startIndex + index + 1}: ${error.message}`);
          }
        });
        
        // המשך לבאצ' הבא אחרי זמן קצר
        setTimeout(() => processBatch(startIndex + batchSize), 500);
      };
      
      processBatch(0);
    })
    .on('error', (error) => {
      console.error('שגיאה בקריאת CSV:', error);
      fs.unlinkSync(filePath);
      res.status(500).json({ error: 'שגיאה בעיבוד הקובץ' });
    });
});

// === סטטיסטיקות כלליות ===

app.get('/api/stats', authenticateToken, (req, res) => {
 Promise.all([
   new Promise((resolve, reject) => {
     db.get('SELECT COUNT(*) as count FROM donors WHERE status = "active"', (err, row) => {
       if (err) reject(err);
       else resolve({ totalDonors: row.count });
     });
   }),
   new Promise((resolve, reject) => {
     db.get('SELECT COUNT(*) as count FROM users WHERE is_active = 1', (err, row) => {
       if (err) reject(err);
       else resolve({ totalUsers: row.count });
     });
   }),
   new Promise((resolve, reject) => {
     db.get(`
       SELECT COUNT(*) as count FROM search_history 
       WHERE created_at > date('now', '-1 day')
     `, (err, row) => {
       if (err) reject(err);
       else resolve({ searchesToday: row.count });
     });
   }),
   new Promise((resolve, reject) => {
     if (req.user.role === 'admin') {
       db.get(`
         SELECT COUNT(*) as count FROM support_tickets 
         WHERE status != 'closed'
       `, (err, row) => {
         if (err) reject(err);
         else resolve({ openTickets: row.count });
       });
     } else {
       resolve({ openTickets: 0 });
     }
   })
 ]).then(results => {
   const stats = Object.assign({}, ...results);
   res.json(stats);
 }).catch(error => {
   console.error('שגיאה בסטטיסטיקות:', error);
   res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
 });
});

// הוסף את הקוד הזה ל-advanced-server.js בסוף הקובץ, לפני הפעלת השרת

// === API Endpoints חסרים ===

// === ניהול תורמים מתקדם ===

// עריכה קבוצתית של תורמים
app.post('/api/admin/donors/bulk-edit', authenticateToken, requireAdmin, (req, res) => {
  const { donor_ids, updates } = req.body;
  
  if (!donor_ids || !Array.isArray(donor_ids) || donor_ids.length === 0) {
    return res.status(400).json({ error: 'נדרשים מזהי תורמים' });
  }
  
  if (!updates || Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'נדרשים עדכונים' });
  }
  
  let updateFields = [];
  let updateValues = [];
  
  if (updates.city) {
    updateFields.push('city = ?');
    updateValues.push(updates.city);
  }
  if (updates.donor_type) {
    updateFields.push('donor_type = ?');
    updateValues.push(updates.donor_type);
  }
  if (updates.status) {
    updateFields.push('status = ?');
    updateValues.push(updates.status);
  }
  
  if (updateFields.length === 0) {
    return res.status(400).json({ error: 'לא צוינו שדות לעדכון' });
  }
  
  updateFields.push('updated_by = ?', 'updated_at = CURRENT_TIMESTAMP');
  updateValues.push(req.user.id);
  
  const placeholders = donor_ids.map(() => '?').join(',');
  const query = `
    UPDATE donors 
    SET ${updateFields.join(', ')}
    WHERE id IN (${placeholders})
  `;
  
  db.run(query, [...updateValues, ...donor_ids], function(err) {
    if (err) {
      console.error('שגיאה בעריכה קבוצתית:', err);
      return res.status(500).json({ error: 'שגיאה בעריכה קבוצתית' });
    }
    
    logActivity(req.user.id, 'עריכת_תורמים_קבוצתית', 'donor', null, 
      `Bulk updated ${this.changes} donors`, req);
    res.json({ 
      message: `${this.changes} תורמים עודכנו בהצלחה`,
      updated: this.changes 
    });
  });
});

// מחיקה קבוצתית של תורמים
app.post('/api/admin/donors/bulk-delete', authenticateToken, requireAdmin, (req, res) => {
  const { donor_ids } = req.body;
  
  if (!donor_ids || !Array.isArray(donor_ids) || donor_ids.length === 0) {
    return res.status(400).json({ error: 'נדרשים מזהי תורמים למחיקה' });
  }
  
  const placeholders = donor_ids.map(() => '?').join(',');
  
  db.run(`DELETE FROM donors WHERE id IN (${placeholders})`, donor_ids, function(err) {
    if (err) {
      console.error('שגיאה במחיקה קבוצתית:', err);
      return res.status(500).json({ error: 'שגיאה במחיקה קבוצתית' });
    }
    
    logActivity(req.user.id, 'מחיקת_תורמים_קבוצתית', 'donor', null, 
      `Bulk deleted ${this.changes} donors`, req);
    res.json({ 
      message: `${this.changes} תורמים נמחקו בהצלחה`,
      deleted: this.changes 
    });
  });
});

// === ניהול משתמשים מתקדם ===

// מחיקת משתמש
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  
  // בדיקה שלא מוחקים את עצמו
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'לא ניתן למחוק את עצמך' });
  }
  
  db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
    if (err) {
      console.error('שגיאה במחיקת משתמש:', err);
      return res.status(500).json({ error: 'שגיאה במחיקת משתמש' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'משתמש לא נמצא' });
    }
    
    logActivity(req.user.id, 'מחיקת_משתמש', 'user', id, `מחק את המשתמש ${id}`, req);
    res.json({ message: 'משתמש נמחק בהצלחה' });
  });
});

// איפוס סיסמה
app.post('/api/admin/users/:id/reset-password', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { new_password } = req.body;
  
  if (!new_password || new_password.length < 6) {
    return res.status(400).json({ error: 'סיסמה חדשה נדרשת (מינימום 6 תווים)' });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(new_password, 10);
    
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, id], function(err) {
      if (err) {
        console.error('שגיאה באיפוס סיסמה:', err);
        return res.status(500).json({ error: 'שגיאה באיפוס סיסמה' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'משתמש לא נמצא' });
      }
      
      logActivity(req.user.id, 'איפוס_סיסמה', 'user', id, `איפס את הסיסמה עבור המשתמש ${id}`, req);
      res.json({ message: 'סיסמה אופסה בהצלחה' });
    });
  } catch (error) {
    console.error('שגיאה בהצפנת סיסמה:', error);
    res.status(500).json({ error: 'שגיאה בשרת' });
  }
});

// === ניהול הודעות מתקדם ===

// קבלת כל הודעות המערכת (אדמין)
app.get('/api/admin/messages', authenticateToken, requireAdmin, (req, res) => {
  db.all(`
    SELECT m.*, u.username as creator_name
    FROM system_messages m
    LEFT JOIN users u ON m.created_by = u.id
    ORDER BY m.created_at DESC
  `, (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת הודעות:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת הודעות' });
    }
    res.json(rows);
  });
});

// עדכון הודעה
app.put('/api/admin/messages/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { title, content, type, target_role, target_user_id, is_active, expires_at } = req.body;
  
  db.run(`
    UPDATE system_messages 
    SET title = ?, content = ?, type = ?, target_role = ?, target_user_id = ?, 
        is_active = ?, expires_at = ?
    WHERE id = ?
  `, [title, content, type, target_role, target_user_id, is_active ? 1 : 0, expires_at, id], function(err) {
    if (err) {
      console.error('שגיאה בעדכון הודעה:', err);
      return res.status(500).json({ error: 'שגיאה בעדכון הודעה' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'הודעה לא נמצאה' });
    }
    
    logActivity(req.user.id, 'עדכון_הודעה', 'message', id, `עדכן הודעה ${id}`, req);
    res.json({ message: 'הודעה עודכנה בהצלחה' });
  });
});

// מחיקת הודעה
app.delete('/api/admin/messages/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM system_messages WHERE id = ?', [id], function(err) {
    if (err) {
      console.error('שגיאה במחיקת הודעה:', err);
      return res.status(500).json({ error: 'שגיאה במחיקת הודעה' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'הודעה לא נמצאה' });
    }
    
    logActivity(req.user.id, 'מחיקת_הודעה', 'message', id, `מחק הודעה ${id}`, req);
    res.json({ message: 'הודעה נמחקה בהצלחה' });
  });
});

// === כרטיסי תמיכה (אדמין) ===

// עדכון סטטוס כרטיס
app.put('/api/admin/tickets/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { status, assigned_to } = req.body;
  
  let updateFields = ['updated_at = CURRENT_TIMESTAMP'];
  let updateValues = [];
  
  if (status) {
    updateFields.push('status = ?');
    updateValues.push(status);
    
    if (status === 'resolved' || status === 'closed') {
      updateFields.push('resolved_at = CURRENT_TIMESTAMP');
    }
  }
  
  if (assigned_to !== undefined) {
    updateFields.push('assigned_to = ?');
    updateValues.push(assigned_to);
  }
  
  updateValues.push(id);
  
  db.run(`UPDATE support_tickets SET ${updateFields.join(', ')} WHERE id = ?`, updateValues, function(err) {
    if (err) {
      console.error('שגיאה בעדכון כרטיס:', err);
      return res.status(500).json({ error: 'שגיאה בעדכון כרטיס' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'כרטיס לא נמצא' });
    }
    
    logActivity(req.user.id, 'עדכון_כרטיס_תמיכה', 'ticket', id, `עדכן את כרטיס התמיכה ${id}`, req);
    res.json({ message: 'כרטיס עודכן בהצלחה' });
  });
});

// הקצאת מטפל לכרטיס
app.post('/api/admin/tickets/:id/assign', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { assigned_to } = req.body;
  
  db.run(`
    UPDATE support_tickets 
    SET assigned_to = ?, status = 'in_progress', updated_at = CURRENT_TIMESTAMP 
    WHERE id = ?
  `, [assigned_to, id], function(err) {
    if (err) {
      console.error('שגיאה בהקצאת כרטיס:', err);
      return res.status(500).json({ error: 'שגיאה בהקצאת כרטיס' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'כרטיס לא נמצא' });
    }
    
    logActivity(req.user.id, 'הקצאת_כרטיס_תמיכה', 'ticket', id, `הקצה את כרטיס התמיכה ${id} עבור המנהל ${assigned_to}`, req);
    res.json({ message: 'כרטיס הוקצה בהצלחה' });
  });
});

// תגובת אדמין לכרטיס
app.post('/api/admin/tickets/:id/response', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { content, is_internal } = req.body;
  
  if (!content) {
    return res.status(400).json({ error: 'תוכן התגובה נדרש' });
  }
  
  db.run(`
    INSERT INTO ticket_responses (ticket_id, user_id, content, is_internal)
    VALUES (?, ?, ?, ?)
  `, [id, req.user.id, content, is_internal || 0], function(err) {
    if (err) {
      console.error('שגיאה בהוספת תגובה:', err);
      return res.status(500).json({ error: 'שגיאה בהוספת תגובה' });
    }
    
    // עדכון זמן העדכון של הכרטיס
    db.run('UPDATE support_tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?', [id]);
    
    // איפוס סימון קריאה כשאדמין מגיב
    db.run('UPDATE support_tickets SET user_read_admin_response = 0 WHERE id = ?', [id]);
    
    // אם זו תגובה לא פנימית, צור הודעת מערכת למשתמש
    if (!is_internal) {
      db.get('SELECT created_by FROM support_tickets WHERE id = ?', [id], (err, ticket) => {
        if (!err && ticket) {
          db.run(`
            INSERT INTO system_messages (title, content, type, target_user_id, created_by)
            VALUES (?, ?, ?, ?, ?)
          `, [
            'תגובה חדשה לכרטיס התמיכה',
            `יש תגובה חדשה לכרטיס התמיכה שלך #${id}. היכנס למערכת לצפייה בתגובה.`,
            'info',
            ticket.created_by,
            req.user.id
          ]);
        }
      });
    }
    
    logActivity(req.user.id, 'תגובה_כרטיס_תמיכה', 'ticket', id, `הגיב לכרטיס התמיכה ${id}`, req);
    res.json({ message: 'תגובה נוספה בהצלחה', responseId: this.lastID });
  });
});

// === לוגי מערכת מתקדמים ===

// קבלת לוגים מסוננים
app.get('/api/admin/logs', authenticateToken, requireAdmin, (req, res) => {
  const { 
    user_id, 
    action, 
    from_date, 
    to_date, 
    page = 1, 
    limit = 100 
  } = req.query;
  
  const offset = (page - 1) * limit;
  
  let whereClause = '';
  let params = [];
  
  if (user_id) {
    whereClause += ' WHERE al.user_id = ?';
    params.push(user_id);
  }
  
  if (action) {
    whereClause += whereClause ? ' AND al.action = ?' : ' WHERE al.action = ?';
    params.push(action);
  }
  
  if (from_date) {
    whereClause += whereClause ? ' AND al.created_at >= ?' : ' WHERE al.created_at >= ?';
    params.push(from_date);
  }
  
  if (to_date) {
    whereClause += whereClause ? ' AND al.created_at <= ?' : ' WHERE al.created_at <= ?';
    params.push(to_date);
  }
  
  db.all(`
    SELECT al.*, u.username, u.full_name
    FROM activity_logs al
    LEFT JOIN users u ON al.user_id = u.id
    ${whereClause}
    ORDER BY al.created_at DESC
    LIMIT ? OFFSET ?
  `, [...params, limit, offset], (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת לוגים:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת לוגים' });
    }
    
    // ספירת סה"כ תוצאות
    db.get(`
      SELECT COUNT(*) as total 
      FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ${whereClause}
    `, params, (err, countRow) => {
      if (err) {
        console.error('שגיאה בספירת לוגים:', err);
        return res.status(500).json({ error: 'שגיאה בספירת לוגים' });
      }
      
      res.json({
        logs: rows,
        total: countRow.total,
        page: parseInt(page),
        totalPages: Math.ceil(countRow.total / limit)
      });
    });
  });
});

// לוגי משתמש ספציפי
app.get('/api/admin/logs/user/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { limit = 50 } = req.query;
  
  db.all(`
    SELECT al.*, u.username, u.full_name
    FROM activity_logs al
    LEFT JOIN users u ON al.user_id = u.id
    WHERE al.user_id = ?
    ORDER BY al.created_at DESC
    LIMIT ?
  `, [id, limit], (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת לוגי משתמש:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת לוגים' });
    }
    res.json(rows);
  });
});

// ניקוי לוגים ישנים
app.delete('/api/admin/logs/cleanup', authenticateToken, requireAdmin, (req, res) => {
  const { days_old = 90 } = req.body;
  
  db.run(`
    DELETE FROM activity_logs 
    WHERE created_at < date('now', '-${parseInt(days_old)} days')
  `, function(err) {
    if (err) {
      console.error('שגיאה בניקוי לוגים:', err);
      return res.status(500).json({ error: 'שגיאה בניקוי לוגים' });
    }
    
    logActivity(req.user.id, 'ניקוי_לוגים', 'system', null, 
      `Cleaned up ${this.changes} old log entries`, req);
    res.json({ 
      message: `${this.changes} רשומות לוג ישנות נוקו בהצלחה`,
      deleted: this.changes 
    });
  });
});

// === העלאת CSV מתקדמת ===

// היסטוריית העלאות
app.get('/api/admin/upload-history', authenticateToken, requireAdmin, (req, res) => {
  db.all(`
    SELECT 
      al.*,
      u.username, 
      u.full_name,
      CASE 
        WHEN al.details LIKE '%File:%' THEN 
          SUBSTR(al.details, INSTR(al.details, 'File:') + 6, 
                 INSTR(al.details, ',') - INSTR(al.details, 'File:') - 6)
        ELSE 'donors.csv'
      END as file_name,
      CASE 
        WHEN al.details LIKE '%Uploaded%' THEN 
          CAST(SUBSTR(al.details, INSTR(al.details, 'Uploaded ') + 9, 
                     INSTR(al.details, ' donors') - INSTR(al.details, 'Uploaded ') - 9) AS INTEGER)
        ELSE 0
      END as uploaded_count,
      CASE 
        WHEN al.details LIKE '%duplicates%' THEN 
          CAST(SUBSTR(al.details, INSTR(al.details, ', ') + 2, 
                     INSTR(al.details, ' duplicates') - INSTR(al.details, ', ') - 2) AS INTEGER)
        ELSE 0
      END as duplicates_count,
      CASE 
        WHEN al.details LIKE '%errors%' THEN 
          CAST(SUBSTR(al.details, INSTR(al.details, 'duplicates, ') + 12, 
                     INSTR(al.details, ' errors') - INSTR(al.details, 'duplicates, ') - 12) AS INTEGER)
        ELSE 0
      END as errors_count
    FROM activity_logs al
    LEFT JOIN users u ON al.user_id = u.id
    WHERE al.action = 'CSV_UPLOAD'
    ORDER BY al.created_at DESC
    LIMIT 50
  `, (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת היסטוריית העלאות:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
    }
    res.json(rows);
  });
});

// בדיקת איכות נתונים
app.post('/api/admin/data-quality', authenticateToken, requireAdmin, (req, res) => {
  const queries = [
    { name: 'תורמים ללא שם', query: 'SELECT COUNT(*) as count FROM donors WHERE name IS NULL OR name = ""' },
    { name: 'תורמים ללא טלפון', query: 'SELECT COUNT(*) as count FROM donors WHERE phone IS NULL OR phone = ""' },
    { name: 'כפילויות בטלפון', query: 'SELECT phone, COUNT(*) as count FROM donors WHERE phone IS NOT NULL AND phone != "" GROUP BY phone HAVING COUNT(*) > 1' },
    { name: 'אימיילים לא תקינים', query: 'SELECT COUNT(*) as count FROM donors WHERE email IS NOT NULL AND email != "" AND email NOT LIKE "%@%.%"' }
  ];
  
  const results = {};
  let completed = 0;
  
  queries.forEach(query => {
    db.all(query.query, (err, rows) => {
      if (err) {
        console.error(`שגיאה בבדיקת ${query.name}:`, err);
        results[query.name] = { error: err.message };
      } else {
        if (query.name === 'כפילויות בטלפון') {
          results[query.name] = rows;
        } else {
          results[query.name] = rows[0].count;
        }
      }
      
      completed++;
      if (completed === queries.length) {
        res.json(results);
      }
    });
  });
});

// ניקוי כפילויות
app.post('/api/admin/cleanup-duplicates', authenticateToken, requireAdmin, (req, res) => {
  // מחיקת כפילויות על פי מספר הזמנה זהה
  db.run(`
    DELETE FROM donors 
    WHERE id NOT IN (
      SELECT MIN(id) 
      FROM donors 
      WHERE order_number IS NOT NULL AND order_number != ""
      GROUP BY order_number
    )
    AND order_number IS NOT NULL AND order_number != ""
  `, function(err) {
    if (err) {
      console.error('שגיאה בניקוי כפילויות:', err);
      return res.status(500).json({ error: 'שגיאה בניקוי כפילויות' });
    }
    
    logActivity(req.user.id, 'CLEANUP_DUPLICATES', 'donor', null, 
      `Removed ${this.changes} duplicate donors by order_number`, req);
    res.json({ 
      message: `${this.changes} תורמים כפולים הוסרו בהצלחה`,
      removed: this.changes 
    });
  });
});

// === גיבוי ושחזור ===

// יצירת גיבוי
app.get('/api/admin/backup', authenticateToken, requireAdmin, (req, res) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = `C:/DonationApp/backups/backup_${timestamp}.sql`;
  
  // יצירת תיקיית גיבויים אם לא קיימת
  const backupDir = 'C:/DonationApp/backups';
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }
  
  // פשוט מעתיק את קובץ מסד הנתונים
  const sourcePath = 'C:/DonationApp/advanced_database.sqlite';
  
  fs.copyFile(sourcePath, backupPath, (err) => {
    if (err) {
      console.error('שגיאה ביצירת גיבוי:', err);
      return res.status(500).json({ error: 'שגיאה ביצירת גיבוי' });
    }
    
    logActivity(req.user.id, 'יצירת_גיבוי', 'system', null, `הגיבוי נוצר בהצלחה : ${backupPath}`, req);
    res.json({ 
      message: 'גיבוי נוצר בהצלחה',
      backupPath: backupPath,
      timestamp: timestamp
    });
  });
});

// בדיקת תקינות מערכת
app.get('/api/admin/system-health', authenticateToken, requireAdmin, (req, res) => {
  const healthChecks = [];
  
  Promise.all([
    // בדיקת חיבור למסד נתונים
    new Promise((resolve) => {
      db.get('SELECT 1', (err) => {
        healthChecks.push({
          component: 'Database',
          status: err ? 'ERROR' : 'OK',
          message: err ? err.message : 'Connected'
        });
        resolve();
      });
    }),
    
    // בדיקת נפח דיסק
    new Promise((resolve) => {
      try {
        const stats = fs.statSync('C:/DonationApp/advanced_database.sqlite');
        const sizeInMB = (stats.size / (1024 * 1024)).toFixed(2);
        healthChecks.push({
          component: 'Storage',
          status: 'OK',
          message: `Database size: ${sizeInMB} MB`
        });
      } catch (error) {
        healthChecks.push({
          component: 'Storage',
          status: 'ERROR',
          message: error.message
        });
      }
      resolve();
    }),
    
    // בדיקת זמן תגובה
    new Promise((resolve) => {
      const start = Date.now();
      db.get('SELECT COUNT(*) FROM donors', (err) => {
        const responseTime = Date.now() - start;
        healthChecks.push({
          component: 'Performance',
          status: responseTime < 1000 ? 'OK' : 'WARNING',
          message: `Query response time: ${responseTime}ms`
        });
        resolve();
      });
    })
  ]).then(() => {
    const overallStatus = healthChecks.every(check => check.status === 'OK') ? 'HEALTHY' : 
                         healthChecks.some(check => check.status === 'ERROR') ? 'UNHEALTHY' : 'WARNING';
    
    res.json({
      overallStatus,
      timestamp: new Date().toISOString(),
      checks: healthChecks
    });
  });
});

// === נתוני לוח בקרה מתקדם ===

// נתוני לוח הבקרה
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, (req, res) => {
  Promise.all([
    // סה"כ תורמים
    new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM donors WHERE status = "active"', (err, row) => {
        if (err) reject(err);
        else resolve({ totalDonors: row.count });
      });
    }),
    
    // סה"כ משתמשים
    new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM users WHERE is_active = 1', (err, row) => {
        if (err) reject(err);
        else resolve({ totalUsers: row.count });
      });
    }),
    
    // חיפושים היום
    new Promise((resolve, reject) => {
      db.get(`
        SELECT COUNT(*) as count FROM search_history 
        WHERE date(created_at) = date('now')
      `, (err, row) => {
        if (err) reject(err);
        else resolve({ totalSearches: row.count });
      });
    }),
    
    // כרטיסי תמיכה פתוחים
    new Promise((resolve, reject) => {
      db.get(`
        SELECT COUNT(*) as count FROM support_tickets 
        WHERE status IN ('open', 'in_progress')
      `, (err, row) => {
        if (err) reject(err);
        else resolve({ openTickets: row.count });
      });
    }),
    
    // פעילות יומית
    new Promise((resolve, reject) => {
      db.get(`
        SELECT COUNT(DISTINCT user_id) as count FROM activity_logs 
        WHERE date(created_at) = date('now')
      `, (err, row) => {
        if (err) reject(err);
        else resolve({ dailyActivity: row.count });
      });
    }),
    
	// שינויים השבוע (תורמים)
    new Promise((resolve, reject) => {
      db.get(`
        SELECT COUNT(*) as count FROM donors 
        WHERE created_at >= date('now', '-7 days')
      `, (err, row) => {
        if (err) reject(err);
        else resolve({ donorsChange: row.count });
      });
    }),
    
    // שינויים החודש (משתמשים)
    new Promise((resolve, reject) => {
      db.get(`
        SELECT COUNT(*) as count FROM users 
        WHERE created_at >= date('now', '-30 days')
      `, (err, row) => {
        if (err) reject(err);
        else resolve({ usersChange: row.count });
      });
    }),
    
    // שינוי חיפושים מאתמול
    new Promise((resolve, reject) => {
      db.all(`
        SELECT 
          (SELECT COUNT(*) FROM search_history WHERE date(created_at) = date('now')) as today,
          (SELECT COUNT(*) FROM search_history WHERE date(created_at) = date('now', '-1 day')) as yesterday
      `, (err, row) => {
        if (err) reject(err);
        else {
          const today = row[0].today || 0;
          const yesterday = row[0].yesterday || 1;
          const change = Math.round(((today - yesterday) / yesterday) * 100);
          resolve({ searchesChange: change });
        }
      });
    }),
    
    // שינוי כרטיסים מאתמול
    new Promise((resolve, reject) => {
      db.get(`
        SELECT COUNT(*) as count FROM support_tickets 
        WHERE date(created_at) = date('now', '-1 day') AND status = 'closed'
      `, (err, row) => {
        if (err) reject(err);
        else resolve({ ticketsChange: row.count });
      });
    })
  ]).then(results => {
    const dashboardData = Object.assign({}, ...results);
    res.json(dashboardData);
  }).catch(error => {
    console.error('שגיאה בנתוני לוח בקרה:', error);
    res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
  });
});

// פעילות אחרונה
app.get('/api/admin/recent-activity', authenticateToken, requireAdmin, (req, res) => {
  db.all(`
    SELECT al.*, u.username, u.full_name
    FROM activity_logs al
    LEFT JOIN users u ON al.user_id = u.id
    ORDER BY al.created_at DESC
    LIMIT 20
  `, (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת פעילות אחרונה:', error);
      return res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
    }
    res.json(rows);
  });
});

// === הערות אישיות ===

// קבלת ההערות שלי
app.get('/api/my-notes', authenticateToken, (req, res) => {
  db.all(`
    SELECT un.*, d.name as donor_name, d.phone as donor_phone
    FROM user_notes un
    JOIN donors d ON un.donor_id = d.id
    WHERE un.user_id = ?
    ORDER BY un.created_at DESC
  `, [req.user.id], (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת הערות:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת הערות' });
    }
    res.json(rows);
  });
});

// === יצוא נתונים ===

// ייצוא תורמים לאקסל (מחזיר CSV)
app.get('/api/admin/export/donors', authenticateToken, requireAdmin, (req, res) => {
  db.all('SELECT * FROM donors ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      console.error('שגיאה בייצוא תורמים:', err);
      return res.status(500).json({ error: 'שגיאה בייצוא נתונים' });
    }
    
    // יצירת CSV
    const csvHeader = 'ID,Name,Phone,Email,Address,City,Area,Donation_Amount,Last_Contact,Donor_Type,Status,Notes,Created_At\n';
    const csvData = rows.map(donor => {
      return [
        donor.id,
        `"${(donor.name || '').replace(/"/g, '""')}"`,
        `"${(donor.phone || '').replace(/"/g, '""')}"`,
        `"${(donor.email || '').replace(/"/g, '""')}"`,
        `"${(donor.address || '').replace(/"/g, '""')}"`,
        `"${(donor.city || '').replace(/"/g, '""')}"`,
        `"${(donor.area || '').replace(/"/g, '""')}"`,
        donor.donation_amount || '',
        donor.last_contact || '',
        `"${(donor.donor_type || '').replace(/"/g, '""')}"`,
        `"${(donor.status || '').replace(/"/g, '""')}"`,
        `"${(donor.notes || '').replace(/"/g, '""')}"`,
        donor.created_at
      ].join(',');
    }).join('\n');
    
    const csvContent = csvHeader + csvData;
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="donors_export.csv"');
    res.send('\uFEFF' + csvContent); // BOM for Excel Hebrew support
    
    logActivity(req.user.id, 'ייצוא_תורמים', 'donor', null, `יוצאו ${rows.length} תורמים`, req);
  });
});

// ייצוא דוחות
app.get('/api/admin/export/reports', authenticateToken, requireAdmin, (req, res) => {
  const { from_date, to_date } = req.query;
  
  let whereClause = '';
  let params = [];
  
  if (from_date) {
    whereClause += ' WHERE sh.created_at >= ?';
    params.push(from_date);
  }
  
  if (to_date) {
    whereClause += whereClause ? ' AND sh.created_at <= ?' : ' WHERE sh.created_at <= ?';
    params.push(to_date);
  }
  
  db.all(`
    SELECT 
      u.username,
      u.full_name,
      COUNT(sh.id) as total_searches,
      COUNT(DISTINCT sh.search_term) as unique_searches,
      AVG(sh.results_count) as avg_results,
      DATE(sh.created_at) as search_date
    FROM search_history sh
    JOIN users u ON sh.user_id = u.id
    ${whereClause}
    GROUP BY u.id, DATE(sh.created_at)
    ORDER BY search_date DESC, total_searches DESC
  `, params, (err, rows) => {
    if (err) {
      console.error('שגיאה בייצוא דוחות:', err);
      return res.status(500).json({ error: 'שגיאה בייצוא דוחות' });
    }
    
    // יצירת CSV
    const csvHeader = 'Username,Full_Name,Total_Searches,Unique_Searches,Avg_Results,Search_Date\n';
    const csvData = rows.map(row => {
      return [
        `"${(row.username || '').replace(/"/g, '""')}"`,
        `"${(row.full_name || '').replace(/"/g, '""')}"`,
        row.total_searches,
        row.unique_searches,
        Math.round(row.avg_results * 100) / 100,
        row.search_date
      ].join(',');
    }).join('\n');
    
    const csvContent = csvHeader + csvData;
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="search_reports_export.csv"');
    res.send('\uFEFF' + csvContent);
    
    logActivity(req.user.id, 'ייצוא_חיפושים', 'report', null, `ייצא דו"ח חיפושים`, req);
  });
});

// ייצוא לוגים
app.get('/api/admin/export/logs', authenticateToken, requireAdmin, (req, res) => {
  const { from_date, to_date, user_id, action } = req.query;
  
  let whereClause = '';
  let params = [];
  
  if (from_date) {
    whereClause += ' WHERE al.created_at >= ?';
    params.push(from_date);
  }
  
  if (to_date) {
    whereClause += whereClause ? ' AND al.created_at <= ?' : ' WHERE al.created_at <= ?';
    params.push(to_date);
  }
  
  if (user_id) {
    whereClause += whereClause ? ' AND al.user_id = ?' : ' WHERE al.user_id = ?';
    params.push(user_id);
  }
  
  if (action) {
    whereClause += whereClause ? ' AND al.action = ?' : ' WHERE al.action = ?';
    params.push(action);
  }
  
  db.all(`
    SELECT al.*, u.username, u.full_name
    FROM activity_logs al
    LEFT JOIN users u ON al.user_id = u.id
    ${whereClause}
    ORDER BY al.created_at DESC
  `, params, (err, rows) => {
    if (err) {
      console.error('שגיאה בייצוא לוגים:', err);
      return res.status(500).json({ error: 'שגיאה בייצוא לוגים' });
    }
    
    // יצירת CSV
    const csvHeader = 'ID,Username,Full_Name,Action,Target_Type,Target_ID,Details,IP_Address,User_Agent,Created_At\n';
    const csvData = rows.map(log => {
      return [
        log.id,
        `"${(log.username || '').replace(/"/g, '""')}"`,
        `"${(log.full_name || '').replace(/"/g, '""')}"`,
        `"${(log.action || '').replace(/"/g, '""')}"`,
        `"${(log.target_type || '').replace(/"/g, '""')}"`,
        log.target_id || '',
        `"${(log.details || '').replace(/"/g, '""')}"`,
        `"${(log.ip_address || '').replace(/"/g, '""')}"`,
        `"${(log.user_agent || '').replace(/"/g, '""')}"`,
        log.created_at
      ].join(',');
    }).join('\n');
    
    const csvContent = csvHeader + csvData;
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="system_logs_export.csv"');
    res.send('\uFEFF' + csvContent);
    
    logActivity(req.user.id, 'ייצוא_לוגים', 'system', null, `המשתמש ייצא לוגים`, req);
  });
});

// === תבנית CSV להורדה ===

app.get('/api/admin/template/donors-csv', authenticateToken, requireAdmin, (req, res) => {
  const template = `id,מספר הזמנה,שם הפרויקט,השם לתפילה,שם,משפחה,תאריך מסירה,תאריך התיקון,תאריך פטירה חודש,תאריך פטירה יום,הערות,סטטוס,כמות,טלפון,טלפון copy,מייל,כמה שולם/מחיר לשם,צורת תשלום,אמצעי שיווקי,מקור תנועה,שם הקמפין,סוג,מילות מפתח,תוכן,תאריך ושעה,נוצר,שונה לאחרונה,מזהה פרויקט,עיר,רחוב,בניין,דירה
261551,26155,תיקון הנפטרים,שרון בן דליה,נועה,בן אלי,,תמוז התשפ"ה,ניסן,ד',,שולם,1,0523232652,,noabeneli12@gmail.com,₪ 101,תשלום באמצעות,ווצאפ,קבוצת_צאפ_מגזין,,1,,,"27 במאי 2025 15:24",27/05/2025 15:31,27/05/2025 15:31,4275,,,,
261781,26178,תיקון הנפטרים,אליהו איתן בן נג'ימה,מירית,אדרי,,תמוז התשפ"ה,תשרי,ה',,שולם,1,0526269620,,miritmaor12345@gmail.com,₪ 101,תשלום בכרטיס אשראי,ווצאפ,קבוצת_צאפ_מגזין,,1,,,"28 במאי 2025 17:11",28/05/2025 17:13,28/05/2025 17:13,4275,,,,`;
  
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="donors_template.csv"');
  res.send('\uFEFF' + template);
});

// הוסף לקובץ advanced-server.js
app.get('/api/admin/donor/:id/all-donations', authenticateToken, requireAdmin, (req, res) => {
    const { id } = req.params;
    
    // קבלת כל התרומות של התורם לפי ID
    db.get('SELECT phone, COALESCE(name, first_name || " " || last_name) as full_name FROM donors WHERE id = ?', [id], (err, mainDonor) => {
        if (err || !mainDonor) {
            return res.status(404).json({ error: 'תורם לא נמצא' });
        }
        
        // קבלת כל התרומות של אותו תורם
        db.all(`
            SELECT * FROM donors 
            WHERE phone = ? 
            AND COALESCE(name, first_name || " " || last_name) = ?
            ORDER BY created_at DESC
        `, [mainDonor.phone, mainDonor.full_name], (err, donations) => {
            if (err) {
                console.error('שגיאה בטעינת תרומות:', err);
                return res.status(500).json({ error: 'שגיאה בטעינת תרומות' });
            }
            
            res.json(donations);
        });
    });
});

app.get('/api/donor/:id/notes', authenticateToken, (req, res) => {
    const { id } = req.params;
    
    db.all(`
        SELECT un.*, u.full_name as user_name, u.username
        FROM user_notes un
        JOIN users u ON un.user_id = u.id
        WHERE un.donor_id = ?
        ORDER BY un.created_at DESC
    `, [id], (err, rows) => {
        if (err) {
            console.error('שגיאה בטעינת הערות תורם:', err);
            return res.status(500).json({ error: 'שגיאה בטעינת הערות' });
        }
        res.json(rows);
    });
});

// =========================
// === ניהול סוגי תרומות ===
// =========================

// קבלת רשימת סוגי תרומות פעילים (לטלפנים)
app.get('/api/donation-types', authenticateToken, (req, res) => {
 const currentDate = new Date().toISOString().split('T')[0];
 
 db.all(`
   SELECT id, name, url, description, start_date, end_date
   FROM donation_types
   WHERE is_active = 1
   AND (no_expiry = 1 OR start_date IS NULL OR start_date <= ?)
   AND (no_expiry = 1 OR end_date IS NULL OR end_date >= ?)
   ORDER BY name ASC
 `, [currentDate, currentDate], (err, rows) => {
   if (err) {
     console.error('שגיאה בטעינת סוגי תרומות:', err);
     return res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
   }
   
   res.json(rows);
 });
});

// רישום גישה לסוג תרומה
app.post('/api/donation-types/:id/access', authenticateToken, (req, res) => {
 const { id } = req.params;
 const { action = 'VIEW' } = req.body;
 
 // רישום בלוג התרומות
 db.run(`
   INSERT INTO donation_access_logs (user_id, donation_type_id, action, ip_address, user_agent)
   VALUES (?, ?, ?, ?, ?)
 `, [req.user.id, id, action, req.ip, req.get('User-Agent')], (err) => {
   if (err) {
     console.error('שגיאה ברישום לוג תרומה:', err);
   }
 });
 
 // רישום בלוג כללי
 logActivity(req.user.id, 'DONATION_ACCESS', 'donation_type', id, `Accessed donation type: ${action}`, req);
 
 res.json({ message: 'נרשם בהצלחה' });
});

// קבלת כל סוגי התרומות (לאדמין)
app.get('/api/admin/donation-types', authenticateToken, requireAdmin, (req, res) => {
 db.all(`
   SELECT dt.*, u.full_name as created_by_name, u.username as created_by_username
   FROM donation_types dt
   LEFT JOIN users u ON dt.created_by = u.id
   ORDER BY dt.created_at DESC
 `, (err, rows) => {
   if (err) {
     console.error('שגיאה בטעינת סוגי תרומות:', err);
     return res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
   }
   
   res.json(rows);
 });
});

// יצירת סוג תרומה חדש
app.post('/api/admin/donation-types', authenticateToken, requireAdmin, (req, res) => {
 const { name, url, start_date, end_date, no_expiry, description } = req.body;
 
 if (!name || !url) {
   return res.status(400).json({ error: 'שם ו-URL נדרשים' });
 }
 
 // בדיקת תקינות URL
 try {
   new URL(url);
 } catch (error) {
   return res.status(400).json({ error: 'URL לא תקין' });
 }
 
 // בדיקת תאריכים
 if (!no_expiry && start_date && end_date && start_date > end_date) {
   return res.status(400).json({ error: 'תאריך התחלה לא יכול להיות אחרי תאריך סיום' });
 }
 
 db.run(`
   INSERT INTO donation_types (name, url, start_date, end_date, no_expiry, description, created_by)
   VALUES (?, ?, ?, ?, ?, ?, ?)
 `, [
   name.trim(),
   url.trim(),
   no_expiry ? null : start_date,
   no_expiry ? null : end_date,
   no_expiry ? 1 : 0,
   description ? description.trim() : null,
   req.user.id
 ], function(err) {
   if (err) {
     console.error('שגיאה ביצירת סוג תרומה:', err);
     if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
       return res.status(400).json({ error: 'שם התרומה כבר קיים' });
     }
     return res.status(500).json({ error: 'שגיאה ביצירת סוג תרומה' });
   }
   
   logActivity(req.user.id, 'יצירת דף התרמה', 'donation_type', this.lastID, `יצר דף התרמה בשם: ${name}`, req);
   res.json({ message: 'סוג תרומה נוצר בהצלחה', donationTypeId: this.lastID });
 });
});

// עדכון סוג תרומה
app.put('/api/admin/donation-types/:id', authenticateToken, requireAdmin, (req, res) => {
 const { id } = req.params;
 const { name, url, start_date, end_date, no_expiry, is_active, description } = req.body;
 
 if (!name || !url) {
   return res.status(400).json({ error: 'שם ו-URL נדרשים' });
 }
 
 // בדיקת תקינות URL
 try {
   new URL(url);
 } catch (error) {
   return res.status(400).json({ error: 'URL לא תקין' });
 }
 
 // בדיקת תאריכים
 if (!no_expiry && start_date && end_date && start_date > end_date) {
   return res.status(400).json({ error: 'תאריך התחלה לא יכול להיות אחרי תאריך סיום' });
 }
 
 db.run(`
   UPDATE donation_types 
   SET name = ?, url = ?, start_date = ?, end_date = ?, no_expiry = ?, 
       is_active = ?, description = ?, updated_at = CURRENT_TIMESTAMP
   WHERE id = ?
 `, [
   name.trim(),
   url.trim(),
   no_expiry ? null : start_date,
   no_expiry ? null : end_date,
   no_expiry ? 1 : 0,
   is_active ? 1 : 0,
   description ? description.trim() : null,
   id
 ], function(err) {
   if (err) {
     console.error('שגיאה בעדכון סוג תרומה:', err);
     return res.status(500).json({ error: 'שגיאה בעדכון סוג תרומה' });
   }
   
   if (this.changes === 0) {
     return res.status(404).json({ error: 'סוג תרומה לא נמצא' });
   }
   
   logActivity(req.user.id, 'UPDATE_DONATION_TYPE', 'donation_type', id, `Updated donation type: ${name}`, req);
   res.json({ message: 'סוג תרומה עודכן בהצלחה' });
 });
});

// מחיקת סוג תרומה
app.delete('/api/admin/donation-types/:id', authenticateToken, requireAdmin, (req, res) => {
 const { id } = req.params;
 
 // בדיקה אם יש לוגים של השימוש
 db.get('SELECT COUNT(*) as count FROM donation_access_logs WHERE donation_type_id = ?', [id], (err, row) => {
   if (err) {
     console.error('שגיאה בבדיקת לוגים:', err);
     return res.status(500).json({ error: 'שגיאה בשרת' });
   }
   
   if (row.count > 0) {
     // אם יש לוגים, רק השבת במקום מחיקה
     db.run('UPDATE donation_types SET is_active = 0 WHERE id = ?', [id], function(err) {
       if (err) {
         return res.status(500).json({ error: 'שגיאה בהשבתה' });
       }
       
       logActivity(req.user.id, 'DISABLE_DONATION_TYPE', 'donation_type', id, 'Disabled donation type (has usage logs)', req);
       res.json({ message: 'סוג התרומה הושבת (יש לוגי שימוש)' });
     });
   } else {
     // אחרת - מחיקה מלאה
     db.run('DELETE FROM donation_types WHERE id = ?', [id], function(err) {
       if (err) {
         console.error('שגיאה במחיקת סוג תרומה:', err);
         return res.status(500).json({ error: 'שגיאה במחיקת סוג תרומה' });
       }
       
       if (this.changes === 0) {
         return res.status(404).json({ error: 'סוג תרומה לא נמצא' });
       }
       
       logActivity(req.user.id, 'DELETE_DONATION_TYPE', 'donation_type', id, 'Deleted donation type', req);
       res.json({ message: 'סוג תרומה נמחק בהצלחה' });
     });
   }
 });
});

// סטטיסטיקות שימוש בתרומות
app.get('/api/admin/donation-types/stats', authenticateToken, requireAdmin, (req, res) => {
 const { from_date, to_date } = req.query;
 
 let whereClause = '';
 let params = [];
 
 if (from_date) {
   whereClause += ' WHERE dal.created_at >= ?';
   params.push(from_date + ' 00:00:00');
 }
 
 if (to_date) {
   whereClause += whereClause ? ' AND dal.created_at <= ?' : ' WHERE dal.created_at <= ?';
   params.push(to_date + ' 23:59:59');
 }
 
 db.all(`
   SELECT 
     dt.name as donation_name,
     dt.id as donation_id,
     COUNT(dal.id) as access_count,
     COUNT(DISTINCT dal.user_id) as unique_users,
     MAX(dal.created_at) as last_access,
     u.full_name as most_active_user
   FROM donation_types dt
   LEFT JOIN donation_access_logs dal ON dt.id = dal.donation_type_id
   LEFT JOIN users u ON dal.user_id = u.id
   ${whereClause}
   GROUP BY dt.id, dt.name
   ORDER BY access_count DESC
 `, params, (err, rows) => {
   if (err) {
     console.error('שגיאה בטעינת סטטיסטיקות:', err);
     return res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
   }
   
   res.json(rows);
 });
});

// היסטוריית גישה לתרומות
app.get('/api/admin/donation-access-logs', authenticateToken, requireAdmin, (req, res) => {
 const { limit = 100, donation_type_id, user_id } = req.query;
 
 let whereClause = '';
 let params = [];
 
 if (donation_type_id) {
   whereClause += ' WHERE dal.donation_type_id = ?';
   params.push(donation_type_id);
 }
 
 if (user_id) {
   whereClause += whereClause ? ' AND dal.user_id = ?' : ' WHERE dal.user_id = ?';
   params.push(user_id);
 }
 
 params.push(parseInt(limit));
 
 db.all(`
   SELECT 
     dal.*,
     dt.name as donation_name,
     u.full_name as user_name,
     u.username
   FROM donation_access_logs dal
   LEFT JOIN donation_types dt ON dal.donation_type_id = dt.id
   LEFT JOIN users u ON dal.user_id = u.id
   ${whereClause}
   ORDER BY dal.created_at DESC
   LIMIT ?
 `, params, (err, rows) => {
   if (err) {
     console.error('שגיאה בטעינת לוגי גישה:', err);
     return res.status(500).json({ error: 'שגיאה בטעינת נתונים' });
   }
   
   res.json(rows);
 });
});

console.log('✅ כל ה-API endpoints נוספו בהצלחה!');

// === מערכת סינכרון Airtable ===

// פונקציית השוואת רשומות - בדיקה אם השדות שונים
// פונקציית השוואת רשומות - בדיקה אם השדות שונים
function recordsAreDifferent(dbRecord, airtableFields) {
    const fieldsToCompare = {
        project_name: airtableFields['שם הפרויקט'] || '',
        prayer_name: airtableFields['השם לתפילה'] || '',
        first_name: airtableFields['שם'] || '',
        last_name: airtableFields['שם משפחה'] || '',
        phone: airtableFields['טלפון'] || '',
        email: airtableFields['מייל'] || '',
        city: airtableFields['עיר'] || '',
        street: airtableFields['רחוב'] || '',
        building: airtableFields['בניין'] || '',
        apartment: airtableFields['דירה'] || '',
        payment_amount: airtableFields['כמה שולם/מחיר לשם'] || '',
        payment_status: airtableFields['סטטוס'] || '',
        payment_method: airtableFields['צורת תשלום'] || '',
        comments: airtableFields['הערות'] || ''
    };
    
    // השווה כל שדה
    const entries = Object.entries(fieldsToCompare);
    for (let i = 0; i < entries.length; i++) {
        const key = entries[i][0];
        const newValue = entries[i][1];
        const oldValue = dbRecord[key] || '';
        
        if (oldValue.toString().trim() !== newValue.toString().trim()) {
            console.log(`🔄 שדה ${key} השתנה: "${oldValue}" → "${newValue}"`);
            return true;
        }
    }
    
    return false;
}

// פונקציית סינכרון מרכזית עם Airtable
async function syncWithAirtable() {
    if (!base) {
        console.error('❌ Airtable לא מאותחל - בדוק את המפתחות');
        return { success: false, error: 'Airtable לא מאותחל' };
    }
    
    console.log('🔄 מתחיל סינכרון עם Airtable...');
    
    try {
        const records = [];
        
        // קבלת כל הרשומות מ-Airtable
        console.log('📡 מוריד נתונים מ-Airtable...');
        await base(AIRTABLE_TABLE_NAME).select({
            sort: [{ field: "נוצר", direction: "desc" }]
        }).eachPage((pageRecords, fetchNextPage) => {
            records.push(...pageRecords);
            fetchNextPage();
        });
        
        console.log(`📊 התקבלו ${records.length} רשומות מ-Airtable`);
        
        let newRecords = 0;
        let updatedRecords = 0;
        let skippedRecords = 0;
        let errors = 0;
        
        for (const [index, record] of records.entries()) {
            try {
                const fields = record.fields;
                
                // בדיקה אם יש מספר הזמנה
                const orderNumber = fields['מספר הזמנה'];
                if (!orderNumber) {
                    console.log(`⚠️ רשומה ${index + 1}: אין מספר הזמנה - מדלג`);
                    skippedRecords++;
                    continue;
                }
                
                // בדיקת קיום ברשומה במסד הנתונים
                const existingRecord = await new Promise((resolve, reject) => {
                    db.get('SELECT * FROM donors WHERE order_number = ?', [orderNumber], (err, row) => {
                        if (err) reject(err);
                        else resolve(row);
                    });
                });
                
                // הכנת נתוני התורם מ-Airtable
                const donorData = {
                    order_number: orderNumber,
                    project_name: fields['שם הפרויקט'] || '',
                    prayer_name: fields['השם לתפילה'] || '',
                    first_name: fields['שם'] || '',
                    last_name: fields['שם משפחה'] || '',
                    name: `${fields['שם'] || ''} ${fields['שם משפחה'] || ''}`.trim(),
                    phone: fields['טלפון'] || '',
                    phone_copy: fields['טלפון copy'] || '',
                    email: fields['מייל'] || '',
                    city: fields['עיר'] || '',
                    street: fields['רחוב'] || '',
                    building: fields['בניין'] || '',
                    apartment: fields['דירה'] || '',
                    payment_amount: fields['כמה שולם/מחיר לשם'] || '',
                    payment_method: fields['צורת תשלום'] || '',
                    payment_status: fields['סטטוס'] || '',
                    delivery_date: fields['תאריך מסירה'] || '',
                    fix_date: fields['תאריך התיקון'] || '',
                    death_date_month: fields['תאריך פטירה חודש'] || '',
                    death_date_day: fields['תאריך פטירה יום'] || '',
                    comments: fields['הערות'] || '',
                    quantity: parseInt(fields['כמות']) || 1,
                    marketing_source: fields['אמצעי שיווקי'] || '',
                    traffic_source: fields['מקור תנועה'] || '',
                    campaign_name: fields['שם הקמפין'] || '',
                    type_field: fields['סוג'] || '',
                    keywords: fields['מילות מפתח'] || '',
                    content_field: fields['תוכן'] || '',
                    datetime_field: fields['תאריך ושעה'] || '',
                    created_field: fields['נוצר'] || '',
                    project_id: fields['מזהה פרויקט'] || '',
                    last_modified: fields['שונה לאחרונה'] || new Date().toISOString()
                };
                
                if (existingRecord) {
                    // רשומה קיימת - בדיקה אם צריך עדכון
                    if (recordsAreDifferent(existingRecord, fields)) {
                        // עדכון רשומה קיימת
                        await new Promise((resolve, reject) => {
                            db.run(`
                                UPDATE donors SET 
                                    project_name = ?, prayer_name = ?, first_name = ?, last_name = ?,
                                    name = ?, phone = ?, phone_copy = ?, email = ?, city = ?, street = ?, 
                                    building = ?, apartment = ?, payment_amount = ?, payment_method = ?, 
                                    payment_status = ?, delivery_date = ?, fix_date = ?, death_date_month = ?,
                                    death_date_day = ?, comments = ?, quantity = ?, marketing_source = ?,
                                    traffic_source = ?, campaign_name = ?, type_field = ?, keywords = ?,
                                    content_field = ?, datetime_field = ?, created_field = ?, project_id = ?,
                                    last_modified = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
                                WHERE order_number = ?
                            `, [
                                donorData.project_name, donorData.prayer_name, donorData.first_name,
                                donorData.last_name, donorData.name, donorData.phone, donorData.phone_copy,
                                donorData.email, donorData.city, donorData.street, donorData.building,
                                donorData.apartment, donorData.payment_amount, donorData.payment_method,
                                donorData.payment_status, donorData.delivery_date, donorData.fix_date,
                                donorData.death_date_month, donorData.death_date_day, donorData.comments,
                                donorData.quantity, donorData.marketing_source, donorData.traffic_source,
                                donorData.campaign_name, donorData.type_field, donorData.keywords,
                                donorData.content_field, donorData.datetime_field, donorData.created_field,
                                donorData.project_id, donorData.last_modified, 1, orderNumber
                            ], (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                        });
                        updatedRecords++;
                        console.log(`✅ עודכן: ${donorData.name} (${orderNumber})`);
                    } else {
                        console.log(`➡️ ללא שינוי: ${donorData.name} (${orderNumber})`);
                        skippedRecords++;
                    }
                    
                } else {
                    // רשומה חדשה - הוספה למסד הנתונים
                    await new Promise((resolve, reject) => {
                        db.run(`
                            INSERT INTO donors (
                                order_number, project_name, prayer_name, first_name, last_name,
                                name, phone, phone_copy, email, city, street, building, apartment,
                                payment_amount, payment_method, payment_status, delivery_date,
                                fix_date, death_date_month, death_date_day, comments, quantity,
                                marketing_source, traffic_source, campaign_name, type_field,
                                keywords, content_field, datetime_field, created_field,
                                project_id, created_by, last_modified
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `, [
                            donorData.order_number, donorData.project_name, donorData.prayer_name,
                            donorData.first_name, donorData.last_name, donorData.name, donorData.phone,
                            donorData.phone_copy, donorData.email, donorData.city, donorData.street,
                            donorData.building, donorData.apartment, donorData.payment_amount,
                            donorData.payment_method, donorData.payment_status, donorData.delivery_date,
                            donorData.fix_date, donorData.death_date_month, donorData.death_date_day,
                            donorData.comments, donorData.quantity, donorData.marketing_source,
                            donorData.traffic_source, donorData.campaign_name, donorData.type_field,
                            donorData.keywords, donorData.content_field, donorData.datetime_field,
                            donorData.created_field, donorData.project_id, 1, donorData.last_modified
                        ], (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });
                    newRecords++;
                    console.log(`🆕 נוסף חדש: ${donorData.name} (${orderNumber})`);
                }
                
            } catch (error) {
                console.error(`❌ שגיאה ברשומה ${index + 1}:`, error.message);
                errors++;
            }
        }
        
        // סיכום התוצאות
        const syncResult = {
            total: records.length,
            new: newRecords,
            updated: updatedRecords,
            skipped: skippedRecords,
            errors: errors
        };
        
        const logMessage = `Airtable Sync: ${newRecords} new, ${updatedRecords} updated, ${skippedRecords} unchanged, ${errors} errors (${records.length} total)`;
        console.log(`🎉 סינכרון הושלם: ${logMessage}`);
        
        // רישום בלוג המערכת
        db.run(
            `INSERT INTO activity_logs (user_id, action, target_type, details)
             VALUES (?, ?, ?, ?)`,
            [1, 'AIRTABLE_SYNC', 'system', logMessage]
        );
        
        return { success: true, ...syncResult };
        
    } catch (error) {
        console.error('❌ שגיאה כללית בסינכרון Airtable:', error);
        
        // רישום שגיאה
        db.run(
            `INSERT INTO activity_logs (user_id, action, target_type, details)
             VALUES (?, ?, ?, ?)`,
            [1, 'AIRTABLE_SYNC_ERROR', 'system', `Error: ${error.message}`]
        );
        
        return { success: false, error: error.message };
    }
}

// API endpoint לסינכרון ידני (כפתור באדמין)
app.post('/api/admin/sync-airtable', authenticateToken, requireAdmin, async (req, res) => {
    console.log(`👤 ${req.user.username} מפעיל סינכרון ידני עם Airtable`);
    
    const result = await syncWithAirtable();
    
    if (result.success) {
        logActivity(req.user.id, 'MANUAL_AIRTABLE_SYNC', 'system', null, 
            `Manual sync: ${result.new} new, ${result.updated} updated, ${result.skipped} unchanged`, req);
        
        res.json({
            message: 'סינכרון הושלם בהצלחה! 🎉',
            details: {
                totalProcessed: result.total,
                newRecords: result.new,
                updatedRecords: result.updated,
                unchangedRecords: result.skipped,
                errors: result.errors
            }
        });
    } else {
        res.status(500).json({
            error: 'שגיאה בסינכרון עם Airtable',
            details: result.error
        });
    }
});

// סינכרון אוטומטי כל 30 דקות
cron.schedule('*/30 * * * *', () => {
    console.log('⏰ סינכרון אוטומטי מתוזמן עם Airtable...');
    syncWithAirtable();
});

// סינכרון ראשוני בעת הפעלת השרת (אחרי 10 שניות)
setTimeout(() => {
    console.log('🚀 מבצע סינכרון ראשוני עם Airtable...');
    syncWithAirtable();
}, 10000);

console.log('✅ מערכת סינכרון Airtable הותקנה - עדכון אוטומטי כל 30 דקות');

// === נתיבים סטטיים ===

app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
  // אם זה בקשת API שלא נמצאה, החזר 404 JSON
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found: ' + req.path });
  }
  // אחרת החזר את index.html
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// הפעלת השרת
app.listen(PORT, '0.0.0.0', async () => {
 console.log(`🚀 השרת המתקדם פועל על http://localhost:${PORT}`);
 try {
   await initDatabase();
   console.log('✅ כל המערכות מוכנות!');
 } catch (error) {
   console.error('❌ שגיאה באתחול:', error);
 }
});

// טיפול בסגירה נקייה
process.on('SIGINT', () => {
 console.log('\n🔄 סוגר את השרת...');
 db.close((err) => {
   if (err) {
     console.error('שגיאה בסגירת מסד נתונים:', err);
   } else {
     console.log('✅ מסד נתונים נסגר בהצלחה');
   }
   process.exit(0);
 });
});

