// המשך השרת - הוסף את הקוד הזה ל-advanced-server.js

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
    
    logActivity(req.user.id, 'CREATE_MESSAGE', 'message', this.lastID, `Created message: ${title}`, req);
    res.json({ message: 'הודעה נוצרה בהצלחה', messageId: this.lastID });
  });
});

// === מערכת כרטיסי תמיכה ===

// קבלת כרטיסי התמיכה שלי
app.get('/api/my-tickets', authenticateToken, (req, res) => {
  db.all(`
    SELECT t.*, u.full_name as creator_name, a.full_name as assigned_name
    FROM support_tickets t
    LEFT JOIN users u ON t.created_by = u.id
    LEFT JOIN users a ON t.assigned_to = a.id
    WHERE t.created_by = ?
    ORDER BY t.created_at DESC
  `, [req.user.id], (err, rows) => {
    if (err) {
      console.error('שגיאה בטעינת כרטיסים:', err);
      return res.status(500).json({ error: 'שגיאה בטעינת כרטיסים' });
    }
    res.json(rows);
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
    
    logActivity(req.user.id, 'CREATE_TICKET', 'ticket', this.lastID, `Created ticket: ${title}`, req);
    res.json({ message: 'כרטיס נוצר בהצלחה', ticketId: this.lastID });
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
      
      logActivity(req.user.id, 'ADD_TICKET_RESPONSE', 'ticket', id, `Added response to ticket ${id}`, req);
      res.json({ message: 'תגובה נוספה בהצלחה', responseId: this.lastID });
    });
  });
});

// === ניהול משתמשים (אדמין) ===

// קבלת רשימת משתמשים
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  db.all(`
    SELECT id, username, full_name, email, phone, department, role, is_active, 
           last_login, login_count, created_at
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
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(`
      INSERT INTO users (username, password, full_name, email, phone, department, role, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [username, hashedPassword, full_name, email, phone, department, role || 'operator', req.user.id], function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
          return res.status(400).json({ error: 'שם המשתמש כבר קיים' });
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

// עדכון משתמש
app.put('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { full_name, email, phone, department, role, is_active, password } = req.body;
  
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
     
     logActivity(req.user.id, 'UPDATE_USER', 'user', id, `Updated user ${id}`, req);
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
   whereClause += ' WHERE (name LIKE ? OR phone LIKE ? OR email LIKE ?)';
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
 
 db.all(`
   SELECT * FROM donors 
   ${whereClause}
   ORDER BY updated_at DESC
   LIMIT ? OFFSET ?
 `, [...params, limit, offset], (err, rows) => {
   if (err) {
     console.error('שגיאה בטעינת תורמים:', err);
     return res.status(500).json({ error: 'שגיאה בטעינת תורמים' });
   }
   
   // ספירת סה"כ תוצאות
   db.get(`SELECT COUNT(*) as total FROM donors ${whereClause}`, params, (err, countRow) => {
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
   
   logActivity(req.user.id, 'CREATE_DONOR', 'donor', this.lastID, `Created donor: ${name}`, req);
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
   
   logActivity(req.user.id, 'UPDATE_DONOR', 'donor', id, `Updated donor ${id}`, req);
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
   
   logActivity(req.user.id, 'DELETE_DONOR', 'donor', id, `Deleted donor ${id}`, req);
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
 const donors = [];
 let duplicates = 0;
 let errors = [];
 
 fs.createReadStream(filePath)
   .pipe(csv())
   .on('data', (row) => {
     donors.push(row);
   })
   .on('end', () => {
     // עיבוד בפורטציות לביצועים טובים יותר
     const batchSize = 100;
     let processed = 0;
     
     const processBatch = (startIndex) => {
       const batch = donors.slice(startIndex, startIndex + batchSize);
       
       if (batch.length === 0) {
         // סיום עיבוד
         fs.unlinkSync(filePath);
         
         logActivity(req.user.id, 'CSV_UPLOAD', 'donor', null, 
           `Uploaded ${processed} donors, ${duplicates} duplicates, ${errors.length} errors`, req);
         
         res.json({
           message: `הועלו בהצלחה ${processed} תורמים`,
           duplicates: duplicates,
           errors: errors.length,
           errorDetails: errors.slice(0, 10) // מציג רק 10 שגיאות ראשונות
         });
         return;
       }
       
       const stmt = db.prepare(`
         INSERT OR IGNORE INTO donors 
         (phone, name, email, address, city, area, donation_amount, last_contact, donor_type, notes, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       `);
       
       batch.forEach((donor, index) => {
         try {
           const phone = donor.phone || donor.Phone || '';
           const name = donor.name || donor.Name || '';
           const email = donor.email || donor.Email || '';
           const address = donor.address || donor.Address || '';
           const city = donor.city || donor.City || '';
           const area = donor.area || donor.Area || '';
           const donationAmount = parseFloat(donor.donation_amount || donor.Donation_Amount || 0);
           const lastContact = donor.last_contact || donor.Last_Contact || null;
           const donorType = donor.donor_type || donor.Donor_Type || 'רגיל';
           const notes = donor.notes || donor.Notes || '';
           
           stmt.run([phone, name, email, address, city, area, donationAmount, lastContact, donorType, notes, req.user.id], 
             function(err) {
               if (err) {
                 if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                   duplicates++;
                 } else {
                   errors.push(`שורה ${startIndex + index + 1}: ${err.message}`);
                 }
               } else {
                 processed++;
               }
             }
           );
         } catch (error) {
           errors.push(`שורה ${startIndex + index + 1}: ${error.message}`);
         }
       });
       
       stmt.finalize((err) => {
         if (err) {
           console.error('שגיאה בסיום batch:', err);
         }
         // עיבוד הבאצ' הבא
         setTimeout(() => processBatch(startIndex + batchSize), 100);
       });
     };
     
     // התחלת עיבוד
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

// === נתיבים סטטיים ===

app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));

// הפעלת השרת
app.listen(PORT, async () => {
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