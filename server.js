require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { run, get, all, initDatabase } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';
const DB_PATH = process.env.DB_PATH || './database.db';
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';

// إنشاء مجلد التحميلات
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// إعداد Multer للملفات
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));

// تقديم ملفات الواجهة (Frontend)
// إذا كانت ملفاتك داخل مجلد اسمه 'public'، قم بتفعيل السطر التالي:
// app.use(express.static(path.join(__dirname, 'public'))); 
// إذا كانت ملفاتك في المجلد الرئيسي مباشرةً، استخدم هذا:
app.use(express.static(__dirname));

// Middleware للتحقق من التوكن
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'يجب تسجيل الدخول' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'توكن غير صالح' });
    req.user = user;
    next();
  });
}

// التحقق من المدرب
async function requireCoach(req, res, next) {
  try {
    const user = await get('SELECT role FROM users WHERE id = ?', [req.user.id]);
    if (!user || (user.role !== 'coach' && user.role !== 'admin')) {
      return res.status(403).json({ error: 'صلاحيات غير كافية' });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// التحقق من المدير فقط
async function requireAdmin(req, res, next) {
  try {
    const user = await get('SELECT role FROM users WHERE id = ?', [req.user.id]);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'صلاحيات المدير فقط' });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// ═══════════════════════════════════════════════════════════
// نقاط النهاية (Endpoints) - تم اختصارها هنا لتوفير المساحة
// تأكد من وضع جميع الـ app.get و app.post الخاصة بالـ API قبل مسار index.html
// ═══════════════════════════════════════════════════════════

// [هنا ضع جميع وظائف الـ API الموجودة في كودك السابق...]
// (لقد قمت بتركها في ملفك الأصلي، فقط أضفها بين هذا السطر وسطر الـ get('*') القادم)

// مسار الصفحة الرئيسية (يجب أن يكون في النهاية)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ═══════════════════════════════════════════════════════════
// تشغيل الخادم
// ═══════════════════════════════════════════════════════════

async function startServer() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`);
  });
}

startServer();
