const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

// ==================== ИНИЦИАЛИЗАЦИЯ ====================
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Статические файлы (будем отдавать HTML из памяти)
app.use(express.static(path.join(__dirname, 'public')));

// ==================== БАЗА ДАННЫХ ====================
const dbPath = path.join(__dirname, 'dimagram.db');
const db = new sqlite3.Database(dbPath);

// Создание таблиц
db.serialize(() => {
  // Пользователи
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT,
    avatar TEXT,
    bio TEXT,
    status TEXT DEFAULT 'online',
    theme TEXT DEFAULT 'dark',
    wallpaper TEXT,
    notification_sound BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Контакты
  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    contact_id INTEGER NOT NULL,
    custom_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, contact_id)
  )`);
  
  // Сообщения
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE NOT NULL,
    chat_id TEXT NOT NULL,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER,
    group_id INTEGER,
    message_type TEXT DEFAULT 'text',
    content TEXT,
    file_url TEXT,
    file_name TEXT,
    file_size INTEGER,
    status TEXT DEFAULT 'sent',
    reply_to_id TEXT,
    is_edited BOOLEAN DEFAULT 0,
    is_deleted BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Группы
  db.run(`CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    avatar TEXT,
    description TEXT,
    created_by INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Участники групп
  db.run(`CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(group_id, user_id)
  )`);
  
  // Прочитанные сообщения
  db.run(`CREATE TABLE IF NOT EXISTS read_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(message_id, user_id)
  )`);
  
  console.log('✅ База данных инициализирована');
});

// ==================== НАСТРОЙКА ЗАГРУЗКИ ФАЙЛОВ ====================
const uploadDir = path.join(__dirname, 'uploads');
const avatarsDir = path.join(uploadDir, 'avatars');
const filesDir = path.join(uploadDir, 'files');

[uploadDir, avatarsDir, filesDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const type = req.query.type || 'files';
    cb(null, type === 'avatar' ? avatarsDir : filesDir);
  },
  filename: (req, file, cb) => {
    cb(null, uuidv4() + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

// ==================== ХРАНЕНИЕ СОКЕТОВ ====================
const userSockets = new Map(); // userId -> socketId[]

// ==================== JWT MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
  
  jwt.verify(token, 'dimagram_secret_key_2024', (err, user) => {
    if (err) return res.status(403).json({ error: 'Недействительный токен' });
    req.user = user;
    next();
  });
};

// ==================== API МАРШРУТЫ ====================

// Регистрация
app.post('/api/register', async (req, res) => {
  const { username, phone, password, displayName } = req.body;
  
  if (!username || !phone || !password) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }
  
  // Проверка существования
  db.get('SELECT id FROM users WHERE username = ? OR phone = ?', [username, phone], async (err, existing) => {
    if (existing) {
      return res.status(400).json({ error: 'Пользователь уже существует' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      'INSERT INTO users (username, phone, password, display_name) VALUES (?, ?, ?, ?)',
      [username, phone, hashedPassword, displayName || username],
      function(err) {
        if (err) return res.status(500).json({ error: 'Ошибка создания' });
        
        db.get('SELECT id, username, phone, display_name, avatar, status FROM users WHERE id = ?', [this.lastID], (err, user) => {
          const token = jwt.sign({ id: user.id, username: user.username }, 'dimagram_secret_key_2024', { expiresIn: '7d' });
          res.json({ token, user });
        });
      }
    );
  });
});

// Вход
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ? OR phone = ?', [login, login], async (err, user) => {
    if (!user) return res.status(401).json({ error: 'Неверные учетные данные' });
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Неверные учетные данные' });
    
    db.run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
    
    const token = jwt.sign({ id: user.id, username: user.username }, 'dimagram_secret_key_2024', { expiresIn: '7d' });
    
    const userData = {
      id: user.id,
      username: user.username,
      phone: user.phone,
      display_name: user.display_name,
      avatar: user.avatar,
      bio: user.bio,
      status: user.status,
      theme: user.theme
    };
    
    res.json({ token, user: userData });
  });
});

// Получение текущего пользователя
app.get('/api/me', authenticateToken, (req, res) => {
  db.get('SELECT id, username, phone, display_name, avatar, bio, status, theme, wallpaper FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (user) res.json(user);
    else res.status(404).json({ error: 'Пользователь не найден' });
  });
});

// Поиск пользователей
app.get('/api/search', authenticateToken, (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  
  db.all(
    'SELECT id, username, display_name, avatar, status FROM users WHERE username LIKE ? OR display_name LIKE ? LIMIT 20',
    [`%${q}%`, `%${q}%`],
    (err, users) => {
      res.json(users.filter(u => u.id !== req.user.id));
    }
  );
});

// Контакты пользователя
app.get('/api/contacts', authenticateToken, (req, res) => {
  db.all(
    `SELECT c.*, u.username, u.display_name, u.avatar, u.status, u.last_seen 
     FROM contacts c 
     JOIN users u ON c.contact_id = u.id 
     WHERE c.user_id = ?`,
    [req.user.id],
    (err, contacts) => {
      res.json(contacts);
    }
  );
});

// Добавление контакта
app.post('/api/contacts', authenticateToken, (req, res) => {
  const { contactId } = req.body;
  
  db.run('INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)', [req.user.id, contactId], function(err) {
    if (err) return res.status(500).json({ error: 'Ошибка добавления' });
    
    db.get('SELECT id, username, display_name, avatar, status FROM users WHERE id = ?', [contactId], (err, contact) => {
      res.json({ success: true, contact });
    });
  });
});

// Удаление контакта
app.delete('/api/contacts/:contactId', authenticateToken, (req, res) => {
  db.run('DELETE FROM contacts WHERE user_id = ? AND contact_id = ?', [req.user.id, req.params.contactId], () => {
    res.json({ success: true });
  });
});

// Загрузка файла
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Нет файла' });
  
  const fileUrl = `/uploads/${req.query.type === 'avatar' ? 'avatars' : 'files'}/${req.file.filename}`;
  res.json({ url: fileUrl, name: req.file.originalname, size: req.file.size });
});

// Обновление профиля
app.put('/api/profile', authenticateToken, (req, res) => {
  const { display_name, bio, avatar, status, theme } = req.body;
  
  const updates = [];
  const values = [];
  
  if (display_name !== undefined) { updates.push('display_name = ?'); values.push(display_name); }
  if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
  if (avatar !== undefined) { updates.push('avatar = ?'); values.push(avatar); }
  if (status !== undefined) { updates.push('status = ?'); values.push(status); }
  if (theme !== undefined) { updates.push('theme = ?'); values.push(theme); }
  
  if (updates.length === 0) return res.json({ success: true });
  
  values.push(req.user.id);
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values, () => {
    res.json({ success: true });
  });
});

// История сообщений
app.get('/api/messages/:chatId', authenticateToken, (req, res) => {
  const { chatId } = req.params;
  const { limit = 50 } = req.query;
  
  db.all(
    `SELECT m.*, u.username, u.display_name, u.avatar 
     FROM messages m 
     LEFT JOIN users u ON m.sender_id = u.id 
     WHERE m.chat_id = ? AND m.is_deleted = 0 
     ORDER BY m.created_at DESC LIMIT ?`,
    [chatId, limit],
    (err, messages) => {
      res.json({ messages: (messages || []).reverse() });
    }
  );
});

// ==================== SOCKET.IO ====================
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));
  
  try {
    const decoded = jwt.verify(token, 'dimagram_secret_key_2024');
    socket.userId = decoded.id;
    socket.username = decoded.username;
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log(`🔌 Пользователь подключился: ${socket.userId}`);
  
  // Сохраняем сокет
  if (!userSockets.has(socket.userId)) userSockets.set(socket.userId, []);
  userSockets.get(socket.userId).push(socket.id);
  
  // Обновляем статус
  db.run('UPDATE users SET status = "online", last_seen = CURRENT_TIMESTAMP WHERE id = ?', [socket.userId]);
  socket.broadcast.emit('user_status', { userId: socket.userId, status: 'online' });
  
  // Отправка сообщения
  socket.on('send_message', (data) => {
    const { chatId, recipientId, groupId, messageType, content, fileUrl, fileName, fileSize, replyToId } = data;
    const messageId = uuidv4();
    const timestamp = new Date().toISOString();
    
    db.run(
      `INSERT INTO messages (message_id, chat_id, sender_id, recipient_id, group_id, message_type, content, file_url, file_name, file_size, reply_to_id, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sent', ?)`,
      [messageId, chatId, socket.userId, recipientId, groupId, messageType, content, fileUrl, fileName, fileSize, replyToId, timestamp],
      () => {
        // Получаем информацию об отправителе
        db.get('SELECT username, display_name, avatar FROM users WHERE id = ?', [socket.userId], (err, sender) => {
          const messageData = {
            messageId, chatId, senderId: socket.userId,
            senderName: sender?.display_name || sender?.username,
            senderAvatar: sender?.avatar,
            recipientId, groupId, messageType, content, fileUrl, fileName, fileSize,
            replyToId, status: 'sent', created_at: timestamp
          };
          
          // Отправляем получателю
          if (recipientId) {
            const recipientSockets = userSockets.get(recipientId) || [];
            recipientSockets.forEach(sid => io.to(sid).emit('new_message', messageData));
          }
          
          // Отправляем в группу
          if (groupId) {
            io.to(`group_${groupId}`).emit('new_message', messageData);
          }
          
          // Отправляем отправителю
          const senderSockets = userSockets.get(socket.userId) || [];
          senderSockets.forEach(sid => io.to(sid).emit('message_sent', messageData));
        });
      }
    );
  });
  
  // Индикатор печати
  socket.on('typing', (data) => {
    const { recipientId, groupId, isTyping } = data;
    
    if (recipientId) {
      const targetSockets = userSockets.get(recipientId) || [];
      targetSockets.forEach(sid => {
        io.to(sid).emit('user_typing', { userId: socket.userId, isTyping });
      });
    }
    
    if (groupId) {
      socket.to(`group_${groupId}`).emit('user_typing', { userId: socket.userId, isTyping });
    }
  });
  
  // Прочитано сообщение
  socket.on('message_read', (data) => {
    const { messageId } = data;
    
    db.run('INSERT OR IGNORE INTO read_receipts (message_id, user_id) VALUES (?, ?)', [messageId, socket.userId]);
    db.run('UPDATE messages SET status = "read" WHERE message_id = ?', [messageId]);
    
    db.get('SELECT sender_id FROM messages WHERE message_id = ?', [messageId], (err, msg) => {
      if (msg && msg.sender_id !== socket.userId) {
        const senderSockets = userSockets.get(msg.sender_id) || [];
        senderSockets.forEach(sid => {
          io.to(sid).emit('message_read_receipt', { messageId, userId: socket.userId });
        });
      }
    });
  });
  
  // WebRTC сигнализация для звонков
  socket.on('call_user', (data) => {
    const { targetUserId, callType, signalData } = data;
    const targetSockets = userSockets.get(targetUserId) || [];
    targetSockets.forEach(sid => {
      io.to(sid).emit('incoming_call', {
        fromUserId: socket.userId,
        fromUsername: socket.username,
        callType,
        signalData
      });
    });
  });
  
  socket.on('answer_call', (data) => {
    const { targetUserId, signalData } = data;
    const targetSockets = userSockets.get(targetUserId) || [];
    targetSockets.forEach(sid => {
      io.to(sid).emit('call_answered', { signalData });
    });
  });
  
  socket.on('ice_candidate', (data) => {
    const { targetUserId, candidate } = data;
    const targetSockets = userSockets.get(targetUserId) || [];
    targetSockets.forEach(sid => {
      io.to(sid).emit('ice_candidate', { candidate });
    });
  });
  
  socket.on('end_call', (data) => {
    const { targetUserId } = data;
    const targetSockets = userSockets.get(targetUserId) || [];
    targetSockets.forEach(sid => {
      io.to(sid).emit('call_ended');
    });
  });
  
  // Отключение
  socket.on('disconnect', () => {
    console.log(`🔌 Пользователь отключился: ${socket.userId}`);
    
    const sockets = userSockets.get(socket.userId) || [];
    const index = sockets.indexOf(socket.id);
    if (index > -1) sockets.splice(index, 1);
    
    if (sockets.length === 0) {
      userSockets.delete(socket.userId);
      db.run('UPDATE users SET status = "offline", last_seen = CURRENT_TIMESTAMP WHERE id = ?', [socket.userId]);
      socket.broadcast.emit('user_status', { userId: socket.userId, status: 'offline' });
    }
  });
});

// ==================== ФРОНТЕНД (HTML + CSS + JS) ====================
// Главная страница
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Димаграм - Современный мессенджер</title>
    <link rel="manifest" href="/manifest.json">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #0f0f0f;
            --bg-secondary: #1e1e1e;
            --bg-tertiary: #2d2d2d;
            --text-primary: #ffffff;
            --text-secondary: #a0a0a0;
            --accent: #5865f2;
            --accent-hover: #4752c4;
            --danger: #ed4245;
            --success: #23a55a;
            --border: #3b3b3b;
            --message-bg-me: #2b2d31;
            --message-bg-other: #1e1f22;
        }

        [data-theme="light"] {
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --bg-tertiary: #e8e8e8;
            --text-primary: #000000;
            --text-secondary: #666666;
            --border: #e0e0e0;
            --message-bg-me: #e3f2fd;
            --message-bg-other: #f5f5f5;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            overflow: hidden;
        }

        .app-container {
            display: flex;
            height: 100vh;
            width: 100vw;
            overflow: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: 320px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
        }

        .sidebar-header {
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 20px;
            font-weight: bold;
        }

        .logo i {
            color: var(--accent);
            font-size: 28px;
        }

        .icon-btn {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 20px;
            cursor: pointer;
            padding: 8px;
            border-radius: 8px;
            transition: all 0.2s;
        }

        .icon-btn:hover {
            background: var(--bg-tertiary);
            color: var(--accent);
        }

        .search-bar {
            margin: 15px;
            padding: 10px 15px;
            background: var(--bg-tertiary);
            border-radius: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .search-bar input {
            background: none;
            border: none;
            color: var(--text-primary);
            font-size: 14px;
            width: 100%;
            outline: none;
        }

        .chats-list {
            flex: 1;
            overflow-y: auto;
            padding: 10px;
        }

        .chat-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.2s;
            margin-bottom: 5px;
        }

        .chat-item:hover {
            background: var(--bg-tertiary);
            transform: translateX(5px);
        }

        .chat-item.active {
            background: var(--accent);
        }

        .chat-avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            object-fit: cover;
        }

        .chat-info {
            flex: 1;
        }

        .chat-name {
            font-weight: 600;
            margin-bottom: 4px;
        }

        .chat-last-message {
            font-size: 12px;
            color: var(--text-secondary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .user-card {
            padding: 15px 20px;
            border-top: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .user-card .avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
        }

        .user-card .user-info {
            flex: 1;
        }

        .user-card .username {
            font-weight: 600;
            display: block;
        }

        .user-card .status {
            font-size: 12px;
            color: var(--success);
        }

        .logout-btn {
            background: none;
            border: none;
            color: var(--danger);
            font-size: 18px;
            cursor: pointer;
            padding: 8px;
            border-radius: 8px;
        }

        /* Chat Area */
        .chat-area {
            flex: 1;
            display: flex;
            flex-direction: column;
        }

        .chat-header {
            padding: 15px 20px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .chat-header-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .chat-header-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
        }

        .chat-header-name {
            font-weight: 600;
            font-size: 18px;
        }

        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
        }

        .messages-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .message {
            display: flex;
            gap: 10px;
            animation: fadeInUp 0.3s ease;
        }

        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .message-avatar {
            width: 36px;
            height: 36px;
            border-radius: 50%;
        }

        .message-content {
            flex: 1;
            max-width: 60%;
        }

        .message-header {
            display: flex;
            gap: 10px;
            margin-bottom: 5px;
            font-size: 12px;
        }

        .message-sender {
            font-weight: 600;
        }

        .message-time {
            color: var(--text-secondary);
        }

        .message-bubble {
            background: var(--message-bg-other);
            padding: 10px 14px;
            border-radius: 18px;
            word-wrap: break-word;
        }

        .message.me {
            flex-direction: row-reverse;
        }

        .message.me .message-content {
            align-items: flex-end;
        }

        .message.me .message-bubble {
            background: var(--accent);
            color: white;
        }

        .message-status {
            font-size: 10px;
            margin-top: 5px;
            text-align: right;
        }

        .message-file {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: rgba(0,0,0,0.1);
            border-radius: 12px;
            cursor: pointer;
        }

        /* Input Area */
        .input-area {
            padding: 15px 20px;
            background: var(--bg-secondary);
            border-top: 1px solid var(--border);
        }

        .typing-indicator {
            padding: 5px 10px;
            font-size: 12px;
            color: var(--text-secondary);
            font-style: italic;
        }

        .message-input-wrapper {
            display: flex;
            align-items: center;
            gap: 10px;
            background: var(--bg-tertiary);
            border-radius: 25px;
            padding: 8px 15px;
        }

        .input-btn {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 20px;
            cursor: pointer;
            padding: 5px;
            transition: all 0.2s;
        }

        .input-btn:hover {
            color: var(--accent);
            transform: scale(1.1);
        }

        .message-input-container {
            flex: 1;
        }

        #messageInput {
            width: 100%;
            background: none;
            border: none;
            color: var(--text-primary);
            font-size: 15px;
            resize: none;
            outline: none;
            font-family: inherit;
            max-height: 100px;
        }

        .send-btn {
            background: var(--accent);
            border: none;
            color: white;
            width: 36px;
            height: 36px;
            border-radius: 50%;
            cursor: pointer;
            transition: all 0.2s;
        }

        .send-btn:hover {
            background: var(--accent-hover);
            transform: scale(1.05);
        }

        /* Right Panel */
        .right-panel {
            width: 320px;
            background: var(--bg-secondary);
            border-left: 1px solid var(--border);
            overflow-y: auto;
        }

        .panel-section {
            padding: 20px;
            border-bottom: 1px solid var(--border);
        }

        .panel-section h3 {
            margin-bottom: 15px;
            font-size: 16px;
        }

        .profile-field {
            margin-bottom: 15px;
        }

        .profile-field label {
            display: block;
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 5px;
        }

        .profile-field input, .profile-field select {
            width: 100%;
            padding: 10px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
        }

        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(8px);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }

        .modal-content {
            background: var(--bg-secondary);
            border-radius: 20px;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }

        .modal-header {
            padding: 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-body {
            padding: 20px;
        }

        .modal-body input {
            width: 100%;
            padding: 12px;
            margin-bottom: 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
        }

        .btn-primary {
            width: 100%;
            padding: 12px;
            background: var(--accent);
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            cursor: pointer;
        }

        /* Call Modal */
        .call-modal .modal-content {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .call-container {
            position: relative;
            min-height: 500px;
        }

        #localVideo {
            position: absolute;
            bottom: 20px;
            right: 20px;
            width: 160px;
            height: 120px;
            border-radius: 12px;
            border: 2px solid white;
            z-index: 2;
        }

        #remoteVideo {
            width: 100%;
            height: auto;
            border-radius: 12px;
        }

        .call-controls {
            position: absolute;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            display: flex;
            gap: 15px;
            z-index: 3;
        }

        .call-btn {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: rgba(0,0,0,0.5);
            border: none;
            color: white;
            cursor: pointer;
        }

        .end-call {
            background: var(--danger);
        }

        /* Toast */
        #toastContainer {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 2000;
        }

        .toast {
            background: var(--bg-secondary);
            color: var(--text-primary);
            padding: 12px 20px;
            border-radius: 8px;
            margin-top: 10px;
            animation: slideInRight 0.3s ease;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }

        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-tertiary);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--accent);
            border-radius: 4px;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .sidebar {
                position: fixed;
                left: -320px;
                z-index: 100;
            }
            .sidebar.open {
                left: 0;
            }
            .right-panel {
                position: fixed;
                right: -320px;
                z-index: 100;
            }
            .right-panel.open {
                right: 0;
            }
            .message-content {
                max-width: 85%;
            }
        }

        .contact-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px;
            border-radius: 8px;
            cursor: pointer;
        }

        .contact-item:hover {
            background: var(--bg-tertiary);
        }

        .search-result {
            padding: 10px;
            border-radius: 8px;
            cursor: pointer;
        }

        .search-result:hover {
            background: var(--bg-tertiary);
        }
    </style>
</head>
<body>
    <div id="app" class="app-container">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="logo"><i class="fab fa-telegram"></i><span>Димаграм</span></div>
                <div><button id="newChatBtn" class="icon-btn"><i class="fas fa-pen"></i></button>
                <button id="settingsBtn" class="icon-btn"><i class="fas fa-cog"></i></button></div>
            </div>
            <div class="search-bar"><i class="fas fa-search"></i><input type="text" id="searchInput" placeholder="Поиск..."></div>
            <div class="chats-list" id="chatsList"></div>
            <div class="user-card" id="userCard">
                <img class="avatar" id="currentUserAvatar" src="https://via.placeholder.com/40" alt="">
                <div class="user-info">
                    <span class="username" id="currentUsername"></span>
                    <span class="status" id="currentUserStatus">online</span>
                </div>
                <button id="logoutBtn" class="logout-btn"><i class="fas fa-sign-out-alt"></i></button>
            </div>
        </aside>
        
        <main class="chat-area" id="chatArea">
            <div class="chat-header" id="chatHeader">
                <div class="chat-header-info">
                    <img class="chat-header-avatar" id="chatAvatar" src="" alt="">
                    <div><div class="chat-header-name" id="chatName"></div></div>
                </div>
                <div><button id="callBtn" class="icon-btn"><i class="fas fa-phone"></i></button>
                <button id="videoCallBtn" class="icon-btn"><i class="fas fa-video"></i></button>
                <button id="infoBtn" class="icon-btn"><i class="fas fa-info-circle"></i></button></div>
            </div>
            <div class="messages-container" id="messagesContainer">
                <div class="messages-list" id="messagesList"></div>
            </div>
            <div class="input-area">
                <div class="typing-indicator" id="typingIndicator" style="display: none;"><span>Печатает...</span></div>
                <div class="message-input-wrapper">
                    <button id="emojiBtn" class="input-btn"><i class="far fa-smile-wink"></i></button>
                    <button id="attachBtn" class="input-btn"><i class="fas fa-paperclip"></i></button>
                    <div class="message-input-container"><textarea id="messageInput" placeholder="Сообщение..." rows="1"></textarea></div>
                    <button id="sendBtn" class="send-btn"><i class="fas fa-paper-plane"></i></button>
                </div>
            </div>
        </main>
        
        <aside class="right-panel" id="rightPanel">
            <div class="panel-content" id="panelContent"></div>
        </aside>
    </div>
    
    <div id="addContactModal" class="modal">
        <div class="modal-content">
            <div class="modal-header"><h3>Добавить контакт</h3><button class="close-modal">&times;</button></div>
            <div class="modal-body">
                <input type="text" id="contactSearch" placeholder="Username или телефон">
                <button id="searchContactBtn" class="btn-primary">Поиск</button>
                <div id="searchResults"></div>
            </div>
        </div>
    </div>
    
    <div id="callModal" class="modal call-modal">
        <div class="modal-content">
            <div class="call-container">
                <video id="localVideo" autoplay muted playsinline></video>
                <video id="remoteVideo" autoplay playsinline></video>
                <div class="call-controls">
                    <button id="muteBtn" class="call-btn"><i class="fas fa-microphone"></i></button>
                    <button id="videoToggleBtn" class="call-btn"><i class="fas fa-video"></i></button>
                    <button id="screenBtn" class="call-btn"><i class="fas fa-desktop"></i></button>
                    <button id="endCallBtn" class="call-btn end-call"><i class="fas fa-phone-slash"></i></button>
                </div>
            </div>
        </div>
    </div>
    
    <div id="toastContainer"></div>
    
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script>
        // ==================== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ====================
        let socket = null;
        let currentUser = null;
        let currentChat = null;
        let contacts = [];
        let chats = [];
        let messages = [];
        let typingTimeout = null;
        let isTyping = false;
        let peerConnection = null;
        let localStream = null;
        let currentCall = null;
        
        // ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
        function showToast(message, type = 'info') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }
        
        function formatTime(date) {
            const d = new Date(date);
            return d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function getStatusIcon(status) {
            switch(status) {
                case 'sent': return 'fa-check';
                case 'delivered': return 'fa-check-double';
                case 'read': return 'fa-check-double';
                default: return 'fa-clock';
            }
        }
        
        // ==================== АВТОРИЗАЦИЯ ====================
        function checkAuth() {
            const token = localStorage.getItem('token');
            if (!token) {
                window.location.href = '/login';
                return false;
            }
            return true;
        }
        
        async function loadCurrentUser() {
            const token = localStorage.getItem('token');
            const res = await fetch('/api/me', { headers: { 'Authorization': \`Bearer \${token}\` } });
            if (res.ok) {
                currentUser = await res.json();
                document.getElementById('currentUsername').textContent = currentUser.display_name || currentUser.username;
                document.getElementById('currentUserStatus').textContent = currentUser.status || 'online';
                if (currentUser.avatar) document.getElementById('currentUserAvatar').src = currentUser.avatar;
                document.body.setAttribute('data-theme', currentUser.theme || 'dark');
                return true;
            }
            localStorage.clear();
            window.location.href = '/login';
            return false;
        }
        
        // ==================== КОНТАКТЫ И ЧАТЫ ====================
        async function loadContacts() {
            const token = localStorage.getItem('token');
            const res = await fetch('/api/contacts', { headers: { 'Authorization': \`Bearer \${token}\` } });
            if (res.ok) {
                contacts = await res.json();
                updateChatsList();
            }
        }
        
        async function addContact(contactId) {
            const token = localStorage.getItem('token');
            await fetch('/api/contacts', {
                method: 'POST',
                headers: { 'Authorization': \`Bearer \${token}\`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ contactId })
            });
            loadContacts();
            showToast('Контакт добавлен', 'success');
        }
        
        function updateChatsList() {
            const container = document.getElementById('chatsList');
            container.innerHTML = '';
            
            // Личные чаты из контактов
            contacts.forEach(contact => {
                const chatId = \`chat_\${Math.min(currentUser.id, contact.contact_id)}_\${Math.max(currentUser.id, contact.contact_id)}\`;
                const div = document.createElement('div');
                div.className = 'chat-item' + (currentChat?.id === chatId ? ' active' : '');
                div.innerHTML = \`
                    <img class="chat-avatar" src="\${contact.avatar || 'https://via.placeholder.com/48'}" alt="">
                    <div class="chat-info">
                        <div class="chat-name">\${escapeHtml(contact.display_name || contact.username)}</div>
                        <div class="chat-last-message">\${contact.status === 'online' ? '🟢 Онлайн' : '⚫ Оффлайн'}</div>
                    </div>
                \`;
                div.onclick = () => openChat({ id: chatId, type: 'private', userId: contact.contact_id, name: contact.display_name || contact.username, avatar: contact.avatar });
                container.appendChild(div);
            });
        }
        
        async function openChat(chat) {
            currentChat = chat;
            
            // Обновляем заголовок
            document.getElementById('chatName').textContent = chat.name;
            document.getElementById('chatAvatar').src = chat.avatar || 'https://via.placeholder.com/40';
            
            // Загружаем историю сообщений
            const token = localStorage.getItem('token');
            const res = await fetch(\`/api/messages/\${chat.id}\`, { headers: { 'Authorization': \`Bearer \${token}\` } });
            const data = await res.json();
            messages = data.messages || [];
            renderMessages();
            
            // Обновляем активный чат в списке
            document.querySelectorAll('.chat-item').forEach(el => el.classList.remove('active'));
            const activeItem = Array.from(document.querySelectorAll('.chat-item')).find(el => el.querySelector('.chat-name')?.textContent === chat.name);
            if (activeItem) activeItem.classList.add('active');
        }
        
        function renderMessages() {
            const container = document.getElementById('messagesList');
            container.innerHTML = '';
            
            messages.forEach(msg => {
                const isMe = msg.sender_id === currentUser.id;
                const div = document.createElement('div');
                div.className = \`message \${isMe ? 'me' : ''}\`;
                div.dataset.messageId = msg.message_id;
                div.innerHTML = \`
                    \${!isMe ? \`<img class="message-avatar" src="\${msg.avatar || 'https://via.placeholder.com/36'}" alt="">\` : ''}
                    <div class="message-content">
                        <div class="message-header">
                            <span class="message-sender">\${escapeHtml(msg.display_name || msg.username)}</span>
                            <span class="message-time">\${formatTime(msg.created_at)}</span>
                        </div>
                        <div class="message-bubble">
                            \${msg.message_type === 'text' ? escapeHtml(msg.content) : 
                              (msg.file_url ? \`<div class="message-file" onclick="window.open('\${msg.file_url}')"><i class="fas fa-file"></i> \${escapeHtml(msg.file_name)}</div>\` : 'Файл')}
                        </div>
                        \${isMe ? \`<div class="message-status"><i class="fas \${getStatusIcon(msg.status)}"></i></div>\` : ''}
                    </div>
                \`;
                container.appendChild(div);
            });
            
            scrollToBottom();
        }
        
        function scrollToBottom() {
            const container = document.getElementById('messagesContainer');
            if (container) container.scrollTop = container.scrollHeight;
        }
        
        // ==================== ОТПРАВКА СООБЩЕНИЙ ====================
        function sendMessage() {
            const input = document.getElementById('messageInput');
            const content = input.value.trim();
            if (!content || !currentChat) return;
            
            socket.emit('send_message', {
                chatId: currentChat.id,
                recipientId: currentChat.type === 'private' ? currentChat.userId : null,
                messageType: 'text',
                content: content
            });
            
            input.value = '';
            adjustTextareaHeight(input);
        }
        
        function adjustTextareaHeight(textarea) {
            textarea.style.height = 'auto';
            textarea.style.height = Math.min(textarea.scrollHeight, 100) + 'px';
        }
        
        function handleTyping() {
            if (!currentChat) return;
            if (!isTyping) {
                isTyping = true;
                socket.emit('typing', { recipientId: currentChat.userId, isTyping: true });
            }
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(() => {
                isTyping = false;
                socket.emit('typing', { recipientId: currentChat.userId, isTyping: false });
            }, 1000);
        }
        
        // ==================== ЗВОНКИ (WebRTC) ====================
        async function startCall(isVideo = false) {
            if (!currentChat || currentChat.type !== 'private') {
                showToast('Звонки доступны только в личных чатах', 'error');
                return;
            }
            
            const modal = document.getElementById('callModal');
            modal.style.display = 'flex';
            
            try {
                localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: isVideo });
                document.getElementById('localVideo').srcObject = localStream;
                
                peerConnection = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
                
                localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
                
                peerConnection.ontrack = (event) => {
                    document.getElementById('remoteVideo').srcObject = event.streams[0];
                };
                
                peerConnection.onicecandidate = (event) => {
                    if (event.candidate) {
                        socket.emit('ice_candidate', { targetUserId: currentChat.userId, candidate: event.candidate });
                    }
                };
                
                const offer = await peerConnection.createOffer();
                await peerConnection.setLocalDescription(offer);
                
                socket.emit('call_user', {
                    targetUserId: currentChat.userId,
                    callType: isVideo ? 'video' : 'audio',
                    signalData: offer
                });
                
                currentCall = { isVideo, targetUserId: currentChat.userId };
            } catch (err) {
                showToast('Не удалось получить доступ к микрофону/камере', 'error');
                modal.style.display = 'none';
            }
        }
        
        // ==================== ПРОФИЛЬ И НАСТРОЙКИ ====================
        function showSettings() {
            const panel = document.getElementById('panelContent');
            panel.innerHTML = \`
                <div class="panel-section">
                    <h3>Профиль</h3>
                    <div class="profile-field">
                        <label>Имя</label>
                        <input type="text" id="editDisplayName" value="\${escapeHtml(currentUser.display_name || '')}">
                    </div>
                    <div class="profile-field">
                        <label>О себе</label>
                        <input type="text" id="editBio" value="\${escapeHtml(currentUser.bio || '')}">
                    </div>
                    <div class="profile-field">
                        <label>Статус</label>
                        <select id="editStatus">
                            <option value="online" \${currentUser.status === 'online' ? 'selected' : ''}>Онлайн</option>
                            <option value="away" \${currentUser.status === 'away' ? 'selected' : ''}>Отошел</option>
                            <option value="dnd" \${currentUser.status === 'dnd' ? 'selected' : ''}>Не беспокоить</option>
                        </select>
                    </div>
                    <div class="profile-field">
                        <label>Тема</label>
                        <select id="editTheme">
                            <option value="dark" \${currentUser.theme === 'dark' ? 'selected' : ''}>Темная</option>
                            <option value="light" \${currentUser.theme === 'light' ? 'selected' : ''}>Светлая</option>
                        </select>
                    </div>
                    <button id="saveProfileBtn" class="btn-primary">Сохранить</button>
                </div>
                <div class="panel-section">
                    <h3>Контакты</h3>
                    <div id="contactsList"></div>
                </div>
            \`;
            
            // Загрузка контактов в панель
            const contactsDiv = document.getElementById('contactsList');
            contacts.forEach(contact => {
                const div = document.createElement('div');
                div.className = 'contact-item';
                div.innerHTML = \`
                    <img src="\${contact.avatar || 'https://via.placeholder.com/32'}" style="width:32px;height:32px;border-radius:50%">
                    <span>\${escapeHtml(contact.display_name || contact.username)}</span>
                    <button class="remove-contact" data-id="\${contact.contact_id}" style="margin-left:auto;background:none;border:none;color:var(--danger);cursor:pointer"><i class="fas fa-trash"></i></button>
                \`;
                contactsDiv.appendChild(div);
            });
            
            document.getElementById('saveProfileBtn')?.addEventListener('click', saveProfile);
            document.querySelectorAll('.remove-contact').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const token = localStorage.getItem('token');
                    await fetch(\`/api/contacts/\${btn.dataset.id}\`, { method: 'DELETE', headers: { 'Authorization': \`Bearer \${token}\` } });
                    loadContacts();
                    showSettings();
                });
            });
        }
        
        async function saveProfile() {
            const token = localStorage.getItem('token');
            const data = {
                display_name: document.getElementById('editDisplayName')?.value,
                bio: document.getElementById('editBio')?.value,
                status: document.getElementById('editStatus')?.value,
                theme: document.getElementById('editTheme')?.value
            };
            
            await fetch('/api/profile', {
                method: 'PUT',
                headers: { 'Authorization': \`Bearer \${token}\`, 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            
            currentUser = { ...currentUser, ...data };
            document.body.setAttribute('data-theme', data.theme);
            showToast('Профиль обновлен', 'success');
        }
        
        // ==================== ЗАГРУЗКА ФАЙЛОВ ====================
        async function attachFile() {
            const input = document.createElement('input');
            input.type = 'file';
            input.onchange = async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                
                const formData = new FormData();
                formData.append('file', file);
                const token = localStorage.getItem('token');
                
                const res = await fetch('/api/upload', {
                    method: 'POST',
                    headers: { 'Authorization': \`Bearer \${token}\` },
                    body: formData
                });
                
                const data = await res.json();
                if (data.url && currentChat) {
                    socket.emit('send_message', {
                        chatId: currentChat.id,
                        recipientId: currentChat.userId,
                        messageType: 'file',
                        fileUrl: data.url,
                        fileName: data.name,
                        fileSize: data.size
                    });
                }
            };
            input.click();
        }
        
        // ==================== ИНИЦИАЛИЗАЦИЯ СОКЕТА ====================
        function initSocket() {
            const token = localStorage.getItem('token');
            socket = io({ auth: { token } });
            
            socket.on('connect', () => showToast('Подключено к серверу', 'success'));
            
            socket.on('new_message', (msg) => {
                if (currentChat && msg.chatId === currentChat.id) {
                    messages.push(msg);
                    renderMessages();
                }
            });
            
            socket.on('user_typing', (data) => {
                if (currentChat && data.userId === currentChat.userId) {
                    const indicator = document.getElementById('typingIndicator');
                    indicator.style.display = data.isTyping ? 'block' : 'none';
                }
            });
            
            socket.on('user_status', (data) => {
                if (currentChat && data.userId === currentChat.userId) {
                    const status = document.getElementById('currentUserStatus');
                    if (status) status.textContent = data.status;
                }
            });
            
            socket.on('incoming_call', async (data) => {
                if (confirm(\`Входящий звонок от \${data.fromUsername}. Принять?\`)) {
                    const modal = document.getElementById('callModal');
                    modal.style.display = 'flex';
                    
                    try {
                        localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: data.callType === 'video' });
                        document.getElementById('localVideo').srcObject = localStream;
                        
                        peerConnection = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
                        localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
                        
                        peerConnection.ontrack = (event) => {
                            document.getElementById('remoteVideo').srcObject = event.streams[0];
                        };
                        
                        peerConnection.onicecandidate = (event) => {
                            if (event.candidate) {
                                socket.emit('ice_candidate', { targetUserId: data.fromUserId, candidate: event.candidate });
                            }
                        };
                        
                        await peerConnection.setRemoteDescription(new RTCSessionDescription(data.signalData));
                        const answer = await peerConnection.createAnswer();
                        await peerConnection.setLocalDescription(answer);
                        
                        socket.emit('answer_call', { targetUserId: data.fromUserId, signalData: answer });
                    } catch (err) {
                        showToast('Ошибка при ответе на звонок', 'error');
                    }
                } else {
                    socket.emit('end_call', { targetUserId: data.fromUserId });
                }
            });
            
            socket.on('call_answered', async (data) => {
                if (peerConnection) {
                    await peerConnection.setRemoteDescription(new RTCSessionDescription(data.signalData));
                }
            });
            
            socket.on('ice_candidate', (data) => {
                if (peerConnection) {
                    peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
                }
            });
            
            socket.on('call_ended', () => {
                if (peerConnection) peerConnection.close();
                if (localStream) localStream.getTracks().forEach(track => track.stop());
                document.getElementById('callModal').style.display = 'none';
                showToast('Звонок завершен', 'info');
            });
        }
        
        // ==================== ОБРАБОТЧИКИ СОБЫТИЙ ====================
        function bindEvents() {
            document.getElementById('sendBtn')?.addEventListener('click', sendMessage);
            document.getElementById('attachBtn')?.addEventListener('click', attachFile);
            document.getElementById('newChatBtn')?.addEventListener('click', () => {
                document.getElementById('addContactModal').style.display = 'flex';
            });
            document.getElementById('settingsBtn')?.addEventListener('click', showSettings);
            document.getElementById('infoBtn')?.addEventListener('click', showSettings);
            document.getElementById('logoutBtn')?.addEventListener('click', () => {
                localStorage.clear();
                window.location.href = '/login';
            });
            document.getElementById('callBtn')?.addEventListener('click', () => startCall(false));
            document.getElementById('videoCallBtn')?.addEventListener('click', () => startCall(true));
            document.getElementById('endCallBtn')?.addEventListener('click', () => {
                if (currentCall) socket.emit('end_call', { targetUserId: currentCall.targetUserId });
                document.getElementById('callModal').style.display = 'none';
                if (peerConnection) peerConnection.close();
                if (localStream) localStream.getTracks().forEach(track => track.stop());
            });
            document.getElementById('muteBtn')?.addEventListener('click', () => {
                if (localStream) {
                    const audioTrack = localStream.getAudioTracks()[0];
                    if (audioTrack) audioTrack.enabled = !audioTrack.enabled;
                }
            });
            document.getElementById('videoToggleBtn')?.addEventListener('click', () => {
                if (localStream) {
                    const videoTrack = localStream.getVideoTracks()[0];
                    if (videoTrack) videoTrack.enabled = !videoTrack.enabled;
                }
            });
            document.getElementById('screenBtn')?.addEventListener('click', async () => {
                const screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
                const videoTrack = screenStream.getVideoTracks()[0];
                const sender = peerConnection?.getSenders().find(s => s.track?.kind === 'video');
                if (sender) sender.replaceTrack(videoTrack);
            });
            
            document.getElementById('messageInput')?.addEventListener('input', () => {
                adjustTextareaHeight(document.getElementById('messageInput'));
                handleTyping();
            });
            document.getElementById('messageInput')?.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                }
            });
            
            document.querySelectorAll('.close-modal').forEach(btn => {
                btn.addEventListener('click', () => {
                    document.getElementById('addContactModal').style.display = 'none';
                });
            });
            
            document.getElementById('searchContactBtn')?.addEventListener('click', async () => {
                const q = document.getElementById('contactSearch').value;
                if (!q) return;
                const token = localStorage.getItem('token');
                const res = await fetch(\`/api/search?q=\${encodeURIComponent(q)}\`, { headers: { 'Authorization': \`Bearer \${token}\` } });
                const users = await res.json();
                const resultsDiv = document.getElementById('searchResults');
                resultsDiv.innerHTML = '';
                users.forEach(user => {
                    const div = document.createElement('div');
                    div.className = 'search-result';
                    div.innerHTML = \`\${escapeHtml(user.display_name || user.username)} (\${user.username})\`;
                    div.onclick = () => addContact(user.id);
                    resultsDiv.appendChild(div);
                });
            });
        }
        
        // ==================== ЗАПУСК ====================
        async function init() {
            if (!checkAuth()) return;
            await loadCurrentUser();
            await loadContacts();
            initSocket();
            bindEvents();
        }
        
        init();
    </script>
</body>
</html>
  `);
});

// Страница входа
app.get('/login', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход - Димаграм</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            width: 400px;
            max-width: 90%;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        .logo {
            text-align: center;
            font-size: 48px;
            margin-bottom: 30px;
            color: white;
        }
        h2 {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        input {
            width: 100%;
            padding: 15px;
            margin-bottom: 15px;
            background: rgba(255,255,255,0.2);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
        }
        input::placeholder { color: rgba(255,255,255,0.7); }
        button {
            width: 100%;
            padding: 15px;
            background: #5865f2;
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover { background: #4752c4; }
        .link {
            text-align: center;
            margin-top: 20px;
            color: white;
        }
        .link a { color: white; text-decoration: underline; }
        .error {
            background: rgba(255,0,0,0.3);
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 15px;
            color: white;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo"><i class="fab fa-telegram"></i></div>
        <h2>Вход в Димаграм</h2>
        <div id="error" class="error" style="display:none"></div>
        <input type="text" id="login" placeholder="Логин или номер телефона">
        <input type="password" id="password" placeholder="Пароль">
        <button onclick="login()">Войти</button>
        <div class="link">Нет аккаунта? <a href="/register">Зарегистрироваться</a></div>
    </div>
    <script>
        async function login() {
            const login = document.getElementById('login').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ login, password })
            });
            
            const data = await res.json();
            if (res.ok) {
                localStorage.setItem('token', data.token);
                window.location.href = '/';
            } else {
                errorDiv.style.display = 'block';
                errorDiv.textContent = data.error || 'Ошибка входа';
            }
        }
        
        document.getElementById('password').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') login();
        });
    </script>
</body>
</html>
  `);
});

// Страница регистрации
app.get('/register', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Регистрация - Димаграм</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .register-container {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            width: 400px;
            max-width: 90%;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        .logo {
            text-align: center;
            font-size: 48px;
            margin-bottom: 30px;
            color: white;
        }
        h2 {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        input {
            width: 100%;
            padding: 15px;
            margin-bottom: 15px;
            background: rgba(255,255,255,0.2);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
        }
        input::placeholder { color: rgba(255,255,255,0.7); }
        button {
            width: 100%;
            padding: 15px;
            background: #5865f2;
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover { background: #4752c4; }
        .link {
            text-align: center;
            margin-top: 20px;
            color: white;
        }
        .link a { color: white; text-decoration: underline; }
        .error {
            background: rgba(255,0,0,0.3);
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 15px;
            color: white;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <div class="logo"><i class="fab fa-telegram"></i></div>
        <h2>Регистрация в Димаграм</h2>
        <div id="error" class="error" style="display:none"></div>
        <input type="text" id="username" placeholder="Имя пользователя">
        <input type="text" id="phone" placeholder="Номер телефона">
        <input type="text" id="displayName" placeholder="Отображаемое имя (опционально)">
        <input type="password" id="password" placeholder="Пароль">
        <button onclick="register()">Зарегистрироваться</button>
        <div class="link">Уже есть аккаунт? <a href="/login">Войти</a></div>
    </div>
    <script>
        async function register() {
            const username = document.getElementById('username').value;
            const phone = document.getElementById('phone').value;
            const displayName = document.getElementById('displayName').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            
            const res = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, phone, displayName, password })
            });
            
            const data = await res.json();
            if (res.ok) {
                localStorage.setItem('token', data.token);
                window.location.href = '/';
            } else {
                errorDiv.style.display = 'block';
                errorDiv.textContent = data.error || 'Ошибка регистрации';
            }
        }
        
        document.getElementById('password').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') register();
        });
    </script>
</body>
</html>
  `);
});

// Статические файлы (создаем папку uploads для доступа)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==================== ЗАПУСК СЕРВЕРА ====================
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║     🚀 ДИМАГРАМ - Современный мессенджер запущен     ║
╠══════════════════════════════════════════════════════╣
║  🌐 Открой в браузере: http://localhost:${PORT}        ║
║  📝 Зарегистрируйся и начни общаться!               ║
║  💬 Поддерживает: чаты, звонки, файлы               ║
╚══════════════════════════════════════════════════════╝
  `);
});