if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'super-secret-key-2025';

// OTP temporary memory storage (server restart pe clear ho jayega)
const tempRegistrations = {};

app.use(express.json({ limit: '50mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB connect hone ke baad hi server start
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB Connected');
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ DB connection failed:', err);
    process.exit(1);
  });

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  reputation: { type: Number, default: 0 }
});

const PostSchema = new mongoose.Schema({
  title: String,
  type: { type: String, enum: ['Lost', 'Found'] },
  location: String,
  description: String,
  imageUrl: String,
  date: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: String,
  status: { type: String, default: 'Active' },
  verificationPin: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);

// JWT verify middleware (protected routes ke liye)
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// OTP generate (gmail only, capstone mode me console log)
app.post('/auth/send-otp', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username.endsWith('@gmail.com')) {
      return res.status(400).json({ error: 'Sirf @gmail.com allowed hai' });
    }

    if (await User.findOne({ username })) {
      return res.status(400).json({ error: 'User already exist karta hai' });
    }

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    tempRegistrations[username] = otp;

    console.log(`🔐 OTP for ${username}: ${otp}`);

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// OTP verify + user create + auto login
app.post('/auth/register-complete', async (req, res) => {
  const { username, otp, password } = req.body;

  if (tempRegistrations[username] !== otp) {
    return res.status(400).json({ error: 'OTP invalid ya expire' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await new User({ username, password: hashedPassword }).save();

    delete tempRegistrations[username];

    const token = jwt.sign({ id: user._id, username }, JWT_SECRET);
    res.json({ success: true, token, username });
  } catch {
    res.status(500).json({ error: 'Database error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user) return res.status(400).json({ error: 'User nahi mila' });

  if (!(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).json({ error: 'Password galat hai' });
  }

  const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
  res.json({ success: true, token, username: user.username });
});

// Posts fetch
app.get('/posts', async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 });
  res.json(posts);
});

// Post create (login required)
app.post('/posts', authenticateToken, async (req, res) => {
  try {
    const post = await new Post({
      ...req.body,
      author: req.user.id,
      authorName: req.user.username
    }).save();

    res.status(201).json(post);
  } catch {
    res.status(500).send('Post save error');
  }
});

// Claim ke liye PIN generate
app.post('/generate-pin/:id', authenticateToken, async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ error: 'Invalid Item ID' });
  }

  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ error: 'Item nahi mila' });

  post.verificationPin = Math.floor(1000 + Math.random() * 9000).toString();
  await post.save();

  res.json({ pin: post.verificationPin });
});

// PIN verify → item resolve + reputation reward
app.post('/verify-pin/:id', authenticateToken, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.verificationPin !== req.body.pin) {
    return res.status(400).json({ success: false, message: 'PIN galat' });
  }

  post.status = 'Resolved';
  post.verificationPin = null;
  await post.save();

  await User.findByIdAndUpdate(req.user.id, { $inc: { reputation: 10 } });

  res.json({ success: true });
});
