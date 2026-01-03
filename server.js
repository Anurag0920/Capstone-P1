if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'super-secret-key-2025';

// --- EMAIL CONFIGURATION ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'yourdeathisnear07@gmail.com', // Your Real Email
        pass: 'ascy pxlq itke aobj'          // Your App Password
    }
});

// Store OTPs in memory { "email": "123456" }
const tempRegistrations = {}; 

app.use(express.json({ limit: '50mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public'))); // Serves your HTML/CSS/JS

// DB Connection
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

// Schemas
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
    date: String, // String format for UI display
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    authorName: String,
    status: { type: String, default: 'Active' },
    verificationPin: String,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);

// Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- AUTH ROUTES ---

// 1. Send OTP
app.post('/auth/send-otp', async (req, res) => {
    const { username } = req.body;

    // Validate Gmail
    if (!username.endsWith('@gmail.com')) {
        return res.status(400).json({ error: 'Please use a valid @gmail.com address' });
    }

    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: 'User already exists. Please Login.' });

    const otp = Math.floor(1000 + Math.random() * 9000).toString(); // 4 Digit OTP
    tempRegistrations[username] = otp;

    const mailOptions = {
        from: '"Misplaced Mansion Admin" <yourdeathisnear07@gmail.com>',
        to: username,
        subject: 'Verify your Account',
        text: `Welcome! Your verification code is: ${otp}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("Email Error:", error);
            return res.status(500).json({ error: 'Failed to send email.' });
        }
        res.json({ success: true, message: 'OTP Sent' });
    });
});

// 2. Verify & Register
app.post('/auth/register-complete', async (req, res) => {
    const { username, otp, password } = req.body;

    if (!tempRegistrations[username] || tempRegistrations[username] !== otp) {
        return res.status(400).json({ error: 'Invalid or Expired OTP' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        
        delete tempRegistrations[username]; // Cleanup
        
        // Auto Login
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
        res.json({ success: true, token, username: user.username });
    } catch (e) {
        res.status(500).json({ error: 'Database error' });
    }
});

// 3. Login
app.post('/login', async (req, res) => {
    const user = await User.findOne({ username: req.body.username });
    if (!user) return res.status(400).json({ error: 'User not found' });
    
    if (await bcrypt.compare(req.body.password, user.password)) {
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
        res.json({ success: true, token, username: user.username });
    } else {
        res.status(401).json({ error: 'Invalid password' });
    }
});

// --- POST ROUTES ---
app.get('/posts', async (req, res) => {
    const posts = await Post.find().sort({ createdAt: -1 });
    res.json(posts);
});

app.post('/posts', authenticateToken, async (req, res) => {
    try {
        const post = new Post({ 
            ...req.body, 
            author: req.user.id, 
            authorName: req.user.username 
        });
        await post.save();
        res.status(201).json(post);
    } catch (e) { res.status(500).send('Error saving post'); }
});

// --- PIN VERIFICATION ROUTES (CRITICAL FOR CLAIMING) ---

// 1. Generate PIN (For Claimant)
app.post('/generate-pin/:id', authenticateToken, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid Item ID' });
        }

        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Item not found' });

        const pin = Math.floor(1000 + Math.random() * 9000).toString();
        post.verificationPin = pin;
        await post.save();
        
        res.json({ pin });
    } catch (e) {
        console.error("Generate PIN Error:", e);
        res.status(500).json({ error: 'Server Error' });
    }
});

// 2. Verify PIN (For Owner)
app.post('/verify-pin/:id', authenticateToken, async (req, res) => {
    const { pin } = req.body;
    try {
        const post = await Post.findById(req.params.id);
        
        if (post.verificationPin === pin) {
            post.status = 'Resolved';
            post.verificationPin = null; // Clear PIN
            await post.save();
            
            // Give Reputation to User
            await User.findByIdAndUpdate(req.user.id, { $inc: { reputation: 10 } });
            
            res.json({ success: true, message: 'Verified!' });
        } else { 
            res.status(400).json({ success: false, message: 'Wrong PIN' }); 
        }
    } catch (e) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));