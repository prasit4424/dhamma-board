// ----------------------------------------------------------------
// ระบบหลังบ้าน (Backend API) สำหรับกระดานสนทนาธรรม
// Version: Final (Ready for Deployment with MongoDB)
// ----------------------------------------------------------------

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // To use environment variables from a .env file

const app = express();
const PORT = process.env.PORT || 3001;

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Database Connection ---
// ตรวจสอบว่ามี DATABASE_URL ใน .env หรือไม่
if (!process.env.DATABASE_URL) {
    console.error("FATAL ERROR: DATABASE_URL is not defined in .env file.");
    process.exit(1); // ออกจากโปรแกรมถ้าไม่มีการตั้งค่า
}
mongoose.connect(process.env.DATABASE_URL)
.then(() => console.log('MongoDB connected successfully.'))
.catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas (Data Structure) ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] },
    profileImageUrl: { type: String, default: 'https://placehold.co/96x96/a5b4fc/1e3a8a?text=ธรรม' }
}, { timestamps: true });

const PostSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true, trim: true },
    content: { type: String, required: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

const CommentSchema = new mongoose.Schema({
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

// --- Mongoose Models ---
const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Comment = mongoose.model('Comment', CommentSchema);

// --- Middleware for Authentication ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Permission denied: Admins only' });
    }
    next();
};

// --- API Endpoints ---

// Auth
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password || password.length < 6) return res.status(400).json({ message: 'ข้อมูลไม่ถูกต้อง' });
        
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: 'ชื่อผู้ใช้นี้มีคนใช้แล้ว' });

        const hashedPassword = await bcrypt.hash(password, 12);
        await User.create({ username, password: hashedPassword });
        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ' });
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

        const userPayload = { id: user._id, username: user.username, role: user.role, profileImageUrl: user.profileImageUrl };
        const token = jwt.sign(userPayload, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ message: 'เข้าสู่ระบบสำเร็จ', token, user: userPayload });
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

// Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { profileImageUrl } = req.body;
        if (!profileImageUrl) return res.status(400).json({ message: 'กรุณาระบุ URL ของรูปภาพ' });

        const updatedUser = await User.findByIdAndUpdate(req.user.id, { profileImageUrl }, { new: true }).select('-password');
        res.json({ message: 'อัปเดตโปรไฟล์สำเร็จ', user: updatedUser });
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

// Posts
app.post('/api/posts', authenticateToken, async (req, res) => {
    try {
        const { title, content } = req.body;
        const newPost = await Post.create({ userId: req.user.id, title, content });
        const populatedPost = await newPost.populate('userId', 'username profileImageUrl');
        res.status(201).json(populatedPost);
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().populate('userId', 'username profileImageUrl').sort({ createdAt: -1 });
        // In a real app, you'd calculate comment counts more efficiently
        res.json(posts);
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

app.get('/api/posts/:id', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id).populate('userId', 'username profileImageUrl');
        if (!post) return res.status(404).json({ message: 'ไม่พบกระทู้' });
        
        const comments = await Comment.find({ postId: req.params.id }).populate('userId', 'username profileImageUrl').sort({ createdAt: -1 });
        
        res.json({ post, comments });
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ message: 'ไม่พบกระทู้' });

        if (post.userId.toString() !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'คุณไม่มีสิทธิ์ลบกระทู้นี้' });
        }
        
        await post.deleteOne();
        await Comment.deleteMany({ postId: req.params.id });
        res.json({ message: 'ลบกระทู้สำเร็จ' });
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

// Comments
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        const newComment = await Comment.create({ postId: req.params.id, userId: req.user.id, content });
        const populatedComment = await newComment.populate('userId', 'username profileImageUrl');
        res.status(201).json(populatedComment);
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

// Likes
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        const likeIndex = post.likes.indexOf(req.user.id);

        if (likeIndex > -1) {
            post.likes.splice(likeIndex, 1); // Unlike
        } else {
            post.likes.push(req.user.id); // Like
        }
        await post.save();
        res.json({ likeCount: post.likes.length });
    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาด' }); }
});

// Gemini AI Features
app.post('/api/posts/:id/summarize', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ message: 'ไม่พบกระทู้' });
        const comments = await Comment.find({ postId: req.params.id });

        let promptText = `กรุณาสรุปใจความสำคัญของกระทู้ธรรมะต่อไปนี้:\n\nหัวข้อ: ${post.title}\nเนื้อหา: ${post.content}\n\nความคิดเห็น:\n${comments.map(c => c.content).join('\n- ')}`;
        
        // Gemini API Call Logic (same as before)
        const apiKey = process.env.GEMINI_API_KEY || "";
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
        const payload = { contents: [{ role: "user", parts: [{ text: promptText }] }] };
        const geminiResponse = await fetch(apiUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        const result = await geminiResponse.json();
        const summary = result.candidates[0].content.parts[0].text;
        res.json({ summary });

    } catch (error) { res.status(500).json({ message: 'เกิดข้อผิดพลาดในการสรุปผล' }); }
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
