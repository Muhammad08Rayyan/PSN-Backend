const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { createServer } = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Allow all origins for development
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(express.json());
app.use(cors());

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer configuration for handling file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI;
console.log('Connecting to MongoDB:', MONGODB_URI);
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Doctor Schema (matching existing database structure)
const doctorSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  residence: { type: String },
  gender: { type: String },
  designation: { type: String },
  pmdcNumber: { type: String },
  address: { type: String },
  province: { type: String },
  country: { type: String },
  instAdress: { type: String },
  instName: { type: String },
  fathersName: { type: String },
  dob: { type: Date },
  cnic: { type: String },
  city: { type: String },
  phone: { type: String },
  isFinalized: { type: Boolean, default: true },
  approvalStatus: { type: String, default: 'Approved' },
  paymentApprovalStatus: { type: String, default: 'Approved' },
  profilePic: { type: String },
  bankSlipPic: { type: String },
  highestQualification: { type: String },
  qualificationDocument: { type: String },
  membershipNumber: { type: Number },
  pushToken: { type: String }, // For push notifications
  // Additional compatibility fields
  specialty: { type: String },
  location: { type: String },
  institution: { type: String }
}, { timestamps: true });

const Doctor = mongoose.model('Doctor', doctorSchema, 'doctors');

// Post Schema for social feed
const postSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
  content: { type: String, required: true },
  image_url: { type: String },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' }],
  comments: [{
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
    content: { type: String, required: true },
    created_at: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const Post = mongoose.model('Post', postSchema, 'posts');

// News Schema for announcements (admin-managed, read-only for mobile)
const newsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image_url: { type: String },
  published_at: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  createdBy: { type: String, default: 'Admin' }
}, { timestamps: true });

const News = mongoose.model('News', newsSchema, 'news');

// Chat Schemas
const conversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true }],
  lastMessage: {
    content: String,
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
    timestamp: { type: Date, default: Date.now }
  },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
  content: { type: String, required: true },
  messageType: { type: String, default: 'text' },
  readBy: [{
    doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
    readAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const Conversation = mongoose.model('Conversation', conversationSchema, 'conversations');
const Message = mongoose.model('Message', messageSchema, 'messages');

// Temporary storage for reset codes (in production, use Redis or database)
const resetCodes = new Map();

// JWT middleware for protected routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'psn_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt for:', email);

    // Find doctor by email
    const doctor = await Doctor.findOne({ email });
    console.log('Doctor found:', !!doctor);
    if (!doctor) {
      console.log('No doctor found with email:', email);
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, doctor.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: doctor._id },
      process.env.JWT_SECRET || 'psn_secret_key',
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: doctor._id,
        name: doctor.name || 'Doctor',
        email: doctor.email,
        specialty: doctor.specialty || doctor.highestQualification || 'Neurologist',
        location: doctor.location || `${doctor.city}, ${doctor.country}` || 'Pakistan',
        institution: doctor.institution || doctor.instName || '',
        profile_image: doctor.profilePic || '',
        designation: doctor.designation || '',
        membershipNumber: doctor.membershipNumber || ''
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user profile endpoint
app.get('/api/auth/profile', async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'psn_secret_key');
    const doctor = await Doctor.findById(decoded.userId).select('-password');

    if (!doctor) {
      return res.status(404).json({ message: 'Doctor not found' });
    }

    res.json(doctor);
  } catch (error) {
    console.error(error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Update profile picture
app.post('/api/auth/update-profile-pic', upload.single('profilePic'), async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'psn_secret_key');

    if (!req.file) {
      return res.status(400).json({ message: 'No image file provided' });
    }

    // Upload to Cloudinary
    const uploadResult = await cloudinary.uploader.upload_stream(
      {
        folder: process.env.CLOUDINARY_FOLDER || 'PSN',
        transformation: [
          { width: 300, height: 300, crop: 'fill', gravity: 'face' },
          { quality: 'auto' }
        ]
      },
      async (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          return res.status(500).json({ message: 'Failed to upload image' });
        }

        try {
          // Update doctor's profile picture in database
          const doctor = await Doctor.findByIdAndUpdate(
            decoded.userId,
            { profilePic: result.secure_url },
            { new: true }
          ).select('-password');

          if (!doctor) {
            return res.status(404).json({ message: 'Doctor not found' });
          }

          res.json({
            message: 'Profile picture updated successfully',
            profilePic: result.secure_url,
            doctor: doctor
          });
        } catch (dbError) {
          console.error('Database update error:', dbError);
          res.status(500).json({ message: 'Failed to update profile picture' });
        }
      }
    );

    uploadResult.end(req.file.buffer);

  } catch (error) {
    console.error('Profile picture update error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete profile picture
app.delete('/api/auth/delete-profile-pic', async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'psn_secret_key');

    // Update doctor's profile picture in database (remove it)
    const doctor = await Doctor.findByIdAndUpdate(
      decoded.userId,
      { $unset: { profilePic: 1 } },
      { new: true }
    ).select('-password');

    if (!doctor) {
      return res.status(404).json({ message: 'Doctor not found' });
    }

    res.json({
      message: 'Profile picture deleted successfully',
      doctor: doctor
    });

  } catch (error) {
    console.error('Profile picture delete error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Forgot password - request reset code
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    // Find doctor by email
    const doctor = await Doctor.findOne({ email });
    if (!doctor) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate 6-digit reset code
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Store reset code (expires in 10 minutes)
    resetCodes.set(email, {
      code: resetCode,
      expires: Date.now() + 10 * 60 * 1000 // 10 minutes
    });

    // In production, you would send this code via email
    console.log(`Reset code for ${email}: ${resetCode}`);

    res.json({
      message: 'Reset code generated',
      // For demo purposes, return the code (remove in production)
      resetCode: resetCode
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify reset code
app.post('/api/auth/verify-reset-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    const resetData = resetCodes.get(email);
    if (!resetData) {
      return res.status(400).json({ message: 'No reset code found' });
    }

    if (Date.now() > resetData.expires) {
      resetCodes.delete(email);
      return res.status(400).json({ message: 'Reset code expired' });
    }

    if (resetData.code !== code) {
      return res.status(400).json({ message: 'Invalid reset code' });
    }

    res.json({ message: 'Code verified successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    const resetData = resetCodes.get(email);
    if (!resetData) {
      return res.status(400).json({ message: 'No reset code found' });
    }

    if (Date.now() > resetData.expires) {
      resetCodes.delete(email);
      return res.status(400).json({ message: 'Reset code expired' });
    }

    if (resetData.code !== code) {
      return res.status(400).json({ message: 'Invalid reset code' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update doctor password
    await Doctor.findOneAndUpdate({ email }, { password: hashedPassword });

    // Remove reset code
    resetCodes.delete(email);

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Image upload endpoint
app.post('/api/upload', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image file provided' });
    }

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        {
          resource_type: 'image',
          folder: process.env.CLOUDINARY_FOLDER || 'PSN',
          transformation: [
            { width: 800, height: 600, crop: 'limit' },
            { quality: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      ).end(req.file.buffer);
    });

    res.json({
      success: true,
      url: uploadResult.secure_url,
      public_id: uploadResult.public_id
    });
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ message: 'Image upload failed' });
  }
});

// Get posts with pagination (social feed)
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const posts = await Post.find()
      .populate('user_id', 'name specialty location highestQualification city country designation instName profilePic')
      .populate('comments.user_id', 'name profilePic')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    // Format posts for frontend
    const formattedPosts = posts.map(post => ({
      id: post._id,
      user: {
        id: post.user_id._id,
        name: post.user_id.name,
        specialty: post.user_id.specialty || post.user_id.highestQualification || 'Neurologist',
        location: post.user_id.location || `${post.user_id.city}, ${post.user_id.country}` || 'Pakistan',
        profilePic: post.user_id.profilePic
      },
      content: post.content,
      image_url: post.image_url,
      timestamp: formatTimeAgo(post.createdAt),
      likes: post.likes.length,
      comments: post.comments.length,
      isLiked: post.likes.includes(req.user.userId),
      createdAt: post.createdAt
    }));

    res.json({
      posts: formattedPosts,
      hasMore: posts.length === limit,
      page,
      totalPosts: await Post.countDocuments()
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create new post
app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    let content, image_url = null;

    // Handle both JSON and FormData requests
    if (req.body.content) {
      content = req.body.content;
      image_url = req.body.image_url || null;
    } else {
      return res.status(400).json({ message: 'Post content is required' });
    }

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ message: 'Post content is required' });
    }

    // If there's an uploaded image file, upload it to Cloudinary
    if (req.file) {
      try {
        const uploadResult = await new Promise((resolve, reject) => {
          cloudinary.uploader.upload_stream(
            {
              resource_type: 'image',
              folder: process.env.CLOUDINARY_FOLDER || 'PSN',
              transformation: [
                { width: 800, height: 600, crop: 'limit' },
                { quality: 'auto' }
              ]
            },
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          ).end(req.file.buffer);
        });
        image_url = uploadResult.secure_url;
      } catch (uploadError) {
        console.error('Error uploading image:', uploadError);
        return res.status(500).json({ message: 'Error uploading image' });
      }
    }

    const post = new Post({
      user_id: req.user.userId,
      content: content.trim(),
      image_url: image_url,
      likes: [],
      comments: []
    });

    await post.save();
    await post.populate('user_id', 'name specialty location highestQualification city country');

    const formattedPost = {
      id: post._id,
      user: {
        id: post.user_id._id,
        name: post.user_id.name,
        specialty: post.user_id.specialty || post.user_id.highestQualification || 'Neurologist',
        location: post.user_id.location || `${post.user_id.city}, ${post.user_id.country}` || 'Pakistan',
        profilePic: post.user_id.profilePic
      },
      content: post.content,
      image_url: post.image_url,
      timestamp: formatTimeAgo(post.createdAt),
      likes: 0,
      comments: 0,
      isLiked: false,
      createdAt: post.createdAt
    };

    res.status(201).json(formattedPost);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Like/unlike post
app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const userId = req.user.userId;
    const isLiked = post.likes.includes(userId);

    if (isLiked) {
      post.likes = post.likes.filter(id => !id.equals(userId));
    } else {
      post.likes.push(userId);
    }

    await post.save();

    res.json({
      likes: post.likes.length,
      isLiked: !isLiked
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get comments for a post
app.get('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId)
      .populate('comments.user_id', 'name profilePic');

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const formattedComments = post.comments.map(comment => ({
      id: comment._id,
      user: {
        id: comment.user_id._id,
        name: comment.user_id.name || 'User',
        profilePic: comment.user_id.profilePic
      },
      content: comment.content,
      timestamp: formatTimeAgo(comment.created_at),
      created_at: comment.created_at
    }));

    res.json({
      comments: formattedComments.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add comment to post
app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ message: 'Comment content is required' });
    }

    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const comment = {
      user_id: req.user.userId,
      content: content.trim(),
      created_at: new Date()
    };

    post.comments.push(comment);
    await post.save();
    await post.populate('comments.user_id', 'name profilePic');

    const addedComment = post.comments[post.comments.length - 1];

    res.status(201).json({
      id: addedComment._id,
      user: {
        name: addedComment.user_id.name,
        profilePic: addedComment.user_id.profilePic
      },
      content: addedComment.content,
      timestamp: formatTimeAgo(addedComment.created_at)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get news/announcements (read-only for mobile users)
app.get('/api/news', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const news = await News.find({ isActive: true })
      .sort({ published_at: -1 })
      .skip(skip)
      .limit(limit);

    const total = await News.countDocuments({ isActive: true });

    const formattedNews = news.map(article => ({
      id: article._id,
      title: article.title,
      description: article.description,
      image_url: article.image_url,
      published_at: article.published_at,
      timestamp: formatTimeAgo(article.published_at),
      createdBy: article.createdBy
    }));

    res.json({
      news: formattedNews,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    });
  } catch (error) {
    console.error('Error fetching news:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get single news article by ID
app.get('/api/news/:newsId', authenticateToken, async (req, res) => {
  try {
    const { newsId } = req.params;

    const article = await News.findById(newsId);

    if (!article || !article.isActive) {
      return res.status(404).json({ message: 'Article not found' });
    }

    const formattedArticle = {
      id: article._id,
      title: article.title,
      description: article.description,
      image_url: article.image_url,
      published_at: article.published_at,
      timestamp: formatTimeAgo(article.published_at),
      createdBy: article.createdBy
    };

    res.json(formattedArticle);
  } catch (error) {
    console.error('Error fetching news article:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Article not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Helper function to format time ago
function formatTimeAgo(date) {
  const now = new Date();
  const diffInSeconds = Math.floor((now - date) / 1000);

  if (diffInSeconds < 60) {
    return 'just now';
  } else if (diffInSeconds < 3600) {
    const minutes = Math.floor(diffInSeconds / 60);
    return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  } else if (diffInSeconds < 86400) {
    const hours = Math.floor(diffInSeconds / 3600);
    return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  } else if (diffInSeconds < 604800) {
    const days = Math.floor(diffInSeconds / 86400);
    return `${days} day${days > 1 ? 's' : ''} ago`;
  } else {
    return date.toLocaleDateString();
  }
}

// Search doctors
app.get('/api/doctors/search', authenticateToken, async (req, res) => {
  try {
    const { q: query } = req.query;

    if (!query || query.trim().length === 0) {
      return res.json({ doctors: [], total: 0 });
    }

    const searchRegex = new RegExp(query.trim(), 'i');

    const doctors = await Doctor.find({
      isFinalized: true,
      approvalStatus: { $in: ['Approved', 'Done'] },
      $or: [
        { name: { $regex: searchRegex } },
        { specialty: { $regex: searchRegex } },
        { highestQualification: { $regex: searchRegex } },
        { city: { $regex: searchRegex } },
        { country: { $regex: searchRegex } },
        { instName: { $regex: searchRegex } },
        { institution: { $regex: searchRegex } },
        { designation: { $regex: searchRegex } }
      ]
    })
    .select('-password -bankSlipPic -qualificationDocument')
    .sort({ name: 1 })
    .limit(100);

    const formattedDoctors = doctors.map(doctor => ({
      id: doctor._id,
      name: doctor.name,
      email: doctor.email,
      specialty: doctor.specialty || doctor.highestQualification || 'Neurologist',
      location: doctor.location || `${doctor.city}, ${doctor.country}` || 'Pakistan',
      hospital: doctor.institution || doctor.instName || 'Medical Institution',
      memberSince: doctor.membershipNumber ? '2018' : new Date(doctor.createdAt).getFullYear().toString(),
      profile_image: doctor.profilePic,
      is_verified: ['Approved', 'Done'].includes(doctor.approvalStatus),
      phone: doctor.phone,
      registration_number: doctor.pmdcNumber,
      bio: doctor.bio || '',
      designation: doctor.designation,
      membershipNumber: doctor.membershipNumber
    }));

    res.json({
      doctors: formattedDoctors,
      total: formattedDoctors.length
    });
  } catch (error) {
    console.error('Error searching doctors:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all doctors (members directory) with pagination
app.get('/api/doctors', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const totalCount = await Doctor.countDocuments({
      isFinalized: true,
      approvalStatus: { $in: ['Approved', 'Done'] }
    });

    const doctors = await Doctor.find({
      isFinalized: true,
      approvalStatus: { $in: ['Approved', 'Done'] }
    })
    .select('-password -bankSlipPic -qualificationDocument')
    .sort({ name: 1 })
    .skip(skip)
    .limit(limit);

    // Format doctors for frontend
    const formattedDoctors = doctors.map(doctor => ({
      id: doctor._id,
      name: doctor.name,
      email: doctor.email,
      specialty: doctor.specialty || doctor.highestQualification || 'Neurologist',
      location: doctor.location || `${doctor.city}, ${doctor.country}` || 'Pakistan',
      hospital: doctor.institution || doctor.instName || 'Medical Institution',
      memberSince: doctor.membershipNumber ? '2018' : new Date(doctor.createdAt).getFullYear().toString(),
      profile_image: doctor.profilePic,
      is_verified: ['Approved', 'Done'].includes(doctor.approvalStatus),
      phone: doctor.phone,
      registration_number: doctor.pmdcNumber,
      bio: doctor.bio || '',
      designation: doctor.designation,
      membershipNumber: doctor.membershipNumber
    }));

    const hasMore = skip + doctors.length < totalCount;

    res.json({
      doctors: formattedDoctors,
      total: totalCount,
      page,
      limit,
      hasMore
    });
  } catch (error) {
    console.error('Error fetching doctors:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Chat API Endpoints

// Get user's conversations list
app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const conversations = await Conversation.find({
      participants: userId
    })
    .populate('participants', 'name profilePic specialty city country')
    .populate('lastMessage.senderId', 'name')
    .sort({ updatedAt: -1 })
    .limit(20);

    const formattedConversations = conversations.map(conv => {
      const otherParticipant = conv.participants.find(p => p._id.toString() !== userId);
      return {
        conversationId: conv._id,
        participant: {
          id: otherParticipant._id,
          name: otherParticipant.name,
          profilePic: otherParticipant.profilePic,
          specialty: otherParticipant.specialty,
          location: `${otherParticipant.city}, ${otherParticipant.country}`
        },
        lastMessage: conv.lastMessage ? {
          content: conv.lastMessage.content,
          senderName: conv.lastMessage.senderId?.name,
          timestamp: conv.lastMessage.timestamp,
          isFromMe: conv.lastMessage.senderId?._id.toString() === userId
        } : null,
        updatedAt: conv.updatedAt
      };
    });

    res.json({ conversations: formattedConversations });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get or create conversation between two users
app.post('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const { recipientId } = req.body;
    const userId = req.user.userId;

    if (!recipientId) {
      return res.status(400).json({ message: 'Recipient ID is required' });
    }

    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      participants: { $all: [userId, recipientId] }
    }).populate('participants', 'name profilePic');

    if (!conversation) {
      // Create new conversation
      conversation = new Conversation({
        participants: [userId, recipientId]
      });
      await conversation.save();
      await conversation.populate('participants', 'name profilePic');
    }

    res.json({ conversation });
  } catch (error) {
    console.error('Error creating/getting conversation:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get messages for a conversation
app.get('/api/conversations/:conversationId/messages', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    // Check if user is participant in conversation
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(req.user.userId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const messages = await Message.find({ conversationId })
      .populate('senderId', 'name profilePic')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const formattedMessages = messages.reverse().map(msg => ({
      id: msg._id,
      senderId: msg.senderId._id,
      senderName: msg.senderId.name,
      content: msg.content,
      timestamp: msg.createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      isMe: msg.senderId._id.toString() === req.user.userId
    }));

    res.json({ messages: formattedMessages });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Send a message
app.post('/api/conversations/:conversationId/messages', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { content } = req.body;
    const senderId = req.user.userId;

    if (!content || !content.trim()) {
      return res.status(400).json({ message: 'Message content is required' });
    }

    // Check if user is participant in conversation
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(senderId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Create message
    const message = new Message({
      conversationId,
      senderId,
      content: content.trim(),
      readBy: [{ doctorId: senderId }]
    });

    await message.save();
    await message.populate('senderId', 'name profilePic');

    // Update conversation's last message
    conversation.lastMessage = {
      content: content.trim(),
      senderId,
      timestamp: new Date()
    };
    conversation.updatedAt = new Date();
    await conversation.save();

    // Get recipient for notification
    const recipientId = conversation.participants.find(id => id.toString() !== senderId.toString());
    const recipient = await Doctor.findById(recipientId).select('name pushToken');
    const sender = await Doctor.findById(senderId).select('name');

    // Send push notification if recipient has push token
    if (recipient && recipient.pushToken) {
      try {
        await fetch('https://exp.host/--/api/v2/push/send', {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Accept-encoding': 'gzip, deflate',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            to: recipient.pushToken,
            title: `${sender.name}`,
            body: content.trim(),
            data: { conversationId, senderId }
          })
        });
        console.log('Push notification sent to:', recipient.name);
      } catch (notifError) {
        console.error('Failed to send notification:', notifError);
      }
    }

    const formattedMessage = {
      id: message._id,
      senderId: message.senderId._id,
      senderName: message.senderId.name,
      content: message.content,
      timestamp: message.createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      isMe: true
    };

    res.status(201).json({ message: formattedMessage });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Socket.IO Authentication Middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error('Authentication error: No token provided'));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const doctor = await Doctor.findById(decoded.id).select('-password');
    if (!doctor) {
      return next(new Error('Authentication error: User not found'));
    }

    socket.userId = doctor._id.toString();
    socket.userName = doctor.name;
    socket.userProfilePic = doctor.profilePic;
    next();
  } catch (error) {
    next(new Error('Authentication error: Invalid token'));
  }
});

// Store active users and their socket connections
const activeUsers = new Map();

// Socket.IO Connection Handler
io.on('connection', (socket) => {
  console.log(`User ${socket.userName} (${socket.userId}) connected`);

  // Add user to active users map
  activeUsers.set(socket.userId, {
    socketId: socket.id,
    name: socket.userName,
    profilePic: socket.userProfilePic,
    lastSeen: new Date()
  });

  // Broadcast user online status to all connections
  socket.broadcast.emit('user_online', {
    userId: socket.userId,
    name: socket.userName,
    profilePic: socket.userProfilePic
  });

  // Handle joining conversation rooms
  socket.on('join_conversation', async (conversationId) => {
    try {
      // Verify user is part of this conversation
      const conversation = await Conversation.findById(conversationId);
      if (!conversation || !conversation.participants.includes(socket.userId)) {
        socket.emit('error', { message: 'Access denied to conversation' });
        return;
      }

      // Join the conversation room
      socket.join(`conv_${conversationId}`);
      console.log(`User ${socket.userName} joined conversation ${conversationId}`);

      // Notify others in the conversation that user is online
      socket.to(`conv_${conversationId}`).emit('user_joined_conversation', {
        userId: socket.userId,
        userName: socket.userName,
        conversationId
      });
    } catch (error) {
      console.error('Error joining conversation:', error);
      socket.emit('error', { message: 'Failed to join conversation' });
    }
  });

  // Handle sending messages
  socket.on('send_message', async (data) => {
    try {
      const { conversationId, content } = data;

      if (!content || !conversationId) {
        socket.emit('error', { message: 'Message content and conversation ID required' });
        return;
      }

      // Verify user is part of this conversation
      const conversation = await Conversation.findById(conversationId);
      if (!conversation || !conversation.participants.includes(socket.userId)) {
        socket.emit('error', { message: 'Access denied to conversation' });
        return;
      }

      // Create and save message
      const message = new Message({
        conversationId,
        senderId: socket.userId,
        content,
        messageType: 'text'
      });

      await message.save();
      await message.populate('senderId', 'name profilePic');

      // Update conversation's last message
      conversation.lastMessage = {
        content: content,
        senderId: socket.userId,
        timestamp: new Date()
      };
      conversation.updatedAt = new Date();
      await conversation.save();

      // Format message for real-time broadcast
      const formattedMessage = {
        id: message._id,
        conversationId: message.conversationId,
        senderId: message.senderId._id,
        senderName: message.senderId.name,
        senderProfilePic: message.senderId.profilePic,
        content: message.content,
        timestamp: message.createdAt.toISOString(),
        createdAt: message.createdAt
      };

      // Broadcast message to all users in the conversation room
      io.to(`conv_${conversationId}`).emit('receive_message', formattedMessage);

      console.log(`Message sent in conversation ${conversationId} by ${socket.userName}`);
    } catch (error) {
      console.error('Error sending message:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Handle typing indicators
  socket.on('typing_start', (data) => {
    const { conversationId } = data;
    socket.to(`conv_${conversationId}`).emit('user_typing', {
      userId: socket.userId,
      userName: socket.userName,
      conversationId,
      isTyping: true
    });
  });

  socket.on('typing_stop', (data) => {
    const { conversationId } = data;
    socket.to(`conv_${conversationId}`).emit('user_typing', {
      userId: socket.userId,
      userName: socket.userName,
      conversationId,
      isTyping: false
    });
  });

  // Handle marking messages as read
  socket.on('mark_messages_read', async (data) => {
    try {
      const { conversationId } = data;

      // Update all unread messages in this conversation to read
      await Message.updateMany(
        {
          conversationId,
          senderId: { $ne: socket.userId },
          readAt: { $exists: false }
        },
        { readAt: new Date() }
      );

      // Broadcast read receipt to other participants
      socket.to(`conv_${conversationId}`).emit('messages_read', {
        conversationId,
        readBy: socket.userId,
        readAt: new Date()
      });
    } catch (error) {
      console.error('Error marking messages as read:', error);
    }
  });

  // Handle leaving conversation
  socket.on('leave_conversation', (conversationId) => {
    socket.leave(`conv_${conversationId}`);
    socket.to(`conv_${conversationId}`).emit('user_left_conversation', {
      userId: socket.userId,
      userName: socket.userName,
      conversationId
    });
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log(`User ${socket.userName} (${socket.userId}) disconnected`);

    // Remove user from active users
    activeUsers.delete(socket.userId);

    // Broadcast user offline status
    socket.broadcast.emit('user_offline', {
      userId: socket.userId,
      lastSeen: new Date()
    });
  });

  // Handle connection errors
  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});

// API endpoint to get online users
app.get('/api/users/online', authenticateToken, (req, res) => {
  const onlineUsers = Array.from(activeUsers.entries()).map(([userId, userData]) => ({
    userId,
    name: userData.name,
    profilePic: userData.profilePic,
    lastSeen: userData.lastSeen
  }));

  res.json({ onlineUsers });
});

// Test route
app.get('/api/test', (req, res) => {
  res.json({ message: 'Test route working!' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Socket.IO server initialized');
  console.log('Available routes:');
  console.log('POST /api/auth/login');
  console.log('GET /api/auth/profile');
  console.log('POST /api/auth/forgot-password');
  console.log('POST /api/auth/verify-reset-code');
  console.log('POST /api/auth/reset-password');
  console.log('POST /api/upload');
  console.log('GET /api/posts');
  console.log('POST /api/posts');
  console.log('POST /api/posts/:postId/like');
  console.log('GET /api/posts/:postId/comments');
  console.log('POST /api/posts/:postId/comments');
  console.log('GET /api/doctors');
  console.log('GET /api/doctors/search');
  console.log('GET /api/conversations');
  console.log('POST /api/conversations');
  console.log('GET /api/conversations/:conversationId/messages');
  console.log('POST /api/conversations/:conversationId/messages');
  console.log('GET /api/news');
  console.log('GET /api/news/:newsId');
  console.log('GET /api/test');
});

module.exports = app;