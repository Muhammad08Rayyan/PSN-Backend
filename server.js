const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { createServer } = require('http');
const { Server } = require('socket.io');
const nodemailer = require('nodemailer');
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

// Email transporter configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
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

// Events Schema (admin-managed, read-only for mobile)
const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: Date, required: true },
  location: { type: String, required: true },
  image_url: { type: String },
  isActive: { type: Boolean, default: true },
  createdBy: { type: String, default: 'Admin' }
}, { timestamps: true });

const Event = mongoose.model('Event', eventSchema, 'events');

// Case Discussion Schema (admin-managed, read-only for mobile)
const caseDiscussionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  uploaded_by: { type: String, required: true },
  resource_url: { type: String }, // Optional image or PDF attachment
  resource_type: { type: String, enum: ['image', 'pdf'], default: null },
  category: { type: String, default: 'General' },
  isActive: { type: Boolean, default: true },
  createdBy: { type: String, default: 'Admin' }
}, { timestamps: true });

const CaseDiscussion = mongoose.model('CaseDiscussion', caseDiscussionSchema, 'casediscussions');

// Jobs Schema for job postings
const jobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  company: { type: String, required: true },
  location: { type: String, required: true },
  type: {
    type: String,
    enum: ['Full-time', 'Part-time', 'Contract', 'Locum'],
    default: 'Full-time'
  },
  salary: { type: String },
  description: { type: String, required: true },
  requirements: [{ type: String }],
  benefits: [{ type: String }],
  experience: { type: String, required: true },
  specialty: { type: String, required: true },
  hospital: { type: String },
  applicants: { type: Number, default: 0 },
  companyLogo: { type: String },
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
  isActive: { type: Boolean, default: true },
  adminVerified: { type: Boolean, default: false },
  expiryDate: { type: Date },
  contactEmail: { type: String },
  contactPhone: { type: String }
}, { timestamps: true });

const Job = mongoose.model('Job', jobSchema, 'jobs');

// Course Schema for course offerings
const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  thumbnail: { type: String }, // URL to course thumbnail image
  instructor: { type: String, required: true },
  duration: { type: String }, // e.g., "4 weeks", "2 hours"
  level: {
    type: String,
    enum: ['Beginner', 'Intermediate', 'Advanced'],
    default: 'Beginner'
  },
  category: { type: String, required: true }, // e.g., "Neurology", "Clinical Skills"
  sections: [{
    title: { type: String, required: true },
    description: { type: String },
    videos: [{
      _id: { type: mongoose.Schema.Types.ObjectId, default: () => new mongoose.Types.ObjectId() },
      title: { type: String, required: true },
      youtubeUrl: { type: String, required: true }, // YouTube video URL
      duration: { type: String }, // e.g., "15:30"
      description: { type: String }
    }]
  }],
  enrolledUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' }],
  maxEnrollments: { type: Number, default: null }, // null means unlimited
  price: { type: Number, default: 0 }, // 0 means free
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
  isActive: { type: Boolean, default: true },
  adminVerified: { type: Boolean, default: false },
  tags: [{ type: String }], // e.g., ["neurosurgery", "pediatric", "diagnosis"]
  prerequisites: [{ type: String }], // Course prerequisites
  learningObjectives: [{ type: String }], // What students will learn
  certificateOffered: { type: Boolean, default: false }
}, { timestamps: true });

const Course = mongoose.model('Course', courseSchema, 'courses');

// Course Enrollment Schema to track user progress
const courseEnrollmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
  courseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
  enrolledAt: { type: Date, default: Date.now },
  completedVideos: [{ type: String }], // Array of video IDs that user has completed
  progress: { type: Number, default: 0 }, // Percentage of course completed (0-100)
  completed: { type: Boolean, default: false },
  completedAt: { type: Date },
  certificateIssued: { type: Boolean, default: false }
}, { timestamps: true });

const CourseEnrollment = mongoose.model('CourseEnrollment', courseEnrollmentSchema, 'courseenrollments');

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
    console.log('Profile picture upload request received');
    console.log('Headers:', req.headers);
    console.log('File:', req.file);
    console.log('Body:', req.body);

    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      console.log('No token provided');
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'psn_secret_key');
    console.log('Token decoded successfully for user:', decoded.userId);

    if (!req.file) {
      console.log('No file received in request');
      return res.status(400).json({ message: 'No image file provided' });
    }

    console.log('File details:', {
      originalname: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size
    });

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

    // Send reset code via email
    const mailOptions = {
      from: process.env.SMTP_USER,
      to: email,
      subject: 'PSN Password Reset Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
            <h2 style="color: #2c5aa0;">Pakistan Society of Neurology</h2>
          </div>
          <div style="padding: 30px 20px;">
            <h3 style="color: #333;">Password Reset Request</h3>
            <p>Dear Dr. ${doctor.name},</p>
            <p>You have requested to reset your password. Please use the following 6-digit verification code:</p>
            <div style="background-color: #f1f3f4; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
              <h1 style="color: #2c5aa0; font-size: 32px; letter-spacing: 8px; margin: 0;">${resetCode}</h1>
            </div>
            <p><strong>This code will expire in 10 minutes.</strong></p>
            <p>If you did not request this password reset, please ignore this email.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
            <p style="color: #666; font-size: 14px;">
              Best regards,<br>
              Pakistan Society of Neurology<br>
              <em>Powered by Helix Pharma</em>
            </p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`Reset code sent to ${email}`);

    res.json({
      message: 'Reset code sent to your email address',
      success: true
    });
  } catch (error) {
    console.error('Email sending error:', error);
    res.status(500).json({ message: 'Failed to send reset code. Please try again.' });
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

// Get events (read-only for mobile users)
app.get('/api/events', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const events = await Event.find({ isActive: true })
      .sort({ date: 1 }) // Sort by date ascending (upcoming first)
      .skip(skip)
      .limit(limit);

    const total = await Event.countDocuments({ isActive: true });

    const formattedEvents = events.map(event => ({
      id: event._id,
      title: event.title,
      description: event.description,
      date: event.date,
      location: event.location,
      image_url: event.image_url,
      timestamp: formatEventDate(event.date),
      createdBy: event.createdBy
    }));

    res.json({
      events: formattedEvents,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    });
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get single event by ID
app.get('/api/events/:eventId', authenticateToken, async (req, res) => {
  try {
    const { eventId } = req.params;

    const event = await Event.findById(eventId);

    if (!event || !event.isActive) {
      return res.status(404).json({ message: 'Event not found' });
    }

    const formattedEvent = {
      id: event._id,
      title: event.title,
      description: event.description,
      date: event.date,
      location: event.location,
      image_url: event.image_url,
      timestamp: formatEventDate(event.date),
      createdBy: event.createdBy
    };

    res.json(formattedEvent);
  } catch (error) {
    console.error('Error fetching event:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Helper function to format event date
function formatEventDate(date) {
  const eventDate = new Date(date);
  const now = new Date();

  // If event is today
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const eventDateOnly = new Date(eventDate.getFullYear(), eventDate.getMonth(), eventDate.getDate());

  if (eventDateOnly.getTime() === today.getTime()) {
    return 'Today';
  }

  // If event is tomorrow
  const tomorrow = new Date(today);
  tomorrow.setDate(today.getDate() + 1);
  if (eventDateOnly.getTime() === tomorrow.getTime()) {
    return 'Tomorrow';
  }

  // If event is within this week
  const diffTime = eventDateOnly.getTime() - today.getTime();
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

  if (diffDays >= 0 && diffDays <= 7) {
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return dayNames[eventDate.getDay()];
  }

  // Otherwise show full date
  return eventDate.toLocaleDateString();
}

// Get case discussions (read-only for mobile users)
app.get('/api/case-discussions', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const discussions = await CaseDiscussion.find({ isActive: true })
      .sort({ createdAt: -1 }) // Sort by newest first
      .skip(skip)
      .limit(limit);

    const total = await CaseDiscussion.countDocuments({ isActive: true });

    const formattedDiscussions = discussions.map(discussion => ({
      id: discussion._id,
      title: discussion.title,
      description: discussion.description,
      uploaded_by: discussion.uploaded_by,
      resource_url: discussion.resource_url,
      resource_type: discussion.resource_type,
      category: discussion.category,
      timestamp: formatTimeAgo(discussion.createdAt),
      createdBy: discussion.createdBy,
      createdAt: discussion.createdAt
    }));

    res.json({
      discussions: formattedDiscussions,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    });
  } catch (error) {
    console.error('Error fetching case discussions:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get single case discussion by ID
app.get('/api/case-discussions/:discussionId', authenticateToken, async (req, res) => {
  try {
    const { discussionId } = req.params;

    const discussion = await CaseDiscussion.findById(discussionId);

    if (!discussion || !discussion.isActive) {
      return res.status(404).json({ message: 'Case discussion not found' });
    }

    const formattedDiscussion = {
      id: discussion._id,
      title: discussion.title,
      description: discussion.description,
      uploaded_by: discussion.uploaded_by,
      resource_url: discussion.resource_url,
      resource_type: discussion.resource_type,
      category: discussion.category,
      timestamp: formatTimeAgo(discussion.createdAt),
      createdBy: discussion.createdBy,
      createdAt: discussion.createdAt
    };

    res.json(formattedDiscussion);
  } catch (error) {
    console.error('Error fetching case discussion:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Case discussion not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Jobs API Endpoints

// Get jobs with pagination and filtering
app.get('/api/jobs', authenticateToken, async (req, res) => {
  try {
    console.log('🔥 JOBS API CALLED!!! Query params:', req.query);
    console.log('🔥 User:', req.user);

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Filter parameters
    const { search, type, specialty, location } = req.query;

    // Build query - only show admin verified jobs to regular users
    let query = { isActive: true, adminVerified: true };

    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { title: { $regex: searchRegex } },
        { company: { $regex: searchRegex } },
        { location: { $regex: searchRegex } },
        { specialty: { $regex: searchRegex } },
        { description: { $regex: searchRegex } }
      ];
    }

    if (type && type !== 'all') {
      query.type = type;
    }

    if (specialty && specialty !== 'all') {
      query.specialty = { $regex: new RegExp(specialty, 'i') };
    }

    if (location) {
      query.location = { $regex: new RegExp(location, 'i') };
    }

    const jobs = await Job.find(query)
      .populate('postedBy', 'name email specialty')
      .sort({ createdAt: -1 }) // Newest first
      .skip(skip)
      .limit(limit);

    const total = await Job.countDocuments(query);

    const formattedJobs = jobs.map(job => ({
      id: job._id,
      title: job.title,
      company: job.company,
      location: job.location,
      type: job.type,
      salary: job.salary,
      description: job.description,
      requirements: job.requirements,
      benefits: job.benefits,
      experience: job.experience,
      specialty: job.specialty,
      hospital: job.hospital,
      applicants: job.applicants,
      companyLogo: job.companyLogo,
      postedDate: job.createdAt,
      contactEmail: job.contactEmail,
      contactPhone: job.contactPhone,
      postedBy: job.postedBy ? {
        id: job.postedBy._id,
        name: job.postedBy.name,
        email: job.postedBy.email,
        specialty: job.postedBy.specialty
      } : null,
      timestamp: formatTimeAgo(job.createdAt)
    }));

    res.json({
      jobs: formattedJobs,
      posts: formattedJobs, // TEMP: Add this for testing
      data: formattedJobs,  // TEMP: Add this for testing
      total,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    });
  } catch (error) {
    console.error('Error fetching jobs:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get single job by ID
app.get('/api/jobs/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    const job = await Job.findById(jobId)
      .populate('postedBy', 'name email specialty profilePic');

    if (!job || !job.isActive) {
      return res.status(404).json({ message: 'Job not found' });
    }

    const formattedJob = {
      id: job._id,
      title: job.title,
      company: job.company,
      location: job.location,
      type: job.type,
      salary: job.salary,
      description: job.description,
      requirements: job.requirements,
      benefits: job.benefits,
      experience: job.experience,
      specialty: job.specialty,
      hospital: job.hospital,
      urgent: job.urgent,
      isEasyApply: job.isEasyApply,
      applicants: job.applicants,
      companyLogo: job.companyLogo,
      postedDate: job.createdAt,
      contactEmail: job.contactEmail,
      contactPhone: job.contactPhone,
      postedBy: job.postedBy ? {
        id: job.postedBy._id,
        name: job.postedBy.name,
        email: job.postedBy.email,
        specialty: job.postedBy.specialty,
        profilePic: job.postedBy.profilePic
      } : null,
      timestamp: formatTimeAgo(job.createdAt)
    };

    res.json(formattedJob);
  } catch (error) {
    console.error('Error fetching job:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Job not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Create new job posting
app.post('/api/jobs', authenticateToken, async (req, res) => {
  try {
    const {
      title,
      company,
      location,
      type,
      salary,
      description,
      requirements,
      benefits,
      experience,
      specialty,
      hospital,
      urgent,
      isEasyApply,
      contactEmail,
      contactPhone,
      expiryDate
    } = req.body;

    // Validate required fields
    if (!title || !company || !location || !description || !experience || !specialty) {
      return res.status(400).json({
        message: 'Missing required fields: title, company, location, description, experience, specialty'
      });
    }

    const job = new Job({
      title,
      company,
      location,
      type: type || 'Full-time',
      salary,
      description,
      requirements: Array.isArray(requirements) ? requirements : [],
      benefits: Array.isArray(benefits) ? benefits : [],
      experience,
      specialty,
      hospital,
      urgent: urgent || false,
      isEasyApply: isEasyApply || false,
      contactEmail,
      contactPhone,
      postedBy: req.user.userId,
      expiryDate: expiryDate ? new Date(expiryDate) : null
    });

    await job.save();
    await job.populate('postedBy', 'name email specialty');

    const formattedJob = {
      id: job._id,
      title: job.title,
      company: job.company,
      location: job.location,
      type: job.type,
      salary: job.salary,
      description: job.description,
      requirements: job.requirements,
      benefits: job.benefits,
      experience: job.experience,
      specialty: job.specialty,
      hospital: job.hospital,
      urgent: job.urgent,
      isEasyApply: job.isEasyApply,
      applicants: job.applicants,
      companyLogo: job.companyLogo,
      postedDate: job.createdAt,
      contactEmail: job.contactEmail,
      contactPhone: job.contactPhone,
      postedBy: {
        id: job.postedBy._id,
        name: job.postedBy.name,
        email: job.postedBy.email,
        specialty: job.postedBy.specialty
      },
      timestamp: formatTimeAgo(job.createdAt)
    };

    res.status(201).json(formattedJob);
  } catch (error) {
    console.error('Error creating job:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update job posting
app.put('/api/jobs/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const updateData = req.body;

    const job = await Job.findById(jobId);

    if (!job) {
      return res.status(404).json({ message: 'Job not found' });
    }

    // Check if user is the owner of the job or is admin
    if (job.postedBy.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const updatedJob = await Job.findByIdAndUpdate(
      jobId,
      { ...updateData, updatedAt: new Date() },
      { new: true }
    ).populate('postedBy', 'name email specialty');

    const formattedJob = {
      id: updatedJob._id,
      title: updatedJob.title,
      company: updatedJob.company,
      location: updatedJob.location,
      type: updatedJob.type,
      salary: updatedJob.salary,
      description: updatedJob.description,
      requirements: updatedJob.requirements,
      benefits: updatedJob.benefits,
      experience: updatedJob.experience,
      specialty: updatedJob.specialty,
      hospital: updatedJob.hospital,
      urgent: updatedJob.urgent,
      isEasyApply: updatedJob.isEasyApply,
      applicants: updatedJob.applicants,
      companyLogo: updatedJob.companyLogo,
      postedDate: updatedJob.createdAt,
      contactEmail: updatedJob.contactEmail,
      contactPhone: updatedJob.contactPhone,
      postedBy: {
        id: updatedJob.postedBy._id,
        name: updatedJob.postedBy.name,
        email: updatedJob.postedBy.email,
        specialty: updatedJob.postedBy.specialty
      },
      timestamp: formatTimeAgo(updatedJob.createdAt)
    };

    res.json(formattedJob);
  } catch (error) {
    console.error('Error updating job:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Job not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete job posting
app.delete('/api/jobs/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    const job = await Job.findById(jobId);

    if (!job) {
      return res.status(404).json({ message: 'Job not found' });
    }

    // Check if user is the owner of the job or is admin
    if (job.postedBy.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Soft delete by setting isActive to false
    await Job.findByIdAndUpdate(jobId, { isActive: false });

    res.json({ message: 'Job deleted successfully' });
  } catch (error) {
    console.error('Error deleting job:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Job not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Increment applicant count
app.post('/api/jobs/:jobId/apply', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    const job = await Job.findById(jobId);

    if (!job || !job.isActive) {
      return res.status(404).json({ message: 'Job not found' });
    }

    // Increment applicant count
    job.applicants = (job.applicants || 0) + 1;
    await job.save();

    res.json({
      message: 'Application submitted successfully',
      applicants: job.applicants
    });
  } catch (error) {
    console.error('Error applying to job:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Job not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin approve job endpoint
app.put('/api/admin/jobs/:jobId/approve', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    // TODO: Add admin role check here
    // For now, any authenticated user can approve (you'll need to add admin role to user schema)

    const job = await Job.findById(jobId);
    if (!job) {
      return res.status(404).json({ message: 'Job not found' });
    }

    job.adminVerified = true;
    await job.save();

    res.json({
      message: 'Job approved successfully',
      job: {
        id: job._id,
        title: job.title,
        adminVerified: job.adminVerified
      }
    });
  } catch (error) {
    console.error('Error approving job:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Job not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin get pending jobs endpoint
app.get('/api/admin/jobs/pending', authenticateToken, async (req, res) => {
  try {
    // TODO: Add admin role check here

    const pendingJobs = await Job.find({
      isActive: true,
      adminVerified: false
    })
    .populate('postedBy', 'name email specialty')
    .sort({ createdAt: -1 });

    const formattedJobs = pendingJobs.map(job => ({
      id: job._id,
      title: job.title,
      company: job.company,
      location: job.location,
      type: job.type,
      salary: job.salary,
      description: job.description,
      requirements: job.requirements,
      benefits: job.benefits,
      experience: job.experience,
      specialty: job.specialty,
      hospital: job.hospital,
      applicants: job.applicants,
      postedBy: job.postedBy,
      adminVerified: job.adminVerified,
      createdAt: job.createdAt,
      contactEmail: job.contactEmail,
      contactPhone: job.contactPhone
    }));

    res.json({
      jobs: formattedJobs,
      total: formattedJobs.length
    });
  } catch (error) {
    console.error('Error fetching pending jobs:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Course endpoints

// Get all courses (only admin verified ones for regular users)
app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Filter parameters
    const { search, category, level } = req.query;

    // Build query - only show admin verified courses to regular users
    let query = { isActive: true, adminVerified: true };

    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { title: { $regex: searchRegex } },
        { description: { $regex: searchRegex } },
        { instructor: { $regex: searchRegex } },
        { category: { $regex: searchRegex } },
        { tags: { $in: [searchRegex] } }
      ];
    }

    if (category && category !== 'all') {
      query.category = { $regex: new RegExp(category, 'i') };
    }

    if (level && level !== 'all') {
      query.level = level;
    }

    const courses = await Course.find(query)
      .populate('postedBy', 'name email specialty')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Course.countDocuments(query);

    const formattedCourses = courses.map(course => ({
      id: course._id,
      title: course.title,
      description: course.description,
      thumbnail: course.thumbnail,
      instructor: course.instructor,
      duration: course.duration,
      level: course.level,
      category: course.category,
      sectionsCount: course.sections.length,
      enrolledCount: course.enrolledUsers.length,
      maxEnrollments: course.maxEnrollments,
      price: course.price,
      tags: course.tags,
      certificateOffered: course.certificateOffered,
      createdAt: course.createdAt,
      postedBy: course.postedBy ? {
        id: course.postedBy._id,
        name: course.postedBy.name,
        email: course.postedBy.email,
        specialty: course.postedBy.specialty
      } : null
    }));

    res.json({
      courses: formattedCourses,
      total,
      page,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Error fetching courses:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get course by ID
app.get('/api/courses/:courseId', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const userId = req.user.userId;

    const course = await Course.findById(courseId)
      .populate('postedBy', 'name email specialty');

    if (!course || !course.isActive || !course.adminVerified) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Check if user is enrolled
    const enrollment = await CourseEnrollment.findOne({
      userId,
      courseId
    });

    const formattedCourse = {
      id: course._id,
      title: course.title,
      description: course.description,
      thumbnail: course.thumbnail,
      instructor: course.instructor,
      duration: course.duration,
      level: course.level,
      category: course.category,
      sections: course.sections,
      enrolledCount: course.enrolledUsers.length,
      maxEnrollments: course.maxEnrollments,
      price: course.price,
      tags: course.tags,
      prerequisites: course.prerequisites,
      learningObjectives: course.learningObjectives,
      certificateOffered: course.certificateOffered,
      createdAt: course.createdAt,
      postedBy: course.postedBy ? {
        id: course.postedBy._id,
        name: course.postedBy.name,
        email: course.postedBy.email,
        specialty: course.postedBy.specialty
      } : null,
      isEnrolled: !!enrollment,
      enrollment: enrollment ? {
        progress: enrollment.progress,
        completedVideos: enrollment.completedVideos,
        completed: enrollment.completed,
        enrolledAt: enrollment.enrolledAt
      } : null
    };

    res.json(formattedCourse);
  } catch (error) {
    console.error('Error fetching course:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Course not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Create new course
app.post('/api/courses', authenticateToken, upload.single('thumbnail'), async (req, res) => {
  try {
    const {
      title,
      description,
      instructor,
      duration,
      level,
      category,
      sections,
      maxEnrollments,
      price,
      tags,
      prerequisites,
      learningObjectives,
      certificateOffered
    } = req.body;

    // Parse JSON fields if they're strings
    const parsedSections = typeof sections === 'string' ? JSON.parse(sections) : sections;
    const parsedTags = typeof tags === 'string' ? JSON.parse(tags) : tags;
    const parsedPrerequisites = typeof prerequisites === 'string' ? JSON.parse(prerequisites) : prerequisites;
    const parsedLearningObjectives = typeof learningObjectives === 'string' ? JSON.parse(learningObjectives) : learningObjectives;

    let thumbnailUrl = null;

    // Upload thumbnail to Cloudinary if provided
    if (req.file) {
      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: 'course_thumbnails',
            resource_type: 'image'
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(req.file.buffer);
      });
      thumbnailUrl = result.secure_url;
    }

    const newCourse = new Course({
      title,
      description,
      thumbnail: thumbnailUrl,
      instructor,
      duration,
      level: level || 'Beginner',
      category,
      sections: parsedSections || [],
      maxEnrollments: maxEnrollments ? parseInt(maxEnrollments) : null,
      price: price ? parseFloat(price) : 0,
      tags: parsedTags || [],
      prerequisites: parsedPrerequisites || [],
      learningObjectives: parsedLearningObjectives || [],
      certificateOffered: certificateOffered === 'true',
      postedBy: req.user.userId,
      adminVerified: false // Requires admin approval
    });

    await newCourse.save();

    res.status(201).json({
      message: 'Course created successfully! It will be visible once approved by admin.',
      course: {
        id: newCourse._id,
        title: newCourse.title,
        adminVerified: newCourse.adminVerified
      }
    });
  } catch (error) {
    console.error('Error creating course:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Enroll in course
app.post('/api/courses/:courseId/enroll', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const userId = req.user.userId;

    const course = await Course.findById(courseId);
    if (!course || !course.isActive || !course.adminVerified) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Check if already enrolled
    const existingEnrollment = await CourseEnrollment.findOne({
      userId,
      courseId
    });

    if (existingEnrollment) {
      return res.status(400).json({ message: 'Already enrolled in this course' });
    }

    // Check enrollment limit
    if (course.maxEnrollments && course.enrolledUsers.length >= course.maxEnrollments) {
      return res.status(400).json({ message: 'Course enrollment is full' });
    }

    // Create enrollment
    const enrollment = new CourseEnrollment({
      userId,
      courseId
    });

    await enrollment.save();
    console.log('Created enrollment:', enrollment);

    // Add user to course's enrolled users
    course.enrolledUsers.push(userId);
    await course.save();

    res.json({
      message: 'Successfully enrolled in course',
      enrollment: {
        id: enrollment._id,
        progress: enrollment.progress,
        enrolledAt: enrollment.enrolledAt
      }
    });
  } catch (error) {
    console.error('Error enrolling in course:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Course not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's enrolled courses
app.get('/api/my-courses', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const enrollments = await CourseEnrollment.find({ userId })
      .populate({
        path: 'courseId',
        populate: {
          path: 'postedBy',
          select: 'name email specialty'
        }
      })
      .sort({ enrolledAt: -1 });

    const enrolledCourses = enrollments
      .filter(enrollment => enrollment.courseId && enrollment.courseId.isActive)
      .map(enrollment => ({
        id: enrollment.courseId._id,
        title: enrollment.courseId.title,
        description: enrollment.courseId.description,
        thumbnail: enrollment.courseId.thumbnail,
        instructor: enrollment.courseId.instructor,
        level: enrollment.courseId.level,
        category: enrollment.courseId.category,
        progress: enrollment.progress,
        completed: enrollment.completed,
        enrolledAt: enrollment.enrolledAt,
        completedAt: enrollment.completedAt,
        certificateOffered: enrollment.courseId.certificateOffered,
        certificateIssued: enrollment.certificateIssued
      }));

    res.json({
      courses: enrolledCourses,
      total: enrolledCourses.length
    });
  } catch (error) {
    console.error('Error fetching enrolled courses:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin approve course endpoint
app.put('/api/admin/courses/:courseId/approve', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;

    // TODO: Add admin role check here

    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    course.adminVerified = true;
    await course.save();

    res.json({
      message: 'Course approved successfully',
      course: {
        id: course._id,
        title: course.title,
        adminVerified: course.adminVerified
      }
    });
  } catch (error) {
    console.error('Error approving course:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Course not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin get pending courses endpoint
app.get('/api/admin/courses/pending', authenticateToken, async (req, res) => {
  try {
    // TODO: Add admin role check here

    const pendingCourses = await Course.find({
      isActive: true,
      adminVerified: false
    })
    .populate('postedBy', 'name email specialty')
    .sort({ createdAt: -1 });

    const formattedCourses = pendingCourses.map(course => ({
      id: course._id,
      title: course.title,
      description: course.description,
      thumbnail: course.thumbnail,
      instructor: course.instructor,
      category: course.category,
      level: course.level,
      sectionsCount: course.sections.length,
      postedBy: course.postedBy,
      adminVerified: course.adminVerified,
      createdAt: course.createdAt
    }));

    res.json({
      courses: formattedCourses,
      total: formattedCourses.length
    });
  } catch (error) {
    console.error('Error fetching pending courses:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Complete video endpoint
app.post('/api/courses/:courseId/complete-video', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { videoId } = req.body;
    const userId = req.user.id;

    console.log('Complete video request:', { courseId, videoId, userId });

    // Find the enrollment
    let enrollment = await CourseEnrollment.findOne({
      courseId: courseId,
      userId: userId
    });

    console.log('Found enrollment:', enrollment);

    if (!enrollment) {
      console.log('No enrollment found for user:', userId, 'course:', courseId);
      return res.status(404).json({ message: 'Enrollment not found' });
    }

    // Add video to completed videos if not already completed
    if (!enrollment.completedVideos.includes(videoId)) {
      enrollment.completedVideos.push(videoId);
    }

    // Get the course to calculate progress
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Calculate total videos in the course
    const totalVideos = course.sections.reduce((total, section) => total + section.videos.length, 0);

    // Update progress
    enrollment.progress = (enrollment.completedVideos.length / totalVideos) * 100;

    // Mark as completed if all videos are done
    if (enrollment.completedVideos.length === totalVideos) {
      enrollment.completed = true;
    }

    await enrollment.save();

    res.json({
      message: 'Video marked as completed',
      progress: enrollment.progress,
      completedVideos: enrollment.completedVideos,
      completed: enrollment.completed
    });
  } catch (error) {
    console.error('Error completing video:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Course not found' });
    }
    res.status(500).json({ message: 'Server error' });
  }
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
  console.log('GET /api/events');
  console.log('GET /api/events/:eventId');
  console.log('GET /api/case-discussions');
  console.log('GET /api/case-discussions/:discussionId');
  console.log('GET /api/jobs');
  console.log('GET /api/jobs/:jobId');
  console.log('POST /api/jobs');
  console.log('PUT /api/jobs/:jobId');
  console.log('DELETE /api/jobs/:jobId');
  console.log('POST /api/jobs/:jobId/apply');
  console.log('GET /api/test');
});

module.exports = app;