/*
 * server.js
 * Optimized Node.js/Express backend for User Profile Keeper.
 * Features include:
 *  - User Registration with OTP email verification
 *  - OTP Verification
 *  - User Login with JWT
 *  - Forgot/Reset Password
 *  - Admin Registration & Login with:
 *      * Admin registration request disabled for already logged-in admins.
 *      * The "set password" step remains hidden until the owner approves the request.
 *      * Maximum of 10 admin accounts.
 *      * Notifying all admins when new registration requests arrive.
 *  - Admin endpoints to view, delete, and block users
 *  - Serving static frontend files (from ../frontend)
 */
/* */
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Sequelize, DataTypes, Op } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');

// Load environment variables
const {
  POSTGRES_HOST,
  POSTGRES_DB,
  POSTGRES_USER,
  POSTGRES_PASSWORD,
  JWT_SECRET,
  EMAIL_SERVICE,      // If using a service (like 'gmail')
  EMAIL_HOST,         // Alternatively, use a full SMTP configuration
  EMAIL_PORT,
  EMAIL_SECURE,
  EMAIL_USER,
  EMAIL_PASS,
  EMAIL_FROM,
  PORT
} = process.env;

const port = PORT || 5000;

// Initialize Express app and middleware
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ------------------------------
// Setup Sequelize Connection
// ------------------------------
const sequelize = new Sequelize(POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, {
  host: POSTGRES_HOST,
  dialect: 'postgres',
  logging: false
});

const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log('PostgreSQL connection established.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
    process.exit(1);
  }
};
connectDB();

// ------------------------------
// Define Models
// ------------------------------

// User Model (with isBlocked flag)
const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  contact: { type: DataTypes.STRING, allowNull: false },
  dob: { type: DataTypes.DATEONLY, allowNull: false },
  city: { type: DataTypes.STRING, allowNull: false },
  isVerified: { type: DataTypes.BOOLEAN, defaultValue: false },
  isBlocked: { type: DataTypes.BOOLEAN, defaultValue: false },
  resetPasswordToken: { type: DataTypes.STRING },
  resetPasswordExpires: { type: DataTypes.DATE }
}, {
  hooks: {
    beforeCreate: async (user) => {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(user.password, salt);
    },
    beforeUpdate: async (user) => {
      if (user.changed('password')) {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
      }
    }
  }
});
User.prototype.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Admin Model (with isApproved flag)
const Admin = sequelize.define('Admin', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  isVerified: { type: DataTypes.BOOLEAN, defaultValue: false },
  isApproved: { type: DataTypes.BOOLEAN, defaultValue: false }
}, {
  hooks: {
    beforeCreate: async (admin) => {
      const salt = await bcrypt.genSalt(10);
      admin.password = await bcrypt.hash(admin.password, salt);
    },
    beforeUpdate: async (admin) => {
      if (admin.changed('password')) {
        const salt = await bcrypt.genSalt(10);
        admin.password = await bcrypt.hash(admin.password, salt);
      }
    }
  }
});
Admin.prototype.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// OTP Model (for email verification)
const OTP = sequelize.define('OTP', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  email: { type: DataTypes.STRING, allowNull: false },
  otp: { type: DataTypes.STRING, allowNull: false }
});

// AdminRequest Model (for pending admin registration requests)
const AdminRequest = sequelize.define('AdminRequest', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  status: { type: DataTypes.ENUM('pending', 'approved', 'declined'), defaultValue: 'pending' }
});

// ------------------------------
// Synchronize Models with Database
// ------------------------------
sequelize.sync({ alter: true })
  .then(() => console.log('Sequelize models synchronized.'))
  .catch(err => console.error('Sequelize synchronization error:', err));

// ------------------------------
// Configure Nodemailer Transporter
// ------------------------------

// Use either a service-based configuration or a custom SMTP configuration
let transporterConfig = {};
if (EMAIL_SERVICE) {
  transporterConfig = {
    service: EMAIL_SERVICE,
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS
    }
  };
} else {
  transporterConfig = {
    host: EMAIL_HOST,
    port: Number(EMAIL_PORT),
    secure: EMAIL_SECURE === 'true',
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS
    }
  };
}
const transporter = nodemailer.createTransport(transporterConfig);

// ------------------------------
// Utility Functions and Middleware
// ------------------------------
const generateToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Middleware to verify JWT and add user/admin info to req.user
const authMiddleware = (roleRequired) => (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authorized, token missing.' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    if (roleRequired && decoded.role !== roleRequired) {
      return res.status(401).json({ error: 'Not authorized for this action.' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ error: 'Not authorized, token invalid.' });
  }
};

// Notify all admins (if any) about specific events
const notifyAllAdmins = async (subject, htmlContent) => {
  try {
    const admins = await Admin.findAll();
    const adminEmails = admins.map(a => a.email);
    if (adminEmails.length > 0) {
      await transporter.sendMail({
        from: EMAIL_FROM,
        to: adminEmails,
        subject,
        html: htmlContent
      });
    }
  } catch (err) {
    console.error('Error notifying admins:', err);
  }
};

// ------------------------------
// Routes
// ------------------------------

// USER ROUTES

// 1. User Registration (with OTP)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, contact, dob, city } = req.body;
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      if (existingUser.isBlocked) {
        return res.status(400).json({ error: 'This email is blocked. Registration is not allowed.' });
      }
      return res.status(400).json({ error: 'User already exists.' });
    }
    const user = await User.create({ name, email, password, contact, dob, city });
    const otpCode = generateOTP();
    await OTP.create({ email, otp: otpCode });
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: email,
      subject: 'Email Verification - OTP',
      html: `<p>Hello ${name},</p>
             <p>Your OTP for email verification is: <strong>${otpCode}</strong></p>
             <p>This OTP is valid for 5 minutes.</p>`
    });
    res.status(201).json({ message: 'Registration successful. Please verify your email using the OTP sent.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// 2. OTP Verification
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const otpRecord = await OTP.findOne({ where: { email, otp } });
    if (!otpRecord) return res.status(400).json({ error: 'Invalid or expired OTP.' });
    await User.update({ isVerified: true }, { where: { email } });
    await OTP.destroy({ where: { email, otp } });
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: email,
      subject: 'Email Verified',
      html: `<p>Your email has been verified successfully!</p>`
    });
    res.status(200).json({ message: 'Email verified successfully.' });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Server error during OTP verification.' });
  }
});

// 3. User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ error: 'Invalid credentials.' });
    if (!user.isVerified) return res.status(400).json({ error: 'Email not verified.' });
    if (user.isBlocked) return res.status(400).json({ error: 'This account is blocked.' });
    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials.' });
    const token = generateToken({ id: user.id, email: user.email });
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: email,
      subject: 'Login Notification',
      html: `<p>You have successfully logged in.</p>`
    });
    res.status(200).json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// 4. Forgot Password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ error: 'User not found.' });
    const resetToken = generateOTP();
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour expiration
    await user.update({ resetPasswordToken: resetToken, resetPasswordExpires: resetExpires });
    const resetUrl = `http://localhost:${port}/api/auth/reset-password?token=${resetToken}&email=${email}`;
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: email,
      subject: 'Password Reset',
      html: `<p>You requested a password reset.</p>
             <p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.</p>`
    });
    res.status(200).json({ message: 'Password reset instructions sent to your email.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error during forgot password.' });
  }
});

// 5. Reset Password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    const user = await User.findOne({
      where: { email, resetPasswordToken: token, resetPasswordExpires: { [Op.gt]: new Date() } }
    });
    if (!user) return res.status(400).json({ error: 'Invalid or expired token.' });
    await user.update({ password: newPassword, resetPasswordToken: null, resetPasswordExpires: null });
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: email,
      subject: 'Password Reset Successful',
      html: `<p>Your password has been reset successfully.</p>`
    });
    res.status(200).json({ message: 'Password has been reset successfully.' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error during password reset.' });
  }
});

// ADMIN ROUTES

// 6. Admin Registration Request
// This endpoint now rejects requests if the caller is already logged in as an admin.
app.post('/api/auth/admin/request-registration', async (req, res) => {
  try {
    // If a token is provided and it belongs to an admin, disallow further registration requests.
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role === 'admin') {
        return res.status(400).json({ error: 'Already logged in as admin. You cannot request a new registration.' });
      }
    }
    const { name, email } = req.body;
    // Check if an AdminRequest already exists
    const existingRequest = await AdminRequest.findOne({ where: { email } });
    if (existingRequest) {
      return res.status(400).json({ error: 'A registration request for this email is already pending or processed.' });
    }
    // Check if an admin already exists with the email
    const existingAdmin = await Admin.findOne({ where: { email } });
    if (existingAdmin) {
      return res.status(400).json({ error: 'An admin with this email already exists.' });
    }
    const request = await AdminRequest.create({ name, email });
    // Notify the owner by email (using a fixed owner email) and also notify all current admins.
    const approveLink = `http://localhost:${port}/api/auth/admin/approve?requestId=${request.id}`;
    const declineLink = `http://localhost:${port}/api/auth/admin/decline?requestId=${request.id}`;
    const ownerEmail = 'ashishjaiswal0701@gmail.com'; // Owner email
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: ownerEmail,
      subject: 'New Admin Registration Request',
      html: `<p>A new admin registration request has been received.</p>
             <p><strong>Name:</strong> ${name}</p>
             <p><strong>Email:</strong> ${email}</p>
             <p>
               <a href="${approveLink}">Approve</a> | <a href="${declineLink}">Decline</a>
             </p>`
    });
    // Notify all existing admins of the new registration request.
    await notifyAllAdmins('New Admin Registration Request',
      `<p>New admin registration request received from ${name} (${email}).</p>`);
    res.status(200).json({ message: 'Registration request sent for approval.' });
  } catch (error) {
    console.error('Admin request error:', error);
    res.status(500).json({ error: 'Server error during admin registration request.' });
  }
});

// 7. Admin Request Approval (Owner action)
app.get('/api/auth/admin/approve', async (req, res) => {
  try {
    const { requestId } = req.query;
    const request = await AdminRequest.findOne({ where: { id: requestId } });
    if (!request) return res.status(404).send('Request not found.');
    await request.update({ status: 'approved' });
    // Notify the requester by email that the registration is approved.
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: request.email,
      subject: 'Admin Registration Approved',
      html: `<p>Hello ${request.name},</p>
             <p>Your admin registration request has been approved.</p>
             <p>Please proceed to complete your registration by setting your password.</p>`
    });
    res.send('Admin registration approved.');
  } catch (error) {
    console.error('Admin approval error:', error);
    res.status(500).send('Server error during admin approval.');
  }
});

// 8. Admin Request Decline (Owner action)
app.get('/api/auth/admin/decline', async (req, res) => {
  try {
    const { requestId } = req.query;
    const request = await AdminRequest.findOne({ where: { id: requestId } });
    if (!request) return res.status(404).send('Request not found.');
    await request.update({ status: 'declined' });
    // Optionally notify the requester.
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: request.email,
      subject: 'Admin Registration Declined',
      html: `<p>Hello ${request.name},</p>
             <p>Your admin registration request has been declined.</p>`
    });
    res.send('Admin registration declined.');
  } catch (error) {
    console.error('Admin decline error:', error);
    res.status(500).send('Server error during admin decline.');
  }
});

// 9. Admin Registration (Complete)
// This endpoint completes registration only if the corresponding AdminRequest is approved.
app.post('/api/auth/admin/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    // Check for an approved AdminRequest
    const adminRequest = await AdminRequest.findOne({ where: { email, status: 'approved' } });
    if (!adminRequest) {
      return res.status(400).json({ error: 'Your registration request has not been approved yet.' });
    }
    // Enforce maximum of 10 admins
    const adminCount = await Admin.count();
    if (adminCount >= 10) return res.status(400).json({ error: 'Admin registration limit reached.' });
    // Create the admin account.
    const admin = await Admin.create({ name, email, password });
    await admin.update({ isVerified: true, isApproved: true });
    // Remove the admin request after successful registration.
    await adminRequest.destroy();
    // Notify all admins of a new registration.
    await notifyAllAdmins('New Admin Registered',
      `<p>New admin registered with email: ${email}</p>`);
    res.status(201).json({ message: 'Admin registration successful.' });
  } catch (error) {
    console.error('Admin registration error:', error);
    res.status(500).json({ error: 'Server error during admin registration.' });
  }
});

// 10. Admin Login
app.post('/api/auth/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ where: { email } });
    if (!admin) return res.status(400).json({ error: 'Invalid credentials.' });
    if (!admin.isVerified) return res.status(400).json({ error: 'Admin email not verified.' });
    if (!admin.isApproved) return res.status(400).json({ error: 'Your registration request is not approved yet.' });
    const isMatch = await admin.comparePassword(password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials.' });
    const token = generateToken({ id: admin.id, email: admin.email, role: 'admin' });
    res.status(200).json({ token, admin });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Server error during admin login.' });
  }
});

// 11. Protected: Get User Profile (for regular users)
app.get('/api/auth/profile', authMiddleware(), async (req, res) => {
  try {
    // Ensure that this is not an admin token
    if (req.user.role && req.user.role === 'admin')
      return res.status(401).json({ error: 'Not authorized as user.' });
    const user = await User.findOne({ where: { id: req.user.id } });
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.status(200).json({ user });
  } catch (error) {
    console.error('User profile error:', error);
    res.status(500).json({ error: 'Server error fetching profile.' });
  }
});

// 12. Protected: Get Admin Profile
app.get('/api/auth/admin/profile', authMiddleware('admin'), async (req, res) => {
  try {
    const admin = await Admin.findOne({ where: { id: req.user.id } });
    if (!admin) return res.status(404).json({ error: 'Admin not found.' });
    res.status(200).json({ admin });
  } catch (error) {
    console.error('Admin profile error:', error);
    res.status(500).json({ error: 'Server error fetching admin profile.' });
  }
});

// 13. Protected: Get All Users (Admin)
app.get('/api/auth/admin/users', authMiddleware('admin'), async (req, res) => {
  try {
    const users = await User.findAll();
    res.status(200).json({ users });
  } catch (error) {
    console.error('Admin get users error:', error);
    res.status(500).json({ error: 'Server error fetching users.' });
  }
});

// 14. Protected: Delete User (Admin)
app.post('/api/auth/admin/delete-user', authMiddleware('admin'), async (req, res) => {
  try {
    const { userId, userEmail, message } = req.body;
    const deletion = await User.destroy({ where: { id: userId } });
    if (!deletion) return res.status(400).json({ error: 'User deletion failed.' });
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: userEmail,
      subject: 'Account Deletion Notification',
      html: `<p>Your account has been deleted.</p><p>Message: ${message}</p>`
    });
    await notifyAllAdmins('User Deleted', `<p>User with email ${userEmail} has been deleted. Message: ${message}</p>`);
    res.status(200).json({ message: 'User deleted successfully.' });
  } catch (error) {
    console.error('Admin delete user error:', error);
    res.status(500).json({ error: 'Server error during user deletion.' });
  }
});

// 15. Protected: Block User (Admin)
app.post('/api/auth/admin/block-user', authMiddleware('admin'), async (req, res) => {
  try {
    const { userId, userEmail, message } = req.body;
    const user = await User.findOne({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: 'User not found.' });
    await user.update({ isBlocked: true });
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: userEmail,
      subject: 'Account Block Notification',
      html: `<p>Your account has been blocked.</p><p>Message: ${message}</p>`
    });
    await notifyAllAdmins('User Blocked', `<p>User with email ${userEmail} has been blocked. Message: ${message}</p>`);
    res.status(200).json({ message: 'User blocked successfully.' });
  } catch (error) {
    console.error('Admin block user error:', error);
    res.status(500).json({ error: 'Server error during user blocking.' });
  }
});

// ------------------------------
// Serve Frontend
// ------------------------------
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ------------------------------
// Root Route & Start Server
// ------------------------------
app.get('/', (req, res) => res.send('User Profile Keeper API is running.'));
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
