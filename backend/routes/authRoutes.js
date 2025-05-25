// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const { Op } = require('sequelize');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 5000}`;

const { User, OTP, AdminRequest, Admin } = require('../models');
const { generateToken } = require('../utils/tokenUtils');
const { generateOTP } = require('../utils/otpUtils');
const { sendEmail, notifyAllAdmins } = require('../utils/emailNotifications');

// 1. User Registration (with OTP)
router.post('/register', async (req, res) => {
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
    await sendEmail(email, 'Email Verification - OTP', `<p>Hello ${name},</p>
      <p>Your OTP for email verification is: <strong>${otpCode}</strong></p>
      <p>This OTP is valid for 5 minutes.</p>`);
    res.status(201).json({ message: 'Registration successful. Please verify your email using the OTP sent.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// 2. OTP Verification
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const otpRecord = await OTP.findOne({ where: { email, otp } });
    if (!otpRecord) return res.status(400).json({ error: 'Invalid or expired OTP.' });
    await User.update({ isVerified: true }, { where: { email } });
    await OTP.destroy({ where: { email, otp } });
    await sendEmail(email, 'Email Verified', `<p>Your email has been verified successfully!</p>`);
    res.status(200).json({ message: 'Email verified successfully.' });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Server error during OTP verification.' });
  }
});

// 3. User Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ error: 'Invalid credentials.' });
    if (!user.isVerified) return res.status(400).json({ error: 'Email not verified.' });
    if (user.isBlocked) return res.status(400).json({ error: 'This account is blocked.' });
    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials.' });
    const token = generateToken({ id: user.id, email: user.email });
    await sendEmail(email, 'Login Notification', `<p>You have successfully logged in.</p>`);
    res.status(200).json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// 4. Forgot Password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ error: 'User not found.' });
    const resetToken = generateOTP();
    const resetExpires = new Date(Date.now() + 3600000);
    await user.update({ resetPasswordToken: resetToken, resetPasswordExpires: resetExpires });
    const resetUrl = `${APP_BASE_URL}/api/auth/reset-password?token=${resetToken}&email=${email}`;
    await sendEmail(email, 'Password Reset', `<p>You requested a password reset.</p>
      <p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.</p>`);
    res.status(200).json({ message: 'Password reset instructions sent to your email.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error during forgot password.' });
  }
});

// 5. Reset Password
router.post('/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    const user = await User.findOne({
      where: { email, resetPasswordToken: token, resetPasswordExpires: { [Op.gt]: new Date() } }
    });
    if (!user) return res.status(400).json({ error: 'Invalid or expired token.' });
    await user.update({ password: newPassword, resetPasswordToken: null, resetPasswordExpires: null });
    await sendEmail(email, 'Password Reset Successful', `<p>Your password has been reset successfully.</p>`);
    res.status(200).json({ message: 'Password has been reset successfully.' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error during password reset.' });
  }
});

// 6. Admin Registration Request
router.post('/admin/request-registration', async (req, res) => {
  try {
    const { name, email } = req.body;
    const existingRequest = await AdminRequest.findOne({ where: { email } });
    if (existingRequest) {
      return res.status(400).json({ error: 'A registration request for this email is already pending or processed.' });
    }
    const existingAdmin = await Admin.findOne({ where: { email } });
    if (existingAdmin) {
      return res.status(400).json({ error: 'An admin with this email already exists.' });
    }
    const request = await AdminRequest.create({ name, email });
    const approveLink = `${APP_BASE_URL}/api/auth/admin/approve?requestId=${request.id}`;
    const declineLink = `${APP_BASE_URL}/api/auth/admin/decline?requestId=${request.id}`;
    const ownerEmail = 'ashishjaiswal0701@gmail.com';
    await sendEmail(ownerEmail, 'New Admin Registration Request', `<p>A new admin registration request has been received.</p>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><a href="${approveLink}">Approve</a> | <a href="${declineLink}">Decline</a></p>`);
    await notifyAllAdmins('New Admin Registration Request',
      `<p>New admin registration request received from ${name} (${email}).</p>`, Admin);
    res.status(200).json({ message: 'Registration request sent for approval.' });
  } catch (error) {
    console.error('Admin registration request error:', error);
    res.status(500).json({ error: 'Server error during admin registration request.' });
  }
});

// 7. Admin Request Approval (Owner action)
router.get('/admin/approve', async (req, res) => {
  try {
    const { requestId } = req.query;
    const request = await AdminRequest.findOne({ where: { id: requestId } });
    if (!request) return res.status(404).send('Request not found.');
    await request.update({ status: 'approved' });
    await sendEmail(request.email, 'Admin Registration Approved', `<p>Hello ${request.name},</p>
      <p>Your admin registration request has been approved.</p>
      <p>Please complete your registration by setting your password.</p>`);
    res.send('Admin registration approved.');
  } catch (error) {
    console.error('Admin approval error:', error);
    res.status(500).send('Server error during admin approval.');
  }
});

// 8. Admin Request Decline (Owner action)
router.get('/admin/decline', async (req, res) => {
  try {
    const { requestId } = req.query;
    const request = await AdminRequest.findOne({ where: { id: requestId } });
    if (!request) return res.status(404).send('Request not found.');
    await request.update({ status: 'declined' });
    await sendEmail(request.email, 'Admin Registration Declined', `<p>Hello ${request.name},</p>
      <p>Your admin registration request has been declined.</p>`);
    res.send('Admin registration declined.');
  } catch (error) {
    console.error('Admin decline error:', error);
    res.status(500).send('Server error during admin decline.');
  }
});

// 9. Complete Admin Registration
router.post('/admin/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const adminRequest = await AdminRequest.findOne({ where: { email, status: 'approved' } });
    if (!adminRequest) {
      return res.status(400).json({ error: 'Your registration request has not been approved yet.' });
    }
    const adminCount = await Admin.count();
    if (adminCount >= 10) return res.status(400).json({ error: 'Admin registration limit reached.' });
    const admin = await Admin.create({ name, email, password });
    await admin.update({ isVerified: true, isApproved: true });
    await adminRequest.destroy();
    await notifyAllAdmins('New Admin Registered', `<p>New admin registered with email: ${email}</p>`, Admin);
    res.status(201).json({ message: 'Admin registration successful.' });
  } catch (error) {
    console.error('Admin registration error:', error);
    res.status(500).json({ error: 'Server error during admin registration.' });
  }
});

// 10. Admin Login
router.post('/admin/login', async (req, res) => {
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
router.get('/profile', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authorized, no token provided.' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // Prevent admins from using this endpoint:
    if (decoded.role && decoded.role === 'admin') {
      return res.status(401).json({ error: 'Not authorized as user.' });
    }
    const user = await User.findOne({ where: { id: decoded.id } });
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.status(200).json({ user });
  } catch (error) {
    console.error('User profile error:', error);
    res.status(401).json({ error: 'Not authorized, token failed.' });
  }
});


module.exports = router;
