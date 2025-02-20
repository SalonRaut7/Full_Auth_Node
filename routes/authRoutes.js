const express = require('express');
const router = express.Router();
const { signup, login, forgotPasswordPage } = require('../controllers/authController');
const { authenticateToken } = require('../middleware/authMiddleware');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const { generateAccessToken, generateRefreshToken } = require('../utils/token');
const { forgotPassword, resetPasswordPage, resetPassword } = require('../controllers/authController');
const passport = require('passport');


router.get('/dashboard', (req, res) => {
  const token = req.cookies.accessToken;

  if (!token) {
    return res.redirect('/login'); // Redirect if no token found
  }

  try {
    // Verify the token and extract user info
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    res.render('dashboard', { user: decoded });
  } catch (error) {
    return res.redirect('/login');
  }
});


router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google callback URL after successful login
router.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const accessToken = jwt.sign({ id: req.user._id ,email: req.user.email}, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: '1h',
    });

    res.cookie('accessToken', accessToken);
    res.redirect('/dashboard');
  }
);


router.get('/login', (req, res) => {
    res.render('login');
});

router.get('/signup', (req, res) => {
    res.render('signup');
});

router.post('/refresh-token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    // Check if refresh token is provided
    if (!refreshToken) return res.status(401).json({ message: 'No token provided' });

    // Find user by refresh token
    const user = await User.findOne({ refreshToken });
    if (!user) return res.status(403).json({ message: 'Invalid token' });

    // Verify refresh token
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Token expired or invalid' });

        // Generate new access token
        const newAccessToken = generateAccessToken(user);
        res.json({ accessToken: newAccessToken });
    });
});


router.post('/logout', async (req, res) => {
    const user = await User.findOne({ refreshToken: req.cookies.refreshToken });

    if (user) {
        user.refreshToken = null;
        await user.save();
    }

    // Clear the cookie
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.status(200).json({ message: 'Logged out successfully' });
});

router.get('/verify-email/:userId', (req, res) => {
    const { userId } = req.params;
    res.render('verify-email', { userId }); 
  });

  router.post('/verify-email/:userId', async (req, res) => {
    const { userId } = req.params;
    const { code } = req.body;
  
    // Find the user by the userId
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
  
    // Check if the OTP matches
    if (user.verificationCode !== code) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }
  
    // OTP is correct, set user as verified
    user.isVerified = true;
    user.verificationCode = null; // Clear the code after verification
    await user.save();
  
    // Redirect to the dashboard
    res.redirect('/dashboard');
  });  


router.post('/api/signup', signup);
router.post('/api/login', login);


router.get('/forgot-password',forgotPasswordPage);
router.post('/forgot-password', forgotPassword);
router.get('/reset-password/:token', resetPasswordPage);
router.post('/reset-password/:token', resetPassword);

module.exports = router;