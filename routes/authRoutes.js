const express = require('express');
const router = express.Router();
const { signup, login } = require('../controllers/authController');
const { authenticateToken } = require('../middleware/authMiddleware');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const { generateAccessToken, generateRefreshToken } = require('../utils/token');

router.get('/dashboard', authenticateToken, (req, res) => {
  res.render('dashboard', { user: req.user });
});


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


router.post('/api/signup', signup);
router.post('/api/login', login);

module.exports = router;