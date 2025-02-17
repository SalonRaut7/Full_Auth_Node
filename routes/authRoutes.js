const express = require('express');
const router = express.Router();
const { signup, login } = require('../controllers/authController');


router.get('/login', (req, res) => {
    res.render('login');
});

router.get('/signup', (req, res) => {
    res.render('signup');
});

// POST Routes for Auth
router.post('/api/signup', signup);
router.post('/api/login', login);

module.exports = router;