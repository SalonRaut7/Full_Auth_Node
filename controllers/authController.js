require('dotenv').config();
const User = require('../models/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { generateAccessToken, generateRefreshToken } = require('../utils/token');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; //regular expression for validating email format
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// @desc Register User
// @route POST /auth/signup
// @access Public
exports.signup = async (req, res) => {
  try {
    const { fullname, email, password ,confirmPassword} = req.body;
    //email validation
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    //password validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/; //regular expression for validating password requirements
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.'
      });
    }
    // Check if the both the passwords are matched
    if(password !== confirmPassword){
      return res.status(401).json({message: 'passwords fields do not match'});
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    //generating verification code
    const verificationCode = crypto.randomBytes(3).toString('hex');
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save new user
    const newUser = new User({
      Full_Name: fullname,
      email,
      password: hashedPassword,
      verificationCode,
    });
    const accessToken = generateAccessToken(newUser);
    const refreshToken = generateRefreshToken(newUser);
    newUser.refreshToken = refreshToken;
    await newUser.save();
    res.cookie('accessToken', accessToken);
    // Send Email using nodemailer
    const transporter = nodemailer.createTransport({
      host: 'smtp.zoho.com',
      port: 465,
      secure: true, // Use SSL
      auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS,  
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify your email',
      text: `Your verification code is: ${verificationCode}`,
    };

    await transporter.sendMail(mailOptions);
    res.redirect(`/verify-email/${newUser._id}`);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc Login User
// @route POST /auth/login
// @access Public
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    if (!user.isVerified) {
      return res.status(403).json({ message: 'Please verify your email before logging in.' });
    }
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    user.refreshToken = refreshToken;
    await user.save();
    res.cookie('accessToken', accessToken);
    res.cookie('refreshToken', refreshToken);
    // res.status(200).json({
    //   message: 'Login successful',
    //   accessToken,
    //   user: { id: user._id, email: user.email },
    // });
    return res.redirect('/dashboard');
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Generate Reset Token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 15 * 60 * 1000; // 15 minutes expiry
    await user.save();

    // Send Email to the email address for reseting the password
    const transporter = nodemailer.createTransport({
      host: 'smtp.zoho.com',
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetLink = `http://localhost:8000/reset-password/${resetToken}`;
    
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Reset Your Password',
      text: `Click the link to reset your password: ${resetLink}`,
    });

    res.json({ message: 'Reset link sent to your email' });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

exports.forgotPasswordPage = async(req,res) =>{
  res.render('forgotPassword');
}

exports.resetPasswordPage = async (req, res) => {
  const { token } = req.params;
  res.render('resetPassword', { token });
};

exports.resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    // Find user by reset token
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }, // Check if token is still valid
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // Clear reset token fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    
    await user.save();
    
    res.json({ message: 'Password reset successful. You can now log in.' });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};


passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,  
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,  
      callbackURL: "http://localhost:8000/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user already exists in the database
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          // If user doesn't exist, create a new user
          user = new User({
            googleId: profile.id,
            Full_Name: profile.displayName,
            email: profile.emails[0].value,
            isVerified: true, // Google users are already verified
          });

          await user.save();
        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// Serialize user data
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user data
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

