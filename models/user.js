require('dotenv').config();
const mongoose = require('mongoose');
mongoose.connect(process.env.CONNECTION_STRING);


const userSchema = mongoose.Schema({
    googleId: { type: String, unique: true, sparse: true }, // Google OAuth ID
    Full_Name: String,
    email: { type: String, unique: true, required: true },
    password: String, // Optional (OAuth users won't have a password)
    refreshToken: String,
    verificationCode: String,
    isVerified: {
        type: Boolean,
        default: false,
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
});

module.exports = mongoose.model('user', userSchema);