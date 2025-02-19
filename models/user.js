const mongoose = require('mongoose');
mongoose.connect('mongodb://127.0.0.1:27017/authenticationdetails');


const userSchema = mongoose.Schema({
    Full_Name: String,
    email: String,
    password:String,
    refreshToken: String,
    verificationCode:String,
    isVerified:{
        type:Boolean,
        default:false,
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
});

module.exports = mongoose.model('user', userSchema);