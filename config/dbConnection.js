const mongoose = require('mongoose');

const connectDb = async ()=>{
    try {
        const connect = await mongoose.connect(process.env.CONNECTION_STRING);
        // mongoose.connect('mongodb://127.0.0.1:27017/authenticationdetails');
        console.log('Database connected: ',connect.connection.host, connect.connection.name);
    } catch (err) {
        console.log(err);
        process.exit(1);
    }
};
module.exports = connectDb;