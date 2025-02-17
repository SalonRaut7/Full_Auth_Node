const express = require('express');
const app = express();
const path = require('path');
const dotenv = require('dotenv').config();
const port = process.env.PORT || 8000;
const connectDb = require('./config/dbConnection');


connectDb();
// Middleware to parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

//setting up view engine
app.set('views', path.join(__dirname, 'views')) 
app.set('view engine', 'ejs') 


  
app.use('/', require("./routes/authRoutes"));




app.listen(port, ()=>{
    console.log(`Server running at http://localhost:${port}`);
});

