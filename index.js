const express = require('express');
const app = express();
const path = require('path');
const dotenv = require('dotenv').config();
const port = process.env.PORT || 8000;
const connectDb = require('./config/dbConnection');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const session = require('express-session');
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");

connectDb();

// Use Helmet to secure HTTP headers and allow Tailwind CDN for content security policy
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
      },
    },
  })
);

// mongo sanitization
app.use(mongoSanitize());

app.use(
  session({
    secret: process.env.SESSION_SECRET, 
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Middleware to parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

//setting up view engine
app.set('views', path.join(__dirname, 'views')) 
app.set('view engine', 'ejs') 

app.use(cookieParser());
  
app.use('/', require("./routes/authRoutes"));




app.listen(port, ()=>{
    console.log(`Server running at http://localhost:${port}`);
});

