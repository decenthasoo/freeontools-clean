require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== Configuration ====================
app.set('trust proxy', 1); // Enable for Render's proxy

// ==================== Environment Validation ====================
if (!process.env.JWT_SECRET || !process.env.SESSION_SECRET) {
    console.error('Missing JWT_SECRET or SESSION_SECRET in .env');
    process.exit(1);
}

if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.error('Missing GMAIL_USER or GMAIL_PASS in .env');
    process.exit(1);
}

// ==================== Middleware ====================
app.use(cors({
    origin: [
        'https://www.freeontools.com',
        'http://localhost:8080' // Keep for local testing
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, '../'))); // Serve frontend files

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true, // HTTPS only
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,
        domain: 'freeontools.com'
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// ==================== Database & Services ====================
mongoose.connect(process.env.MONGO_URI, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
}).then(() => {
    console.log('MongoDB connected');
    User.collection.createIndex({ email: 1 }, { unique: true, sparse: true });
}).catch(err => console.error('MongoDB connection error:', err));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
    }
});

// ==================== Passport Strategies ====================
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: 'https://www.freeontools.com/auth/facebook/callback',
    profileFields: ['id', 'emails', 'name']
}, /* Existing Facebook strategy code */));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'https://www.freeontools.com/auth/google/callback'
}, /* Existing Google strategy code */));

// ==================== Routes ====================
// (Keep all your existing route handlers exactly as-is, only update URLs)

// Example route updates:
app.get('/auth/facebook/callback', 
    passport.authenticate('facebook', { 
        failureRedirect: 'https://www.freeontools.com/login.html' 
    }),
    (req, res) => {
        const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.redirect(`https://www.freeontools.com/profile.html?token=${token}`);
    }
);

app.get('/auth/google/callback',
    passport.authenticate('google', { 
        failureRedirect: 'https://www.freeontools.com/login.html' 
    }),
    (req, res) => {
        const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.redirect(`https://www.freeontools.com/profile.html?token=${token}`);
    }
);

// ==================== Server Start ====================
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Frontend: https://www.freeontools.com`);
    console.log(`API: https://www.freeontools.com/api`);
});