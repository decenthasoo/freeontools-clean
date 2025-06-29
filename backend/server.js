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

// ==================== Environment Configuration ====================
// Fallback to Render's alternative variable names if primary not set
const JWT_SECRET = process.env.JWT_SECRET || process.env.JMT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || process.env.JMT_SECRET;
const MONGO_URI = process.env.MONGO_URI || process.env.MONGQ_URI;
const GMAIL_USER = process.env.GMAIL_USER || process.env.GMATL_USER;
const GMAIL_PASS = process.env.GMAIL_PASS || process.env.GMATL_PASS;

// ==================== Environment Validation ====================
if (!JWT_SECRET || !SESSION_SECRET) {
    console.error('ERROR: Missing JWT secret. Please set either:');
    console.error('- JWT_SECRET or JMT_SECRET in environment variables');
    process.exit(1);
}

if (!GMAIL_USER || !GMAIL_PASS) {
    console.error('ERROR: Missing email credentials. Please set either:');
    console.error('- GMAIL_USER/GMAIL_PASS or GMATL_USER/GMATL_PASS');
    process.exit(1);
}

// ==================== Middleware ====================
app.set('trust proxy', 1);

app.use(cors({
    origin: [
        'https://www.freeontools.com',
        'http://localhost:8080'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, '../')));

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,
        domain: process.env.NODE_ENV === 'production' ? 'freeontools.com' : undefined
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// ==================== Database & Services ====================
mongoose.connect(MONGO_URI, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
}).then(() => {
    console.log('MongoDB connected');
    User.collection.createIndex({ email: 1 }, { unique: true, sparse: true });
}).catch(err => console.error('MongoDB connection error:', err));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: GMAIL_USER,
        pass: GMAIL_PASS
    }
});

// ==================== Passport Strategies ====================
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.NODE_ENV === 'production' 
        ? 'https://www.freeontools.com/auth/facebook/callback'
        : 'http://localhost:3000/auth/facebook/callback',
    profileFields: ['id', 'emails', 'name']
}, /* Existing Facebook strategy */));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.NODE_ENV === 'production'
        ? 'https://www.freeontools.com/auth/google/callback'
        : 'http://localhost:3000/auth/google/callback'
}, /* Existing Google strategy */));

// ==================== Routes ====================
// Keep all your existing routes exactly as they are
// Just update the JWT signing to use the new variable:

app.get('/auth/facebook/callback', 
    passport.authenticate('facebook', { 
        failureRedirect: process.env.NODE_ENV === 'production'
            ? 'https://www.freeontools.com/login.html'
            : 'http://localhost:8080/login.html'
    }),
    (req, res) => {
        const token = jwt.sign({ userId: req.user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.redirect(process.env.NODE_ENV === 'production'
            ? `https://www.freeontools.com/profile.html?token=${token}`
            : `http://localhost:8080/profile.html?token=${token}`);
    }
);

// ==================== Server Start ====================
app.listen(PORT, () => {
    console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode`);
    console.log(`Port: ${PORT}`);
    console.log(`Frontend: ${process.env.NODE_ENV === 'production' 
        ? 'https://www.freeontools.com' 
        : 'http://localhost:8080'}`);
});