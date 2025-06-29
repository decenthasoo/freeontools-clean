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
const config = {
  jwtSecret: process.env.JWT_SECRET || process.env.JMT_SECRET,
  sessionSecret: process.env.SESSION_SECRET || process.env.JMT_SECRET,
  mongoURI: process.env.MONGO_URI || process.env.MONGQ_URI,
  emailUser: process.env.GMAIL_USER || process.env.GMATL_USER,
  emailPass: process.env.GMAIL_PASS || process.env.GMATL_PASS,
  nodeEnv: process.env.NODE_ENV || 'development'
};

// ==================== Environment Validation ====================
if (!config.jwtSecret || !config.sessionSecret) {
  console.error('\x1b[31m', 'ERROR: Missing required secrets:');
  console.error('- Set JWT_SECRET or JMT_SECRET');
  console.error('- Set SESSION_SECRET or use JMT_SECRET');
  console.error('\x1b[0m');
  process.exit(1);
}

if (!config.emailUser || !config.emailPass) {
  console.error('\x1b[31m', 'ERROR: Missing email credentials:');
  console.error('- Set GMAIL_USER/GMAIL_PASS or GMATL_USER/GMATL_PASS');
  console.error('\x1b[0m');
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
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    sameSite: config.nodeEnv === 'production' ? 'lax' : 'none',
    maxAge: 24 * 60 * 60 * 1000,
    domain: config.nodeEnv === 'production' ? 'freeontools.com' : undefined
  }
}));

// ==================== Passport Setup ====================
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ==================== Database & Services ====================
mongoose.connect(config.mongoURI, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
}).then(() => {
  console.log('MongoDB connected');
  User.collection.createIndex({ email: 1 }, { unique: true, sparse: true });
}).catch(err => console.error('MongoDB connection error:', err));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.emailUser,
    pass: config.emailPass
  }
});

// ==================== Passport Strategies ====================
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: config.nodeEnv === 'production' 
    ? 'https://www.freeontools.com/auth/facebook/callback'
    : 'http://localhost:3000/auth/facebook/callback',
  profileFields: ['id', 'emails', 'name', 'displayName']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ 
      $or: [
        { facebookId: profile.id },
        { email: profile.emails[0].value }
      ]
    });

    if (!user) {
      user = new User({
        facebookId: profile.id,
        email: profile.emails[0].value,
        name: profile.displayName || `${profile.name.givenName} ${profile.name.familyName}`,
        isVerified: true
      });
      await user.save();
    } else if (!user.facebookId) {
      user.facebookId = profile.id;
      await user.save();
    }

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: config.nodeEnv === 'production'
    ? 'https://www.freeontools.com/auth/google/callback'
    : 'http://localhost:3000/auth/google/callback',
  scope: ['profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ 
      $or: [
        { googleId: profile.id },
        { email: profile.emails[0].value }
      ]
    });

    if (!user) {
      user = new User({
        googleId: profile.id,
        email: profile.emails[0].value,
        name: profile.displayName,
        isVerified: true
      });
      await user.save();
    } else if (!user.googleId) {
      user.googleId = profile.id;
      await user.save();
    }

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// ==================== Routes ====================
// (Keep all your existing routes exactly as they were)
// Example route with updated JWT signing:
app.get('/auth/facebook/callback', 
  passport.authenticate('facebook', { 
    failureRedirect: config.nodeEnv === 'production'
      ? 'https://www.freeontools.com/login.html'
      : 'http://localhost:8080/login.html'
  }),
  (req, res) => {
    const token = jwt.sign({ 
      userId: req.user._id,
      email: req.user.email
    }, config.jwtSecret, { expiresIn: '1h' });
    
    res.redirect(config.nodeEnv === 'production'
      ? `https://www.freeontools.com/profile.html?token=${token}`
      : `http://localhost:8080/profile.html?token=${token}`);
  }
);

// ==================== Server Start ====================
app.listen(PORT, () => {
  console.log(`\n\x1b[36mServer running in ${config.nodeEnv} mode\x1b[0m`);
  console.log(`\x1b[33mPort:\x1b[0m ${PORT}`);
  console.log(`\x1b[33mFrontend:\x1b[0m ${config.nodeEnv === 'production' 
    ? 'https://www.freeontools.com' 
    : 'http://localhost:8080'}`);
  console.log(`\x1b[33mAPI Base:\x1b[0m http://localhost:${PORT}/api\n`);
});