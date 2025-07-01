require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

// Environment Configuration
const config = {
  jwtSecret: process.env.JWT_SECRET || process.env.JMT_SECRET,
  sessionSecret: process.env.SESSION_SECRET || process.env.JMT_SECRET,
  mongoURI: process.env.MONGO_URI || process.env.MONGQ_URI,
  emailUser: process.env.GMAIL_USER || process.env.GMATL_USER,
  emailPass: process.env.GMAIL_PASS || process.env.GMATL_PASS,
  nodeEnv: process.env.NODE_ENV || 'development',
  facebookAppId: process.env.FACEBOOK_APP_ID,
  facebookAppSecret: process.env.FACEBOOK_APP_SECRET,
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET
};

// Debug MongoDB connection
console.log('Attempting to connect to MongoDB at:', config.mongoURI);

// Environment Validation
if (!config.jwtSecret || !config.sessionSecret) {
  console.error('\x1b[31m', 'ERROR: Missing required secrets:');
  console.error('- Set JWT_SECRET or JMT_SECRET');
  console.error('- Set SESSION_SECRET or use JMT_SECRET');
  console.error('\x1b[0m');
  process.exit(1);
}

// Middleware
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

// Static File Serving
app.use(express.static(path.join(__dirname, '../')));

// Redirect Middleware
app.use((req, res, next) => {
  // Force HTTPS and www in production
  if (config.nodeEnv === 'production') {
    if (req.hostname === 'freeontools.com') {
      return res.redirect(301, `https://www.freeontools.com${req.url}`);
    }
    if (!req.secure && req.get('x-forwarded-proto') !== 'https') {
      return res.redirect(`https://${req.hostname}${req.url}`);
    }
  }
  
  // Remove .html and trailing slash
  if (req.path.endsWith('.html') || req.path.endsWith('/')) {
    const cleanUrl = req.path.replace(/\.html$/, '').replace(/\/$/, '');
    return res.redirect(301, cleanUrl);
  }
  
  next();
});

// Session Configuration
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

// Passport Setup
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

// MongoDB Connection
const connectWithRetry = () => {
  mongoose.connect(config.mongoURI, { 
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 30000
  })
  .then(() => {
    console.log('\x1b[32mMongoDB connected successfully\x1b[0m');
    return User.collection.createIndex({ email: 1 }, { unique: true, sparse: true });
  })
  .catch(err => {
    console.error('\x1b[31mMongoDB connection failed:\x1b[0m', err.message);
    console.log('Retrying connection in 5 seconds...');
    setTimeout(connectWithRetry, 5000);
  });
};

connectWithRetry();

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.emailUser,
    pass: config.emailPass
  }
});

// OAuth Strategy Initialization
const initOAuthStrategies = () => {
  if (config.facebookAppId && config.facebookAppSecret) {
    passport.use(new FacebookStrategy({
      clientID: config.facebookAppId,
      clientSecret: config.facebookAppSecret,
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
    console.log('\x1b[32mFacebook OAuth initialized\x1b[0m');
  }

  if (config.googleClientId && config.googleClientSecret) {
    passport.use(new GoogleStrategy({
      clientID: config.googleClientId,
      clientSecret: config.googleClientSecret,
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
    console.log('\x1b[32mGoogle OAuth initialized\x1b[0m');
  }
};

initOAuthStrategies();

// Route Handling
app.get('/auth/facebook/callback', 
  passport.authenticate('facebook', { 
    failureRedirect: config.nodeEnv === 'production'
      ? 'https://www.freeontools.com/login'
      : 'http://localhost:8080/login'
  }),
  (req, res) => {
    const token = jwt.sign({ 
      userId: req.user._id,
      email: req.user.email
    }, config.jwtSecret, { expiresIn: '1h' });
    res.redirect(config.nodeEnv === 'production'
      ? `https://www.freeontools.com/profile?token=${token}`
      : `http://localhost:8080/profile?token=${token}`);
  }
);

// Final Catch-All Route
app.get('*', (req, res) => {
  // Skip API routes
  if (req.path.startsWith('/auth/') || req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }

  const filePath = path.join(__dirname, '../', req.path === '/' ? 'index.html' : req.path);
  
  // Try exact path first
  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }
  
  // Try with .html extension
  if (fs.existsSync(`${filePath}.html`)) {
    return res.sendFile(`${filePath}.html`);
  }
  
  // Fallback to index.html
  res.sendFile(path.join(__dirname, '../index.html'));
});

// Server Start
app.listen(PORT, () => {
  console.log(`\n\x1b[36mServer running in ${config.nodeEnv} mode\x1b[0m`);
  console.log(`\x1b[33mPort:\x1b[0m ${PORT}`);
  console.log(`\x1b[33mFrontend:\x1b[0m ${config.nodeEnv === 'production' 
    ? 'https://www.freeontools.com' 
    : 'http://localhost:8080'}`);
  console.log(`\x1b[33mDatabase:\x1b[0m ${config.mongoURI}`);
  console.log(`\x1b[33mOAuth Status:\x1b[0m`);
  console.log(`- Facebook: ${config.facebookAppId ? 'Enabled' : 'Disabled'}`);
  console.log(`- Google: ${config.googleClientId ? 'Enabled' : 'Disabled'}\n`);
});