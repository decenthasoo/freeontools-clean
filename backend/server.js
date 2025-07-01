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

// ==================== ENVIRONMENT CONFIG ====================
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

// ==================== MONGOOSE CONNECTION ====================
console.log('Connecting to MongoDB at:', config.mongoURI);
mongoose.connect(config.mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 30000
})
.then(() => console.log('\x1b[32mMongoDB connected successfully\x1b[0m'))
.catch(err => {
  console.error('\x1b[31mMongoDB connection failed:\x1b[0m', err.message);
  process.exit(1);
});

// ==================== EXPRESS MIDDLEWARE ====================
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS Configuration
app.use(cors({
  origin: [
    'https://www.freeontools.com',
    'https://freeontools.com',
    'http://localhost:8080'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Static File Serving with Cache Control
app.use(express.static(path.join(__dirname, '../'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=31536000');
    }
  }
});

// ==================== REDIRECT MIDDLEWARE ====================
app.use((req, res, next) => {
  const host = req.hostname;
  const url = req.url;

  // 1. Redirect naked domain to www
  if (host === 'freeontools.com') {
    return res.redirect(301, `https://www.freeontools.com${url}`);
  }

  // 2. Remove .html extensions
  if (url.endsWith('.html')) {
    return res.redirect(301, url.replace(/\.html$/, ''));
  }

  // 3. Remove trailing slashes (except root)
  if (url.endsWith('/') && url !== '/') {
    return res.redirect(301, url.replace(/\/$/, ''));
  }

  next();
});

// ==================== SESSION CONFIG ====================
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    sameSite: config.nodeEnv === 'production' ? 'lax' : 'none',
    maxAge: 24 * 60 * 60 * 1000,
    domain: config.nodeEnv === 'production' ? '.freeontools.com' : undefined
  }
}));

// ==================== PASSPORT CONFIG ====================
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

// ==================== OAUTH STRATEGIES ====================
// Facebook Strategy
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
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// Google Strategy
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
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// ==================== ROUTES ====================
// Health Check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Facebook Auth Routes
app.get('/auth/facebook', passport.authenticate('facebook'));

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
    res.redirect(`${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:8080'}/profile?token=${token}`);
  }
);

// Google Auth Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: config.nodeEnv === 'production'
      ? 'https://www.freeontools.com/login'
      : 'http://localhost:8080/login'
  }),
  (req, res) => {
    const token = jwt.sign({ 
      userId: req.user._id,
      email: req.user.email
    }, config.jwtSecret, { expiresIn: '1h' });
    res.redirect(`${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:8080'}/profile?token=${token}`);
  }
);

// Sample API Route (replace with your actual API endpoints)
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== FRONTEND ROUTING ====================
app.get('*', (req, res) => {
  // Skip API/auth routes
  if (req.path.startsWith('/auth/') || req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }

  const requestedPath = req.path === '/' ? 'index' : req.path.replace(/^\//, '').replace(/\/$/, '');
  const filePath = path.join(__dirname, '../', `${requestedPath}.html`);

  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }
  
  // Fallback to index.html for client-side routing
  res.sendFile(path.join(__dirname, '../index.html'));
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('\x1b[31mError:\x1b[0m', err.stack);
  res.status(500).send('Internal Server Error');
});

// ==================== SERVER START ====================
app.listen(PORT, () => {
  console.log(`\n\x1b[36mServer running in ${config.nodeEnv} mode\x1b[0m`);
  console.log(`\x1b[33mPort:\x1b[0m ${PORT}`);
  console.log(`\x1b[33mFrontend URL:\x1b[0m https://www.freeontools.com`);
  console.log(`\x1b[33mDatabase:\x1b[0m ${config.mongoURI}`);
  console.log(`\x1b[33mOAuth Status:\x1b[0m`);
  console.log(`- Facebook: ${config.facebookAppId ? 'Enabled' : 'Disabled'}`);
  console.log(`- Google: ${config.googleClientId ? 'Enabled' : 'Disabled'}\n`);
});