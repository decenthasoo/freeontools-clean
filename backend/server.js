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
const PORT = process.env.PORT || 10000;

// Configuration
const config = {
  jwtSecret: process.env.JWT_SECRET || 'default-secret-key',
  sessionSecret: process.env.SESSION_SECRET || 'default-session-secret',
  mongoURI: process.env.MONGO_URI || 'mongodb://localhost:27017/freeontools',
  emailUser: process.env.EMAIL_USER || 'your-email@example.com',
  emailPass: process.env.EMAIL_PASS || 'your-email-password',
  nodeEnv: process.env.NODE_ENV || 'production',
  facebookAppId: process.env.FACEBOOK_APP_ID,
  facebookAppSecret: process.env.FACEBOOK_APP_SECRET,
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET
};

// Path configuration
const staticPath = path.resolve(__dirname, '../');
const indexPath = path.resolve(staticPath, 'Index.html');
const footerPath = path.resolve(staticPath, 'Footer.html');

console.log('\n=== Server Initialization ===');
console.log('Environment:', config.nodeEnv);
console.log('Static files path:', staticPath);
console.log('Directory contents:', fs.readdirSync(staticPath));

// Verify critical files exist
if (!fs.existsSync(staticPath)) {
  console.error('\x1b[31mERROR: Static files directory not found\x1b[0m');
  process.exit(1);
}
if (!fs.existsSync(indexPath)) {
  console.error('\x1b[31mERROR: Index.html not found at:', indexPath, '\x1b[0m');
  process.exit(1);
}
if (!fs.existsSync(footerPath)) {
  console.error('\x1b[31mERROR: Footer.html not found at:', footerPath, '\x1b[0m');
  process.exit(1);
}

// Middleware Setup
app.set('trust proxy', 1);

// 1. FIX FOR DOMAIN REDIRECTS (403 errors)
app.use((req, res, next) => {
  const host = req.get('host').replace(/:\d+$/, '');
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const url = req.originalUrl;

  // Skip static files and API routes
  if (url.includes('.') || url.startsWith('/api/') || url.startsWith('/auth/')) {
    return next();
  }

  // Handle all domain variants
  if (config.nodeEnv === 'production') {
    if (host === 'freeontools.com' || protocol !== 'https') {
      return res.redirect(301, `https://www.freeontools.com${url}`);
    }
  }
  next();
});

// 2. FIX FOR DOUBLE CONTENT
app.use((req, res, next) => {
  res.locals.contentSent = false;
  next();
});

// Fix MIME types for JS files
app.use((req, res, next) => {
  if (req.path.endsWith('.js')) {
    res.type('application/javascript');
  }
  next();
});

// Static files with proper caching
app.use(express.static(staticPath, {
  setHeaders: (res, filePath) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    }
  }
}));

// 3. FIX FOR FOOTER - handle both cases
app.get(['/footer.html', '/Footer.html'], (req, res) => {
  res.sendFile(footerPath);
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
    maxAge: 24 * 60 * 60 * 1000
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

// Database Connection
mongoose.connect(config.mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('\x1b[32mMongoDB connected successfully\x1b[0m'))
.catch(err => {
  console.error('\x1b[31mMongoDB connection failed:\x1b[0m', err);
  process.exit(1);
});

// Email Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.emailUser,
    pass: config.emailPass
  }
});

// Facebook OAuth Strategy
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
          { email: profile.emails?.[0]?.value }
        ]
      });

      if (!user) {
        user = new User({
          facebookId: profile.id,
          email: profile.emails?.[0]?.value,
          name: profile.displayName || `${profile.name?.givenName} ${profile.name?.familyName}`,
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
  console.log('\x1b[32mFacebook OAuth initialized\x1b[0m');
}

// Google OAuth Strategy
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
          { email: profile.emails?.[0]?.value }
        ]
      });

      if (!user) {
        user = new User({
          googleId: profile.id,
          email: profile.emails?.[0]?.value,
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
  console.log('\x1b[32mGoogle OAuth initialized\x1b[0m');
}

// API Routes
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    environment: config.nodeEnv,
    timestamp: new Date().toISOString()
  });
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

// Sample API Route
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. MAIN ROUTING HANDLER - fixes content duplication
app.get('*', (req, res, next) => {
  // Skip if content already sent
  if (res.locals.contentSent) {
    return next();
  }

  // Skip API routes and files with extensions
  if (req.path.startsWith('/api/') || req.path.startsWith('/auth/') || req.path.includes('.')) {
    return next();
  }

  // Handle .html redirects
  if (req.path.endsWith('.html')) {
    const cleanPath = req.path.replace(/\.html$/, '');
    return res.redirect(301, cleanPath);
  }

  // Check if specific page exists
  const pagePath = path.join(staticPath, `${req.path}.html`);
  if (fs.existsSync(pagePath)) {
    res.locals.contentSent = true;
    return res.sendFile(pagePath);
  }

  // Only send Index.html if no specific page found
  res.locals.contentSent = true;
  res.sendFile(indexPath);
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('\x1b[31mSERVER ERROR:\x1b[0m', err.stack);
  res.status(500).send('Internal Server Error');
});

// Start server
app.listen(PORT, () => {
  console.log(`\nServer running on port ${PORT}`);
  console.log('Production URLs:');
  console.log('- https://www.freeontools.com (primary)');
  console.log('- http://freeontools.com → redirects to https://www.freeontools.com');
  console.log('- https://freeontools.com → redirects to https://www.freeontools.com');
  console.log('\nReady to handle requests');
});