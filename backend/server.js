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
const staticPath = path.join(__dirname, '../');
const indexPath = path.join(staticPath, 'Index.html');
const footerPath = path.join(staticPath, 'Footer.html');

console.log('\n=== Server Initialization ===');
console.log('Environment:', config.nodeEnv);
console.log('Static files path:', staticPath);
console.log('Index.html path:', indexPath);
console.log('Footer.html path:', footerPath);

// Verify critical files exist
if (!fs.existsSync(staticPath)) {
  console.error('\x1b[31mERROR: Static files directory not found at:', staticPath, '\x1b[0m');
  process.exit(1);
}
if (!fs.existsSync(indexPath)) {
  console.error('\x1b[31mERROR: Index.html not found\x1b[0m');
  process.exit(1);
}
if (!fs.existsSync(footerPath)) {
  console.error('\x1b[31mERROR: Footer.html not found\x1b[0m');
  process.exit(1);
}

// Middleware Setup
app.set('trust proxy', 1);

// Enhanced Redirect Middleware - Handles all cases
app.use((req, res, next) => {
  const host = req.get('host').toLowerCase();
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const originalUrl = req.originalUrl;

  // Skip redirect checks for static files and API routes
  if (originalUrl.includes('.') && !originalUrl.endsWith('.html') || 
      originalUrl.startsWith('/api/') || 
      originalUrl.startsWith('/auth/')) {
    return next();
  }

  // Determine target URL
  let targetUrl = null;

  // Handle .html to clean URL redirect (301 permanent)
  if (originalUrl.endsWith('.html')) {
    targetUrl = `https://www.freeontools.com${originalUrl.replace(/\.html$/, '')}`;
  }
  // Handle naked domain or HTTP
  else if (config.nodeEnv === 'production') {
    if (host === 'freeontools.com' || protocol !== 'https') {
      targetUrl = `https://www.freeontools.com${originalUrl}`;
    }
  }

  // Perform redirect if needed
  if (targetUrl && targetUrl !== `https://${host}${originalUrl}`) {
    console.log(`Redirecting: ${protocol}://${host}${originalUrl} → ${targetUrl}`);
    return res.redirect(301, targetUrl);
  }

  next();
});

// CORS Configuration
app.use(cors({
  origin: [
    'https://www.freeontools.com',
    'https://freeontools.com',
    'http://localhost:8080'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Fix for MIME type and case sensitivity issues
app.use((req, res, next) => {
  // Fix JS MIME types
  if (req.path.endsWith('.js')) {
    res.type('application/javascript');
  }
  // Case-insensitive route for Footer.html
  if (req.path.toLowerCase() === '/footer.html') {
    return res.sendFile(footerPath);
  }
  next();
});

// Static File Serving with proper headers
app.use(express.static(staticPath, {
  maxAge: '1y',
  setHeaders: (res, filePath) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

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

// MAIN ROUTING SOLUTION - SEO-friendly with redirect prevention
app.get('*', (req, res, next) => {
  // Skip API/auth routes and files with extensions
  if (req.path.startsWith('/api/') || 
      req.path.startsWith('/auth/') || 
      (req.path.includes('.') && !req.path.endsWith('.html'))) {
    return next();
  }

  // Check if specific HTML page exists
  const htmlPath = path.join(staticPath, `${req.path}.html`);
  if (fs.existsSync(htmlPath)) {
    return res.sendFile(htmlPath);
  }

  // Fallback to Index.html for all other routes
  res.sendFile(indexPath);
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('\x1b[31mSERVER ERROR:\x1b[0m', err.stack);
  res.status(500).send('Internal Server Error');
});

// Server Start
const server = app.listen(PORT, () => {
  console.log('\n\x1b[36m=== Server Successfully Started ===\x1b[0m');
  console.log(`\x1b[32mPort:\x1b[0m ${PORT}`);
  console.log(`\x1b[32mEnvironment:\x1b[0m ${config.nodeEnv}`);
  console.log(`\x1b[32mFrontend URL:\x1b[0m https://www.freeontools.com`);
  console.log('\x1b[36m=== Ready for Connections ===\x1b[0m\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\x1b[33mSIGTERM received. Shutting down gracefully...\x1b[0m');
  server.close(() => {
    mongoose.connection.close().then(() => {
      console.log('\x1b[32mServer stopped\x1b[0m');
      process.exit(0);
    });
  });
});