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
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT; // Don't fallback to 10000, required by Northflank

// Config from .env or fallback
const config = {
  jwtSecret: process.env.JWT_SECRET || 'default-secret-key',
  sessionSecret: process.env.SESSION_SECRET || 'default-session-secret',
  mongoURI: process.env.MONGO_URI || 'mongodb://localhost:27017/freeontools',
  emailUser: process.env.EMAIL_USER,
  emailPass: process.env.EMAIL_PASS,
  nodeEnv: process.env.NODE_ENV || 'production',
  facebookAppId: process.env.FACEBOOK_APP_ID,
  facebookAppSecret: process.env.FACEBOOK_APP_SECRET,
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
};

const staticPath = path.join(__dirname, '../');
const indexPath = path.join(staticPath, 'Index.html');
const footerPath = path.join(staticPath, 'Footer.html');

console.log('\n=== Server Initialization ===');
console.log('Environment:', config.nodeEnv);
console.log('Static path:', path.resolve(staticPath));

// Check required files
if (!fs.existsSync(indexPath) || !fs.existsSync(footerPath)) {
  console.error('Missing Index.html or Footer.html. Check static path.');
  process.exit(1);
}

// Middleware
app.set('trust proxy', 1);

// Redirect HTTP → HTTPS and non-www → www, unless it's a backend domain like *.code.run
app.use((req, res, next) => {
  const host = req.get('host');
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const isBackendDomain = host.includes('code.run') || host.includes('northflank');

  if (config.nodeEnv === 'production' && !isBackendDomain) {
    if (host !== 'www.freeontools.com' || protocol !== 'https') {
      return res.redirect(301, `https://www.freeontools.com${req.url}`);
    }
  }
  next();
});

// Redirect `.html` URLs without breaking query string
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    const newPath = req.path.slice(0, -5);
    const htmlPath = path.join(staticPath, `${newPath}.html`);
    if (fs.existsSync(htmlPath)) {
      const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
      return res.redirect(301, `${newPath}${query}`);
    }
  }
  next();
});

// CORS
app.use(cors({
  origin: ['https://www.freeontools.com', 'https://freeontools.com', 'http://localhost:8080'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Fix MIME types and Footer.html routing
app.use((req, res, next) => {
  if (req.path.endsWith('.js')) res.type('application/javascript');
  if (req.path.toLowerCase() === '/footer.html') {
    return res.sendFile(footerPath);
  }
  next();
});

// Static files
app.use(express.static(staticPath, {
  maxAge: '1y',
  setHeaders: (res, filePath) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
  }
}));

// Session
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// MongoDB
mongoose.connect(config.mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('\x1b[32mMongoDB connected\x1b[0m');
}).catch(err => {
  console.error('MongoDB error:', err);
  process.exit(1);
});

// Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.emailUser,
    pass: config.emailPass
  }
});

transporter.verify((err) => {
  if (err) console.error('Email transport error:', err);
  else console.log('Nodemailer SMTP connected');
});

// Social OAuth
if (config.facebookAppId && config.facebookAppSecret) {
  passport.use(new FacebookStrategy({
    clientID: config.facebookAppId,
    clientSecret: config.facebookAppSecret,
    callbackURL: 'https://www.freeontools.com/api/auth/facebook/callback',
    profileFields: ['id', 'emails', 'name', 'displayName']
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ $or: [{ facebookId: profile.id }, { email: profile.emails?.[0]?.value }] });
      if (!user) {
        user = new User({
          facebookId: profile.id,
          email: profile.emails?.[0]?.value,
          name: profile.displayName,
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
  console.log('Facebook OAuth initialized');
}

if (config.googleClientId && config.googleClientSecret) {
  passport.use(new GoogleStrategy({
    clientID: config.googleClientId,
    clientSecret: config.googleClientSecret,
    callbackURL: 'https://www.freeontools.com/api/auth/google/callback',
    scope: ['profile', 'email'],
    proxy: true
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ $or: [{ googleId: profile.id }, { email: profile.emails?.[0]?.value }] });
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
  console.log('Google OAuth initialized');
}

// Auth Routes
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email }).select('+password');
    if (!user || !user.password || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id, email: user.email }, config.jwtSecret, { expiresIn: '1h' });
    req.session.userId = user._id;
    res.json({ token, message: 'Login successful' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    if (password.length < 8) return res.status(400).json({ message: 'Password too short' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email exists' });

    const user = new User({ name, email, password, isVerified: true });
    await user.save();
    const token = jwt.sign({ userId: user._id, email: user.email }, config.jwtSecret, { expiresIn: '1h' });
    req.session.userId = user._id;
    res.json({ token, message: 'Signup successful' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Email not found' });

    const token = jwt.sign({ userId: user._id }, config.jwtSecret, { expiresIn: '1h' });
    const link = `https://www.freeontools.com/reset-password.html?token=${token}`;
    await transporter.sendMail({
      from: `"FreeOnTools" <${config.emailUser}>`,
      to: email,
      subject: 'Reset your password',
      html: `Click <a href="${link}">here</a> to reset your password`
    });
    res.json({ message: 'Reset email sent' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to send email' });
  }
});

app.post('/api/validate-reset-token', async (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, config.jwtSecret);
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error('Invalid');
    res.json({ valid: true });
  } catch {
    res.status(400).json({ valid: false });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', time: new Date().toISOString() });
});

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google', {
  failureRedirect: 'https://www.freeontools.com/login.html'
}), (req, res) => {
  const token = jwt.sign({ userId: req.user._id, email: req.user.email }, config.jwtSecret, { expiresIn: '1h' });
  res.redirect(`https://www.freeontools.com/profile.html?token=${token}`);
});

app.get('/api/auth/facebook', passport.authenticate('facebook'));
app.get('/api/auth/facebook/callback', passport.authenticate('facebook', {
  failureRedirect: 'https://www.freeontools.com/login.html'
}), (req, res) => {
  const token = jwt.sign({ userId: req.user._id, email: req.user.email }, config.jwtSecret, { expiresIn: '1h' });
  res.redirect(`https://www.freeontools.com/profile.html?token=${token}`);
});

// Universal Route Handler for *.html fallback
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.includes('.')) return next();
  const htmlPath = path.join(staticPath, `${req.path}.html`);
  if (fs.existsSync(htmlPath)) return res.sendFile(htmlPath);
  res.sendFile(indexPath);
});

// Error handler
app.use((err, req, res, next) => {
  console.error('SERVER ERROR:', err);
  res.status(500).send('Internal Server Error');
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('\x1b[36m=== Server Successfully Started ===\x1b[0m');
  console.log(`\x1b[32mPort:\x1b[0m ${PORT}`);
  console.log(`\x1b[32mEnv:\x1b[0m ${config.nodeEnv}`);
  console.log('\x1b[36m=====================================\x1b[0m\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Closing...');
  server.close(() => {
    mongoose.connection.close().then(() => {
      console.log('Server & DB connection closed.');
      process.exit(0);
    });
  });
});
