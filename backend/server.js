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
const PORT = process.env.PORT || 10000;

// Configuration
const config = {
  jwtSecret: process.env.JWT_SECRET || 'default-secret-key',
  sessionSecret: process.env.SESSION_SECRET || 'default-session-secret',
  mongoURI: process.env.MONGO_URI || 'mongodb://localhost:27017/freeontools',
  emailUser: process.env.EMAIL_USER || 'decenthasoo@gmail.com',
  emailPass: process.env.EMAIL_PASS,
  nodeEnv: process.env.NODE_ENV || 'production',
  facebookAppId: process.env.FACEBOOK_APP_ID,
  facebookAppSecret: process.env.FACEBOOK_APP_SECRET,
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET
};

// Temporarily comment out to prevent server crash during debugging
// if (!config.emailPass) {
//   console.error('\x1b[31mERROR: EMAIL_PASS not set in environment variables\x1b[0m');
//   process.exit(1);
// }

// Path configuration - Points to freeontools-clean root
const staticPath = path.join(__dirname, '../'); // Points to C:\...\freeontools-clean
const indexPath = path.join(staticPath, 'Index.html');
const footerPath = path.join(staticPath, 'Footer.html');

console.log('\n=== Server Initialization ===');
console.log('Environment:', config.nodeEnv);
console.log('Static files path:', path.resolve(staticPath));
console.log('Index.html path:', indexPath);
console.log('Footer.html path:', footerPath);

// Verify critical files exist
if (!fs.existsSync(staticPath)) {
  console.error('\x1b[31mERROR: Static directory not found\x1b[0m');
  console.log('Directory contents:', fs.readdirSync(__dirname));
  process.exit(1);
}
if (!fs.existsSync(indexPath) || !fs.existsSync(footerPath)) {
  console.error('\x1b[31mERROR: Required files not found\x1b[0m');
  console.log('Directory contents:', fs.readdirSync(staticPath));
  process.exit(1);
}

// Middleware Setup
app.set('trust proxy', 1); // For Render.com proxy

// Redirect Middleware - Handles non-www to www and HTTP to HTTPS
app.use((req, res, next) => {
  const host = req.get('host');
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  console.log(`Request: ${protocol}://${host}${req.url}`);
  if (config.nodeEnv === 'production') {
    if (host !== 'www.freeontools.com' || protocol !== 'https') {
      console.log(`Redirecting to https://www.freeontools.com${req.url}`);
      return res.redirect(301, `https://www.freeontools.com${req.url}`);
    }
  }
  next();
});

// Remove .html extension
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    const newPath = req.path.slice(0, -5);
    const htmlPath = path.join(staticPath, `${newPath}.html`);
    if (fs.existsSync(htmlPath)) {
      console.log(`Redirecting ${req.path} to ${newPath}`);
      return res.redirect(301, newPath);
    }
  }
  next();
});

// CORS Configuration
app.use(cors({
  origin: config.nodeEnv === 'production'
    ? ['https://www.freeontools.com']
    : ['https://www.freeontools.com', 'https://freeontools.com', 'http://localhost:8080'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Fix MIME types and case sensitivity
app.use((req, res, next) => {
  if (req.path.endsWith('.js')) {
    res.type('application/javascript');
  }
  if (req.path.toLowerCase() === '/footer.html') {
    console.log(`Serving Footer.html from ${footerPath}`);
    return res.sendFile(footerPath);
  }
  next();
});

// Static File Serving
app.use(express.static(staticPath, {
  maxAge: '1y',
  setHeaders: (res, filePath) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
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
    sameSite: 'lax',
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

// Verify SMTP connection
transporter.verify((error, success) => {
  if (error) {
    console.error('\x1b[31mnodemailer: SMTP connection failed:\x1b[0m', error);
  } else {
    console.log('\x1b[32mnodemailer: SMTP connection successful\x1b[0m');
  }
});

// Facebook OAuth Strategy
if (config.facebookAppId && config.facebookAppSecret) {
  passport.use(new FacebookStrategy({
    clientID: config.facebookAppId,
    clientSecret: config.facebookAppSecret,
    callbackURL: config.nodeEnv === 'production'
      ? 'https://www.freeontools.com/api/auth/facebook/callback'
      : 'http://localhost:3000/api/auth/facebook/callback',
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
      ? 'https://www.freeontools.com/api/auth/google/callback'
      : 'http://localhost:3000/api/auth/google/callback',
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

// Authentication Routes
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      console.log(`auth.js: Login attempt for non-existent email: ${email}`);
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    if (!user.password) {
      console.log(`auth.js: Login error: No password stored for user ${email} (likely social login)`);
      return res.status(400).json({ 
        message: 'This account uses social login (Google/Facebook). Please use the appropriate login method or reset your password.' 
      });
    }
    if (!user.isVerified) {
      console.log(`auth.js: Login failed for ${email}: Account not verified`);
      return res.status(403).json({ message: 'Please verify your email before logging in.' });
    }
    const isMatch = await user.comparePassword(password); // Use User model's method
    if (!isMatch) {
      console.log(`auth.js: Login failed for ${email}: Incorrect password`);
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const token = jwt.sign({ userId: user._id, email: user.email }, config.jwtSecret, { expiresIn: '1h' });
    req.session.userId = user._id;
    user.lastLogin = new Date();
    await user.save();
    console.log(`auth.js: Login successful for ${email}`);
    res.json({ token, message: 'Login successful' });
  } catch (error) {
    console.error('auth.js: Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    // Validate password length
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    user = new User({ name, email, password, isVerified: true }); // Set isVerified: true
    await user.save();
    const token = jwt.sign({ userId: user._id, email: user.email }, config.jwtSecret, { expiresIn: '1h' });
    req.session.userId = user._id;
    res.json({ token, message: 'Signup successful' });
  } catch (error) {
    console.error('auth.js: Signup error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log(`auth.js: Forgot password attempt for non-existent email: ${email}`);
      return res.status(404).json({ message: 'Email not found' });
    }
    const token = jwt.sign({ userId: user._id }, config.jwtSecret, { expiresIn: '1h' });
    const resetLink = `https://www.freeontools.com/reset-password.html?token=${encodeURIComponent(token)}`;
    await transporter.sendMail({
      from: `"FreeOnTools" <${config.emailUser}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.`
    });
    console.log(`auth.js: Password reset email sent to ${email}`);
    res.json({ message: 'Password reset link sent to your email' });
  } catch (error) {
    console.error('auth.js: Forgot password error:', error.message, error.stack);
    res.status(500).json({ message: 'Failed to send reset link. Please try again.', error: error.message });
  }
});

app.post('/api/validate-reset-token', async (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    const user = await User.findById(decoded.userId);
    if (!user) {
      console.log(`auth.js: Invalid reset token for user ID: ${decoded.userId}`);
      return res.status(400).json({ valid: false, message: 'Invalid or expired token' });
    }
    res.json({ valid: true, message: 'Token is valid' });
  } catch (error) {
    console.error('auth.js: Validate reset token error:', error);
    res.status(400).json({ valid: false, message: 'Invalid or expired token' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  console.log(`auth.js: Reset password attempt with token: ${token}`);
  try {
    if (!token) {
      console.log('auth.js: Reset password failed: No token provided');
      return res.status(400).json({ message: 'Token is required' });
    }
    const decoded = jwt.verify(token, config.jwtSecret);
    const user = await User.findById(decoded.userId).select('+password');
    if (!user) {
      console.log(`auth.js: Reset password failed: User not found for ID ${decoded.userId}`);
      return res.status(400).json({ message: 'Invalid or expired token' });
    }
    if (password.length < 8) {
      console.log(`auth.js: Reset password failed: Password too short for user ${user.email}`);
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }
    user.password = password; // Will be hashed by pre('save') hook
    await user.save();
    console.log(`auth.js: Password reset successful for ${user.email}`);
    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('auth.js: Reset password error:', error.message, error.stack);
    res.status(400).json({ message: 'Invalid or expired token', error: error.message });
  }
});

app.get('/auth/check', (req, res) => {
  if (req.session.userId) {
    res.json({ authenticated: true });
  } else {
    res.json({ authenticated: false });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('auth.js: Logout error:', err);
      return res.status(500).json({ message: 'Logout failed' });
    }
    res.json({ message: 'Logout successful' });
  });
});

// Facebook Auth Routes
app.get('/api/auth/facebook', passport.authenticate('facebook'));

app.get('/api/auth/facebook/callback', passport.authenticate('facebook', {
  failureRedirect: config.nodeEnv === 'production'
    ? 'https://www.freeontools.com/login.html'
    : 'http://localhost:8080/login.html'
}), (req, res) => {
  const token = jwt.sign({ userId: req.user._id, email: req.user.email }, config.jwtSecret, { expiresIn: '1h' });
  res.redirect(`https://www.freeontools.com/profile.html?token=${token}`);
});

// Google Auth Routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback', passport.authenticate('google', {
  failureRedirect: config.nodeEnv === 'production'
    ? 'https://www.freeontools.com/login.html'
    : 'http://localhost:8080/login.html'
}), (req, res) => {
  const token = jwt.sign({ userId: req.user._id, email: req.user.email }, config.jwtSecret, { expiresIn: '1h' });
  res.redirect(`https://www.freeontools.com/profile.html?token=${token}`);
});

// API Routes
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    environment: config.nodeEnv,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(400).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// MAIN ROUTING SOLUTION - Case-sensitive HTML file handling
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/auth/')) {
    return next();
  }
  if (req.path.includes('.')) {
    return next();
  }
  const htmlPath = path.join(staticPath, `${req.path}.html`);
  console.log(`Attempting to serve: ${htmlPath}`);
  if (fs.existsSync(htmlPath)) {
    console.log(`Serving HTML file: ${htmlPath}`);
    return res.sendFile(htmlPath);
  }
  console.log(`Serving Index.html from: ${indexPath}`);
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