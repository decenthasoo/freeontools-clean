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

// Configuration with enhanced defaults
const config = {
  jwtSecret: process.env.JWT_SECRET || 'default-secret-change-in-production',
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

// 1. PATH CONFIGURATION FOR RENDER.COM
const staticPath = path.join(__dirname, '../..'); // Points to /opt/render/project
console.log('\n=== Server Initialization ===');
console.log('Environment:', config.nodeEnv);
console.log('Static files path:', staticPath);

// 2. VERIFY FILES EXIST
try {
  const files = fs.readdirSync(staticPath);
  console.log('Found', files.length, 'files in root directory');
  
  if (!fs.existsSync(path.join(staticPath, 'index.html'))) {
    console.error('\x1b[31mERROR: index.html not found in root directory\x1b[0m');
    console.log('First 10 files:', files.slice(0, 10));
    process.exit(1);
  }
} catch (err) {
  console.error('\x1b[31mERROR: Could not read static directory\x1b[0m', err);
  process.exit(1);
}

// 3. MIDDLEWARE SETUP
app.set('trust proxy', 1);

// Enhanced CORS
app.use(cors({
  origin: [
    'https://www.freeontools.com',
    'https://freeontools.com',
    'http://localhost:8080'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files with proper caching
app.use(express.static(staticPath, {
  maxAge: '1y',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

// Redirect middleware
app.use((req, res, next) => {
  // Redirect naked domain to www
  if (req.hostname === 'freeontools.com') {
    return res.redirect(301, `https://www.freeontools.com${req.url}`);
  }
  next();
});

// Session with production settings
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
    domain: config.nodeEnv === 'production' ? '.freeontools.com' : undefined
  }
}));

// Passport initialization
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

// 4. DATABASE CONNECTION WITH RETRY
const connectWithRetry = () => {
  mongoose.connect(config.mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 30000
  })
  .then(() => console.log('\x1b[32mMongoDB connected successfully\x1b[0m'))
  .catch(err => {
    console.error('\x1b[31mMongoDB connection failed, retrying in 5s...\x1b[0m', err.message);
    setTimeout(connectWithRetry, 5000);
  });
};
connectWithRetry();

// 5. OAUTH STRATEGIES (COMPLETE IMPLEMENTATIONS)
if (config.facebookAppId && config.facebookAppSecret) {
  passport.use(new FacebookStrategy({
    clientID: config.facebookAppId,
    clientSecret: config.facebookAppSecret,
    callbackURL: `${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:3000'}/auth/facebook/callback`,
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

if (config.googleClientId && config.googleClientSecret) {
  passport.use(new GoogleStrategy({
    clientID: config.googleClientId,
    clientSecret: config.googleClientSecret,
    callbackURL: `${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:3000'}/auth/google/callback`,
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

// 6. ROUTES
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    environment: config.nodeEnv,
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// Auth routes (Facebook and Google implementations)
app.get('/auth/facebook', passport.authenticate('facebook'));
app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { 
    failureRedirect: `${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:8080'}/login`,
    session: true
  }),
  (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, config.jwtSecret, { expiresIn: '1h' });
    res.redirect(`${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:8080'}/profile?token=${token}`);
  }
);

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: `${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:8080'}/login`,
    session: true
  }),
  (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, config.jwtSecret, { expiresIn: '1h' });
    res.redirect(`${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:8080'}/profile?token=${token}`);
  }
);

// 7. DYNAMIC ROUTE HANDLING
app.get('*', (req, res) => {
  const basePath = req.path === '/' ? 'index.html' : `${req.path.replace(/^\//, '')}.html`;
  const filePath = path.join(staticPath, basePath);

  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      // Fallback to index.html for SPA routing
      return res.sendFile(path.join(staticPath, 'index.html'));
    }
    res.sendFile(filePath);
  });
});

// 8. ERROR HANDLING
app.use((err, req, res, next) => {
  console.error('\x1b[31mSERVER ERROR:\x1b[0m', err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: config.nodeEnv === 'development' ? err.message : undefined
  });
});

// 9. SERVER STARTUP WITH HEALTH CHECKS
const server = app.listen(PORT, () => {
  console.log('\n\x1b[36m=== Server Started ===\x1b[0m');
  console.log(`\x1b[32mPort:\x1b[0m ${PORT}`);
  console.log(`\x1b[32mEnvironment:\x1b[0m ${config.nodeEnv}`);
  console.log(`\x1b[32mDatabase:\x1b[0m ${config.mongoURI.split('@')[1] || config.mongoURI}`);
  console.log('\x1b[36m=== Ready ===\x1b[0m\n');
});

// 10. PROCESS HANDLERS
server.on('error', (error) => {
  console.error('\x1b[31mSERVER ERROR:\x1b[0m', error);
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('\x1b[33mShutting down...\x1b[0m');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('\x1b[32mServer stopped\x1b[0m');
      process.exit(0);
    });
  });
});