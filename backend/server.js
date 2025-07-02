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

// Configuration with defaults
const config = {
  jwtSecret: process.env.JWT_SECRET || 'default_jwt_secret_please_change',
  sessionSecret: process.env.SESSION_SECRET || 'default_session_secret_please_change',
  mongoURI: process.env.MONGO_URI || 'mongodb://localhost:27017/freeontools',
  emailUser: process.env.EMAIL_USER || 'your-email@example.com',
  emailPass: process.env.EMAIL_PASS || 'your-email-password',
  nodeEnv: process.env.NODE_ENV || 'production',
  facebookAppId: process.env.FACEBOOK_APP_ID,
  facebookAppSecret: process.env.FACEBOOK_APP_SECRET,
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET
};

// Path configuration for Render.com vs local development
const isRender = process.env.RENDER === 'true';
const staticPath = path.join(__dirname, isRender ? '../../client' : '../client');

console.log('\n=== Server Initialization ===');
console.log('Environment:', config.nodeEnv);
console.log('Static files path:', staticPath);

// Verify static directory exists
if (!fs.existsSync(staticPath)) {
  console.error('\x1b[31mERROR: Static files directory not found at:', staticPath, '\x1b[0m');
  console.log('Current directory structure:', fs.readdirSync(path.dirname(staticPath)));
  process.exit(1);
}

// Verify index.html exists
const indexPath = path.join(staticPath, 'index.html');
if (!fs.existsSync(indexPath)) {
  console.error('\x1b[31mERROR: index.html not found in static directory\x1b[0m');
  console.log('Files in static directory:', fs.readdirSync(staticPath));
  process.exit(1);
}

// Middleware Setup
app.set('trust proxy', 1);

// Enhanced CORS Configuration
const corsOptions = {
  origin: [
    'https://www.freeontools.com',
    'https://freeontools.com',
    'http://localhost:8080'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};
app.use(cors(corsOptions));

// Body parsers with increased limit
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static file serving with proper caching
app.use(express.static(staticPath, {
  maxAge: isRender ? '1y' : 0,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

// Redirect and security middleware
app.use((req, res, next) => {
  // Redirect naked domain to www
  if (req.hostname === 'freeontools.com') {
    return res.redirect(301, `https://www.freeontools.com${req.url}`);
  }

  // Security headers
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

  next();
});

// Session configuration with production settings
const sessionConfig = {
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
};

if (config.nodeEnv === 'production') {
  sessionConfig.cookie.domain = '.freeontools.com';
}

app.use(session(sessionConfig));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Passport deserialization
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Database connection with retry logic
const connectWithRetry = () => {
  mongoose.connect(config.mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 30000
  })
  .then(() => console.log('\x1b[32mMongoDB connected successfully\x1b[0m'))
  .catch(err => {
    console.error('\x1b[31mMongoDB connection failed, retrying in 5 seconds...\x1b[0m', err.message);
    setTimeout(connectWithRetry, 5000);
  });
};

connectWithRetry();

// Email transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.emailUser,
    pass: config.emailPass
  }
});

transporter.verify((error) => {
  if (error) {
    console.error('\x1b[31mEmail transporter verification failed:\x1b[0m', error);
  } else {
    console.log('\x1b[32mEmail transporter ready\x1b[0m');
  }
});

// Facebook OAuth Strategy (complete implementation)
if (config.facebookAppId && config.facebookAppSecret) {
  passport.use(new FacebookStrategy({
    clientID: config.facebookAppId,
    clientSecret: config.facebookAppSecret,
    callbackURL: `${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:3000'}/auth/facebook/callback`,
    profileFields: ['id', 'emails', 'name', 'displayName'],
    enableProof: true
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

// Google OAuth Strategy (complete implementation)
if (config.googleClientId && config.googleClientSecret) {
  passport.use(new GoogleStrategy({
    clientID: config.googleClientId,
    clientSecret: config.googleClientSecret,
    callbackURL: `${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:3000'}/auth/google/callback`,
    scope: ['profile', 'email'],
    prompt: 'select_account'
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

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memoryUsage: process.memoryUsage()
  });
});

// Debug endpoint
app.get('/api/debug', (req, res) => {
  res.json({
    server: {
      environment: config.nodeEnv,
      port: PORT,
      staticPath,
      files: fs.readdirSync(staticPath),
      indexExists: fs.existsSync(indexPath)
    },
    auth: {
      facebook: !!config.facebookAppId,
      google: !!config.googleClientId
    },
    database: {
      connected: mongoose.connection.readyState === 1,
      host: mongoose.connection?.host || 'disconnected'
    },
    process: {
      version: process.version,
      platform: process.platform,
      memory: process.memoryUsage()
    }
  });
});

// Facebook auth routes
app.get('/auth/facebook', passport.authenticate('facebook', {
  scope: ['email'],
  authType: 'rerequest'
}));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { 
    failureRedirect: config.nodeEnv === 'production'
      ? 'https://www.freeontools.com/login?error=auth_failed'
      : 'http://localhost:8080/login?error=auth_failed',
    session: true
  }),
  (req, res) => {
    const token = jwt.sign({ 
      userId: req.user._id,
      email: req.user.email
    }, config.jwtSecret, { expiresIn: '1h' });
    
    const redirectUrl = `${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:8080'}/profile`;
    res.redirect(`${redirectUrl}?token=${token}&auth=facebook`);
  }
);

// Google auth routes
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
  prompt: 'select_account'
}));

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: config.nodeEnv === 'production'
      ? 'https://www.freeontools.com/login?error=auth_failed'
      : 'http://localhost:8080/login?error=auth_failed',
    session: true
  }),
  (req, res) => {
    const token = jwt.sign({ 
      userId: req.user._id,
      email: req.user.email
    }, config.jwtSecret, { expiresIn: '1h' });
    
    const redirectUrl = `${config.nodeEnv === 'production' ? 'https://www.freeontools.com' : 'http://localhost:8080'}/profile`;
    res.redirect(`${redirectUrl}?token=${token}&auth=google`);
  }
);

// Sample protected API route
app.get('/api/user', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -__v');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Catch-all route for SPA
app.get('*', (req, res) => {
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  res.status(404).sendFile(path.join(staticPath, '404.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('\x1b[31mERROR:\x1b[0m', err.stack);
  
  const status = err.status || 500;
  const message = config.nodeEnv === 'development' ? err.message : 'An error occurred';
  
  res.status(status).json({
    error: {
      status,
      message,
      ...(config.nodeEnv === 'development' && { stack: err.stack })
    }
  });
});

// Server startup
const server = app.listen(PORT, () => {
  console.log('\n\x1b[36m=== Server Successfully Started ===\x1b[0m');
  console.log(`\x1b[32mPort:\x1b[0m ${PORT}`);
  console.log(`\x1b[32mEnvironment:\x1b[0m ${config.nodeEnv}`);
  console.log(`\x1b[32mFrontend URL:\x1b[0m https://www.freeontools.com`);
  console.log(`\x1b[32mDatabase:\x1b[0m ${config.mongoURI.split('@')[1] || config.mongoURI}`);
  console.log(`\x1b[32mStatic Files Path:\x1b[0m ${staticPath}`);
  console.log('\x1b[36m=== Ready for Connections ===\x1b[0m\n');
});

// Server error handling
server.on('error', (error) => {
  console.error('\x1b[31mSERVER STARTUP ERROR:\x1b[0m', error);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\x1b[33mSIGTERM received. Shutting down gracefully...\x1b[0m');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('\x1b[32mServer stopped\x1b[0m');
      process.exit(0);
    });
  });
});

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('\x1b[31mUnhandled Rejection at:\x1b[0m', promise, '\x1b[31mreason:\x1b[0m', reason);
});

// Uncaught exception handler
process.on('uncaughtException', (err) => {
  console.error('\x1b[31mUncaught Exception:\x1b[0m', err.stack);
  process.exit(1);
});