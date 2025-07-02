// 1. Load Environment Variables FIRST
require('dotenv').config();

// 2. Import ALL Required Modules
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

// 3. Initialize Express App
const app = express();
const PORT = process.env.PORT || 10000;

// 4. Configuration Setup
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

// 5. Critical Startup Checks
console.log('=== Starting Server Checks ===');

// 5.1 Validate Required Environment Variables
if (!config.jwtSecret || !config.sessionSecret) {
  console.error('\x1b[31mCRITICAL ERROR: Missing required secrets\x1b[0m');
  console.error('- JWT_SECRET/JMT_SECRET:', config.jwtSecret ? '✅ Found' : '❌ Missing');
  console.error('- SESSION_SECRET:', config.sessionSecret ? '✅ Found' : '❌ Missing');
  process.exit(1);
}

// 5.2 Verify MongoDB Connection String
if (!config.mongoURI) {
  console.error('\x1b[31mCRITICAL ERROR: Missing MongoDB connection string\x1b[0m');
  process.exit(1);
}

// 6. Middleware Setup

// 6.1 Trust Proxy (Important for HTTPS in production)
app.set('trust proxy', 1);

// 6.2 CORS Configuration
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

// 6.3 Body Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 7. Static File Serving (Fixed for Render.com)
const staticPath = path.join(__dirname, process.env.NODE_ENV === 'production' ? '../..' : '..');
console.log('Static files path:', staticPath);

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

// 8. Redirect Middleware
app.use((req, res, next) => {
  const host = req.hostname;
  const url = req.url;

  // 8.1 Redirect naked domain to www
  if (host === 'freeontools.com') {
    return res.redirect(301, `https://www.freeontools.com${url}`);
  }

  // 8.2 Remove .html extensions
  if (url.endsWith('.html')) {
    return res.redirect(301, url.replace(/\.html$/, ''));
  }

  // 8.3 Remove trailing slashes
  if (url.endsWith('/') && url !== '/') {
    return res.redirect(301, url.replace(/\/$/, ''));
  }

  next();
});

// 9. Session Configuration
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

// 10. Passport Setup
app.use(passport.initialize());
app.use(passport.session());

// 10.1 Serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// 10.2 Deserialization
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// 11. Database Connection
console.log('\n=== Database Connection ===');
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

// 12. Email Setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.emailUser,
    pass: config.emailPass
  }
});

// 13. OAuth Strategies

// 13.1 Facebook Strategy
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
      done(null, user);
    } catch (err) {
      done(err);
    }
  }));
  console.log('\x1b[32mFacebook OAuth initialized\x1b[0m');
} else {
  console.log('\x1b[33mFacebook OAuth disabled (missing credentials)\x1b[0m');
}

// 13.2 Google Strategy
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
      done(null, user);
    } catch (err) {
      done(err);
    }
  }));
  console.log('\x1b[32mGoogle OAuth initialized\x1b[0m');
} else {
  console.log('\x1b[33mGoogle OAuth disabled (missing credentials)\x1b[0m');
}

// 14. Routes

// 14.1 Health Check
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: config.nodeEnv
  });
});

// 14.2 Debug Route
app.get('/debug', (req, res) => {
  res.json({
    server: {
      environment: config.nodeEnv,
      port: PORT,
      staticFilesPath: staticPath,
      uptime: process.uptime()
    },
    auth: {
      facebook: !!config.facebookAppId,
      google: !!config.googleClientId
    },
    database: {
      connected: mongoose.connection.readyState === 1
    }
  });
});

// 14.3 Facebook Auth Routes
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

// 14.4 Google Auth Routes
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

// 14.5 API Routes
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 15. Dynamic Route Handling (for SPA)
app.get('*', (req, res) => {
  const requestedPath = req.path === '/' ? 'index.html' : `${req.path.replace(/^\//, '')}.html`;
  const fullPath = path.join(staticPath, requestedPath);
  
  fs.access(fullPath, fs.constants.F_OK, (err) => {
    if (err) {
      console.log(`File not found: ${fullPath}, serving index.html`);
      return res.sendFile(path.join(staticPath, 'index.html'));
    }
    res.sendFile(fullPath);
  });
});

// 16. Error Handling
app.use((err, req, res, next) => {
  console.error('\x1b[31mSERVER ERROR:\x1b[0m', err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: config.nodeEnv === 'development' ? err.message : 'Something went wrong'
  });
});

// 17. Server Startup
const server = app.listen(PORT, () => {
  console.log('\n\x1b[36m=== Server Successfully Started ===\x1b[0m');
  console.log(`\x1b[32mMode:\x1b[0m ${config.nodeEnv}`);
  console.log(`\x1b[32mPort:\x1b[0m ${PORT}`);
  console.log(`\x1b[32mFrontend:\x1b[0m https://www.freeontools.com`);
  console.log(`\x1b[32mDatabase:\x1b[0m ${config.mongoURI.split('@')[1]}`);
  console.log(`\x1b[32mStatic Files:\x1b[0m ${staticPath}`);
  console.log('\x1b[36m=== Ready for Connections ===\x1b[0m\n');
});

// 18. Server Error Handling
server.on('error', (error) => {
  console.error('\x1b[31mSERVER STARTUP FAILED:\x1b[0m', error);
  if (error.code === 'EADDRINUSE') {
    console.error(`\x1b[31mPort ${PORT} is already in use\x1b[0m`);
  }
  process.exit(1);
});

// 19. Process Termination Handling
process.on('SIGTERM', () => {
  console.log('\x1b[33mSIGTERM received. Shutting down gracefully...\x1b[0m');
  server.close(() => {
    console.log('\x1b[32mServer closed\x1b[0m');
    mongoose.connection.close(false, () => {
      console.log('\x1b[32mDatabase connection closed\x1b[0m');
      process.exit(0);
    });
  });
});