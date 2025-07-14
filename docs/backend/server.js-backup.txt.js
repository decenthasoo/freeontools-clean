const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const app = express();
const PORT = 3000;

// MongoDB connection
mongoose.connect(
  'mongodb+srv://decenthasoo:ZtpSoF8SzKCTlLVD@cluster0.0czsbhk.mongodb.net/freeontools?retryWrites=true&w=majority',
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
).then(() => console.log('server.js: MongoDB connected'))
  .catch(err => console.error('server.js: MongoDB connection error:', err.message));

// Middleware
app.use(express.json());
app.use(cors({
  origin: ['http://192.168.1.5:8080', 'http://127.0.0.1:8080'],
  credentials: true,
}));
app.use(session({
  secret: 'mySecret123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'none',
    maxAge: 24 * 60 * 60 * 1000,
  },
}));
app.use(passport.initialize());
app.use(passport.session());

// Passport Facebook Strategy
passport.use(new FacebookStrategy({
  clientID: '1934441037328664', // Replace with your Facebook App ID
  clientSecret: 'a25d6b18008859b3496672db7c7d8d23', // Replace with your Facebook App Secret
  callbackURL: 'https://8786-2401-4900-1c43-d988-e46f-10c4-b4a5-2763.ngrok-free.app/auth/facebook/callback',
  profileFields: ['id', 'emails', 'name'],
}, async (accessToken, refreshToken, profile, done) => {
  console.log('server.js: Facebook profile:', profile);
  try {
    let user = await User.findOne({ facebookId: profile.id });
    if (!user) {
      user = new User({
        facebookId: profile.id,
        email: profile.emails ? profile.emails[0].value : '',
        name: profile.displayName || '',
      });
      await user.save();
      console.log('server.js: New Facebook user created:', user.email);
    } else {
      console.log('server.js: Existing Facebook user found:', user.email);
    }
    return done(null, user);
  } catch (err) {
    console.error('server.js: Facebook auth error:', err);
    return done(err, null);
  }
}));

// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: '457747933042-vkue9p1e9qso38uohnmbpsoh566i5f0b.apps.googleusercontent.com',
  clientSecret: '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', // Replace with your Client Secret
  callbackURL: 'https://8786-2401-4900-1c43-d988-e46f-10c4-b4a5-2763.ngrok-free.app/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  console.log('server.js: Google profile:', profile);
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = new User({
        googleId: profile.id,
        email: profile.emails ? profile.emails[0].value : '',
        name: profile.displayName || '',
      });
      await user.save();
      console.log('server.js: New Google user created:', user.email);
    } else {
      console.log('server.js: Existing Google user found:', user.email);
    }
    return done(null, user);
  } catch (err) {
    console.error('server.js: Google auth error:', err);
    return done(err, null);
  }
}));

// Passport serialize/deserialize
passport.serializeUser((user, done) => {
  console.log('server.js: Serializing user:', user._id);
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    console.log('server.js: Deserializing user:', user ? user.email : 'Not found');
    done(null, user);
  } catch (err) {
    console.error('server.js: Deserialization error:', err);
    done(err, null);
  }
});

// Routes
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  console.log('server.js: Signup attempt for email:', email);
  try {
    let user = await User.findOne({ email });
    if (user) {
      console.log('server.js: Signup failed - User already exists:', email);
      return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({ name, email, password: hashedPassword });
    await user.save();
    console.log('server.js: User created:', email);
    const token = jwt.sign({ userId: user._id }, 'FreeonToolsSecret123!', { expiresIn: '1h' });
    req.login(user, (err) => {
      if (err) {
        console.error('server.js: Auto-login after signup failed:', err);
        return res.status(500).json({ message: 'Auto-login failed', error: err.message });
      }
      console.log('server.js: Auto-login successful for:', email);
      res.status(201).json({ token, message: 'Signup and login successful' });
    });
  } catch (err) {
    console.error('server.js: Signup error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('server.js: Login attempt for email:', email);
  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log('server.js: Login failed - User not found:', email);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!user.password || !isMatch) {
      console.log('server.js: Login failed - Invalid password for:', email);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    console.log('server.js: Login successful for:', email);
    const token = jwt.sign({ userId: user._id }, 'FreeonToolsSecret123!', { expiresIn: '1h' });
    req.login(user, (err) => {
      if (err) {
        console.error('server.js: Login failed:', err);
        return res.status(500).json({ message: 'Login failed', error: err.message });
      }
      res.json({ token, message: 'Login successful' });
    });
  } catch (err) {
    console.error('server.js: Login error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: 'http://192.168.1.5:8080/login.html' }),
  (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, 'FreeonToolsSecret123!', { expiresIn: '1h' });
    console.log('server.js: Facebook login successful, generated token for user:', req.user.email);
    res.redirect(`http://192.168.1.5:8080/profile.html?token=${token}`);
  }
);

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: 'http://192.168.1.5:8080/login.html' }),
  (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, 'FreeonToolsSecret123!', { expiresIn: '1h' });
    console.log('server.js: Google login successful, generated token for user:', req.user.email);
    res.redirect(`http://192.168.1.5:8080/profile.html?token=${token}`);
  }
);

app.get('/auth/check', (req, res) => {
  console.log('server.js: /auth/check - Session:', req.session);
  console.log('server.js: /auth/check - User:', req.user);
  if (req.isAuthenticated()) {
    console.log('server.js: /auth/check - User authenticated:', req.user.email);
    res.json({ authenticated: true, user: req.user });
  } else {
    console.log('server.js: /auth/check - User not authenticated');
    res.json({ authenticated: false });
  }
});

app.post('/logout', (req, res) => {
  console.log('server.js: Logout requested');
  req.logout((err) => {
    if (err) {
      console.error('server.js: Logout error:', err);
      return res.status(500).json({ message: 'Logout failed', error: err.message });
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('server.js: Session destroy error:', err);
        return res.status(500).json({ message: 'Logout failed', error: err.message });
      }
      console.log('server.js: Logout successful, session destroyed');
      res.json({ message: 'Logged out successfully' });
    });
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => console.log(`server.js: Server running on port ${PORT}`));