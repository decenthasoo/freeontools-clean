require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('./models/User');

const app = express();
const PORT = 3000;

// Validate environment variables
if (!process.env.NGROK_URL || !process.env.NGROK_URL.startsWith('https://')) {
    console.error('server.js: Invalid or missing NGROK_URL in .env');
    process.exit(1);
}
if (!process.env.JWT_SECRET || !process.env.SESSION_SECRET) {
    console.error('server.js: Missing JWT_SECRET or SESSION_SECRET in .env');
    process.exit(1);
}
if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.error('server.js: Missing GMAIL_USER or GMAIL_PASS in .env');
    process.exit(1);
}

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('server.js: MongoDB connected');
    // Ensure index on email for faster queries
    User.collection.createIndex({ email: 1 }, { unique: true, sparse: true }, (err) => {
        if (err) {
            console.error('server.js: Failed to create index on email:', err.message);
        } else {
            console.log('server.js: Index created on email field');
        }
    });
}).catch(err => console.error('server.js: MongoDB connection error:', err.message));

// Nodemailer Transport
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
    }
});

// Middleware
app.use(cors({
    origin: 'http://127.0.0.1:8080',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Log response headers for CORS debugging
app.use((req, res, next) => {
    const originalSetHeader = res.setHeader;
    res.setHeader = function (key, value) {
        console.log(`server.js: Setting header ${key}: ${value}`);
        originalSetHeader.call(this, key, value);
    };
    next();
});

// Handle OPTIONS preflight requests
app.options('*', cors({
    origin: 'http://127.0.0.1:8080',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,
    },
}));
app.use(passport.initialize());
app.use(passport.session());

// Passport Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: `${process.env.NGROK_URL}/auth/facebook/callback`,
    profileFields: ['id', 'emails', 'name'],
}, async (accessToken, refreshToken, profile, done) => {
    console.log('server.js: Facebook profile:', profile.id);
    try {
        let user = await User.findOne({
            $or: [
                { facebookId: profile.id },
                { email: profile.emails ? profile.emails[0].value : '' },
            ],
        });
        if (!user) {
            user = new User({
                facebookId: profile.id,
                email: profile.emails ? profile.emails[0].value : '',
                name: profile.displayName || '',
            });
            await user.save();
            console.log('server.js: New Facebook user created:', user.email);
        } else {
            if (!user.facebookId) {
                user.facebookId = profile.id;
                await user.save();
                console.log('server.js: Linked Facebook account to existing user:', user.email);
            } else {
                console.log('server.js: Existing Facebook user found:', user.email);
            }
        }
        return done(null, user);
    } catch (err) {
        console.error('server.js: Facebook auth error:', err.message, err.stack);
        return done(err);
    }
}));

// Passport Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.NGROK_URL}/auth/google/callback`,
}, async (accessToken, refreshToken, profile, done) => {
    console.log('server.js: Google profile:', profile.id);
    try {
        let user = await User.findOne({
            $or: [
                { googleId: profile.id },
                { email: profile.emails ? profile.emails[0].value : '' },
            ],
        });
        if (!user) {
            user = new User({
                googleId: profile.id,
                email: profile.emails ? profile.emails[0].value : '',
                name: profile.displayName || '',
            });
            await user.save();
            console.log('server.js: New Google user created:', user.email);
        } else {
            if (!user.googleId) {
                user.googleId = profile.id;
                await user.save();
                console.log('server.js: Linked Google account to existing user:', user.email);
            } else {
                console.log('server.js: Existing Google user found:', user.email);
            }
        }
        return done(null, user);
    } catch (err) {
        console.error('server.js: Google auth error:', err.message, err.stack);
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
        console.error('server.js: Deserialization error:', err.message, err.stack);
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
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        req.login(user, (err) => {
            if (err) {
                console.error('server.js: Auto-login after signup failed:', err.message, err.stack);
                return res.status(500).json({ message: 'Auto-login failed', error: err.message });
            }
            console.log('server.js: Auto-login successful for:', email);
            res.status(201).json({ token, message: 'Signup and login successful' });
        });
    } catch (err) {
        console.error('server.js: Signup error:', err.message, err.stack);
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
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        req.login(user, (err) => {
            if (err) {
                console.error('server.js: Login failed:', err.message, err.stack);
                return res.status(500).json({ message: 'Login failed', error: err.message });
            }
            res.json({ token, message: 'Login successful' });
        });
    } catch (err) {
        console.error('server.js: Login error:', err.message, err.stack);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: 'http://127.0.0.1:8080/login.html' }),
    (req, res) => {
        const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('server.js: Facebook login successful, generated token for user:', req.user.email);
        res.redirect(`http://127.0.0.1:8080/profile.html?token=${token}`);
    }
);

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: 'http://127.0.0.1:8080/login.html' }),
    (req, res) => {
        const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('server.js: Google login successful, generated token for user:', req.user.email);
        res.redirect(`http://127.0.0.1:8080/profile.html?token=${token}`);
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
            console.error('server.js: Logout error:', err.message, err.stack);
            return res.status(500).json({ message: 'Logout failed', error: err.message });
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('server.js: Session destroy error:', err.message, err.stack);
                return res.status(500).json({ message: 'Logout failed', error: err.message });
            }
            console.log('server.js: Logout successful, session destroyed');
            res.json({ message: 'Logged out successfully' });
        });
    });
});

app.post('/api/forgot-password', async (req, res) => {
    const startTime = Date.now();
    console.log('server.js: Forgot password request started at:', new Date().toISOString());
    const { email } = req.body;
    console.log('server.js: Forgot password request for email:', email);
    try {
        if (!email) {
            console.log('server.js: Missing email in request');
            return res.status(400).json({ message: 'Email is required' });
        }

        // Measure MongoDB query time
        const queryStart = Date.now();
        const user = await User.findOne({ email });
        console.log('server.js: MongoDB query took:', Date.now() - queryStart, 'ms');

        if (!user) {
            console.log('server.js: User not found:', email);
            return res.status(404).json({ message: 'User not found' });
        }
        console.log('server.js: User found:', user.email);

        // Generate and save token
        const tokenStart = Date.now();
        const now = new Date();
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        user.resetPasswordToken = token;
        user.resetPasswordExpires = new Date(now.getTime() + 3600000);
        await user.save();
        console.log('server.js: Token generation and save took:', Date.now() - tokenStart, 'ms');
        console.log('server.js: User updated with reset token:', {
            email: user.email,
            resetPasswordToken: user.resetPasswordToken,
            resetPasswordExpires: user.resetPasswordExpires.toISOString()
        });

        // Send email
        const emailStart = Date.now();
        const resetUrl = `http://127.0.0.1:8080/reset-password.html?token=${encodeURIComponent(token)}`;
        const mailOptions = {
            from: process.env.GMAIL_USER,
            to: email,
            subject: 'FreeonTools Password Reset',
            text: `Click this link to reset your password: ${resetUrl}\nThis link expires in 1 hour.`,
        };
        await transporter.sendMail(mailOptions);
        console.log('server.js: Email sending took:', Date.now() - emailStart, 'ms');
        console.log('server.js: Reset email sent to:', email);

        console.log('server.js: Forgot password request completed in:', Date.now() - startTime, 'ms');
        res.status(200).json({ message: 'Reset link sent to your email' });
    } catch (error) {
        console.error('server.js: Forgot password error:', error.message, error.stack);
        console.log('server.js: Forgot password request failed after:', Date.now() - startTime, 'ms');
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { token, password } = req.body;
    console.log('server.js: Reset password request with token, length:', token ? token.length : 'null', 'value:', token);
    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: new Date() },
        });
        console.log('server.js: User lookup result:', user ? {
            email: user.email,
            resetPasswordToken: user.resetPasswordToken,
            resetPasswordExpires: user.resetPasswordExpires.toISOString()
        } : 'No user found');
        if (!user) {
            console.log('server.js: Invalid or expired token');
            return res.status(400).json({ message: 'Invalid or expired token' });
        }
        console.log('server.js: User found for reset:', user.email);
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        console.log('server.js: Password reset successful for:', user.email);
        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('server.js: Reset password error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/validate-reset-token', async (req, res) => {
    const { token } = req.body;
    console.log('server.js: Validating reset token, length:', token ? token.length : 'null', 'value:', token);
    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: new Date() },
        });
        console.log('server.js: User lookup result:', user ? {
            email: user.email,
            resetPasswordToken: user.resetPasswordToken,
            resetPasswordExpires: user.resetPasswordExpires.toISOString()
        } : 'No user found');
        if (!user) {
            console.log('server.js: Invalid or expired reset token');
            return res.status(400).json({ valid: false, message: 'Invalid or expired token' });
        }
        console.log('server.js: Valid reset token for user:', user.email);
        res.status(200).json({ valid: true });
    } catch (error) {
        console.error('server.js: Validate reset token error:', error.message, error.stack);
        res.status(500).json({ valid: false, message: 'Server error' });
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => console.log(`server.js: Server running on port ${PORT}`));