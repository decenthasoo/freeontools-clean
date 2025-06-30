const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    facebookId: { type: String, unique: true, sparse: true },
    googleId: { type: String, unique: true, sparse: true },
    email: { 
        type: String, 
        unique: true, 
        sparse: true,
        validate: {
            validator: function(v) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: props => `${props.value} is not a valid email address!`
        }
    },
    name: { type: String, trim: true },
    password: { 
        type: String,
        minlength: [8, 'Password must be at least 8 characters long'],
        select: false
    },
    resetPasswordToken: { type: String, select: false },
    resetPasswordExpires: { type: Date, select: false },
    isVerified: { type: Boolean, default: false },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Index definitions (matches your existing indexes)
userSchema.index({ email: 1 }, { 
    unique: true, 
    sparse: true,
    name: "email_1"
});

userSchema.index({ facebookId: 1 }, { 
    unique: true, 
    sparse: true,
    name: "facebookId_1" 
});

userSchema.index({ googleId: 1 }, { 
    unique: true, 
    sparse: true,
    name: "googleId_1" 
});

// Password hashing middleware (preserves existing functionality)
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (err) {
        next(err);
    }
});

// Method to compare passwords (preserves existing functionality)
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);