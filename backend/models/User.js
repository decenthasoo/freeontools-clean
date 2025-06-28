const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
    facebookId: { type: String, unique: true, sparse: true },
    googleId: { type: String, unique: true, sparse: true },
    email: { type: String, unique: true, sparse: true },
    name: { type: String },
    password: { type: String },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
});
module.exports = mongoose.model('User', userSchema);