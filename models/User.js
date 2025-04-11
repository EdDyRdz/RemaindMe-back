const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    mfaSecret: { type: String },
    mfaEnabled: { type: Boolean, default: true },
    last_login: { type: Date },
});

const User = mongoose.model("User", UserSchema);

module.exports = User;