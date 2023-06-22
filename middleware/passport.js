const User = require("../models/User");
const LocalStrategy = require("passport-local");
const bcrypt = require("bcrypt");

exports.localStrategy = new LocalStrategy(
  { usernameField: "username" },
  async (username, password, done) => {
    try {
      const foundUser = await User.findOne({ username: username });
      if (!foundUser) {
        return done(null, false);
      }
      const passwordMath = await bcrypt.compare(password, foundUser.password);
      if (!passwordMath) {
        return done(null, false);
      }
      return done(null, foundUser);
    } catch (error) {
      return done(error);
    }
  }
);
