const User = require("../models/User");
const LocalStrategy = require("passport-local");
const JWTStrategy = require("passport-jwt").Strategy;
const { fromAuthHeaderAsBearerToken } = require("passport-jwt").Strategy;
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

exports.jwtStrategy = new JWTStrategy(
  //EXTRACTS TOKEN
  {
    //taking jwt from the header
    jwtFromRequest: fromAuthHeaderAsBearerToken(),
    //using the secret key from .env
    secretOrKey: process.env.JWT_SECRET,
  },
  async (tokenPayload, done) => {
    //check has the token expired or not ?? // it will run evey time
    if (Date.now > tokenPayload.exp * 1000) {
      return done(null, false);
    }

    try {
      //valid token exp
      const user = await User.findById(tokenPayload._id);
      return done(null, user);
    } catch (error) {
      done(error, false);
    }
  }
);
