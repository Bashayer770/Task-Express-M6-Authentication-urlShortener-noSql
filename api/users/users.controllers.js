const User = require("../../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const hashPassword = async (password) => {
  const saltRounds = 10;
  const hashPassword = await bcrypt.hash(password, saltRounds);
  return hashPassword;
};

const generateToken = (user) => {
  const payload = {
    _id: user._id,
    username: user.username,
  };
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "5h" });
  return token;
};

exports.signin = async (req, res) => {
  try {
    const token = await generateToken(req.user);
    res.status(200).json(token);
  } catch (err) {
    res.status(500).json("Server Error");
  }
};

exports.signup = async (req, res, next) => {
  try {
    const { password } = req.body;
    req.body.password = await hashPassword(password);
    const newUser = await User.create(req.body);
    const token = generateToken(newUser);
    res.status(201).json(token);
  } catch (err) {
    console.log(err.message);
    res.status(500).json("Server Error");
  }
};

exports.getUsers = async (req, res) => {
  try {
    const users = await User.find().populate("urls");
    res.status(201).json(users);
  } catch (err) {
    res.status(500).json("Server Error");
  }
};
