const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

class AuthController {

  static async register(req, res) {
    try {
      const { name, email, password } = req.body;

      const userExist = await User.findOne({ email });
      if (userExist) {
        return res.status(400).json({ message: "User already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await User.create({
        name,
        email,
        password: hashedPassword,
      });

      res.json({ message: "User registered successfully", user });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }


  static async login(req, res) {
    try {
      const { email, password, secretKey } = req.body;


      if (secretKey !== process.env.CUSTOM_SECRET_KEY) {
        return res.status(401).json({ message: "Invalid Secret Key" });
      }

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: "User not found" });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      const token = jwt.sign(
        { id: user._id },
        process.env.JWT_SECRET,
        { expiresIn: "12h" }
      );

      res.json({
        message: "Login successful",
        token,
        secretKey: process.env.CUSTOM_SECRET_KEY, // return korchi test er jonno
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }

  // DASHBOARD (TOKEN + SECRET KEY BOTH REQUIRED)
  static async dashboard(req, res) {
    try {
      res.json({
        message: "Welcome to Dashboard",
        user: req.user,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
}

module.exports = AuthController;