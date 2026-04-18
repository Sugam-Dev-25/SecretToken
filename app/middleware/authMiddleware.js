const jwt = require("jsonwebtoken");
const User = require("../models/User");

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    const secretKey = req.headers["x-secret-key"];


    if (!token || !secretKey) {
      return res.status(401).json({
        message: "Token and Secret Key required",
      });
    }


    if (secretKey !== process.env.CUSTOM_SECRET_KEY) {
      return res.status(401).json({
        message: "Invalid Secret Key",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    req.user = user;

    next();
  } catch (err) {
    res.status(401).json({ message: "Unauthorized" });
  }
};

module.exports = authMiddleware;