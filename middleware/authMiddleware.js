const jwt = require('jsonwebtoken');
const User = require("../models/User.model.js");

const protect = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Not authorised. No token.",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Not authorised. User does not exist.",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("JWT error:", error.message);
    return res.status(401).json({
      success: false,
      message: "Not authorised, token failed!",
    });
  }
};

module.exports = { protect };
