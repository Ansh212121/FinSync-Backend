const express = require('express');
const { protect } = require("../middleware/authMiddleware.js")
const {
    registerUser,
    loginUser,
    logoutUser,
    getUserInfo,
    updateProfileImageUrl
} = require("../controllers/authController.js");
const upload = require("../middleware/uploadMiddleware.js")

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/logout', logoutUser);
router.get('/getUser', protect, getUserInfo);
router.post('/updateProfileImageUrl', protect, updateProfileImageUrl);

router.post("/upload-image", upload.single("image"), (req,res) => {
    if(!req.file){
        return res.status(400).json({
            success:false,
            message:"No file uploaded!"
        })
    }
    const imageUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
    return res.status(200).json({
        success:true,
        message:"Image uploaded successfully!",
        imageUrl
    })
} )

module.exports = router;