const express = require("express");
const { protect } = require("../middleware/authMiddleware.js");

const {
    addIncome,
    getAllIncome,
    deleteIncome,
    downloadIncomeExcel
} = require("../controllers/incomeController.js");

const router = express.Router();

router.post("/add-income", protect, addIncome);
router.get("/get-all-income", protect, getAllIncome);
router.get("/download-excel", protect, downloadIncomeExcel);
router.delete("/:id", protect, deleteIncome);

module.exports = router;
