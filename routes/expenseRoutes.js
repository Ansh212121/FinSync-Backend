const express = require('express');
const { protect } = require('../middleware/authMiddleware.js');

const router = express.Router();
const {
    addExpense,
    getAllExpense,
    deleteExpense,
    downloadExpenseExcel
} = require('../controllers/expenseController.js');

router.post('/add-expense', protect, addExpense);
router.get('/get-all-expense', protect, getAllExpense);
router.get('/download-excel', protect, downloadExpenseExcel);
router.delete('/:id', protect, deleteExpense);

module.exports = router;