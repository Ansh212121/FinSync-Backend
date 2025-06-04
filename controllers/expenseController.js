const express = require("express");
const xlsx = require("xlsx");
const User = require("../models/User.model.js");
const Expense = require("../models/Expense.model.js");

//add expense
const addExpense = async (req, res) => {
    const userId = req.user.id;
    try {
        const {category ,amount , icon, date} = req.body;
        if(!category || !amount || !date){
            return res.status(400).json({
                success:false,
                message:"All fields are required!",
            });
        }
        const expense = await Expense.create({
            userId,
            icon,
            category,
            amount,
            date: new Date(date)
        });
        res.status(200).json({
            success:true,
            message:"Expense added successfully!",
            expense
        })
    } catch (error) {
        return res.staus(500).json({
            success: false,
            message:"Failed adding expense !",
        })
    }
}
//get all expense
const getAllExpense = async (req, res) => {
    const userId  = req.user.id;
    try {
        const expense = await Expense.find({userId}).sort({date: -1});
        res.status(200).json({
            success:true,
            message:"Expense fetched successfully!",
            expense,
        })
    } catch (error) {
        res.status(500).json({
            success:false,
            message:"Failed fetching expense details!"
        })
    }
}
//delete expense
const deleteExpense = async (req, res) => {
    const userId = req.user.id;
    try {
        await Expense.findByIdAndDelete(req.params.id);
        res.status(200).json({
            success: true,
            message:"Expense deleted successfully."
        })
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Failed deleting the expense"
        })
    }
}
//download Expense excel
const downloadExpenseExcel = async (req, res) => {
    const userId = req.user.id;
    try {
        const expense = await Expense.find({userId}).sort({date: -1});
        //prepare data for excel
        const data = expense.map((item) => ({
            category : item.category,
            Amount : item.amount,
            Date : item.date
        }));
        const wb = xlsx.utils.book_new();
        const ws = xlsx.utils.json_to_sheet(data);
        xlsx.utils.book_append_sheet(wb, ws, "Expense");
        xlsx.writeFile(wb, "expense_details.xlsx");
        res.download("expense_details.xlsx");
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Failed downloading the expense details!"
        })
    }
}
module.exports = {
    addExpense,
    getAllExpense,
    deleteExpense,
    downloadExpenseExcel
} 