const express = require("express");
const xlsx = require("xlsx");
const User = require("../models/User.model.js");
const Income = require("../models/Income.model.js");

//add income
const addIncome = async (req, res) => {
    const userId = req.user.id;
    try {
        const {source ,amount , icon, date} = req.body;
        if(!source || !amount || !date){
            return res.status(400).json({
                success:false,
                message:"All fields are required!",
            });
        }
        const income = await Income.create({
            userId,
            icon,
            source,
            amount,
            date: new Date(date)
        });
        res.status(200).json({
            success:true,
            message:"Income added successfully!",
            income
        })
    } catch (error) {
        return res.staus(500).json({
            success: false,
            message:"Failed adding income !",
        })
    }
}
//get all income
const getAllIncome = async (req, res) => {
    const userId  = req.user.id;
    try {
        const income = await Income.find({userId}).sort({date: -1});
        res.status(200).json({
            success:true,
            message:"Income fetched successfully!",
            income,
        })
    } catch (error) {
        res.status(500).json({
            success:false,
            message:"Failed fetching income details!"
        })
    }
}
//delete income 
const deleteIncome = async (req, res) => {
    const userId = req.user.id;
    try {
        await Income.findByIdAndDelete(req.params.id);
        res.status(200).json({
            success: true,
            message:"Income deleted successfully."
        })
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Failed deleting the income"
        })
    }
}
//downloadIncome excel
const downloadIncomeExcel = async (req, res) => {
    const userId = req.user.id;
    try {
        const income = await Income.find({userId}).sort({date: -1});
        //prepare data for excel
        const data = income.map((item) => ({
            Source : item.source,
            Amount : item.amount,
            Date : item.date
        }));
        const wb = xlsx.utils.book_new();
        const ws = xlsx.utils.json_to_sheet(data);
        xlsx.utils.book_append_sheet(wb, ws, "Income");
        xlsx.writeFile(wb, "income_details.xlsx");
        res.download("income_details.xlsx");
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Failed downloading the income details!"
        })
    }
}
module.exports = {
    addIncome,
    getAllIncome,
    deleteIncome,
    downloadIncomeExcel
} 