require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const connectDB = require('./config/db.js');
const authRoutes = require('./routes/authRoutes.js');
const incomeRoutes = require('./routes/incomeRoutes.js');
const expenseRoutes = require('./routes/expenseRoutes.js');
const dashboardRoutes = require('./routes/dashboardRoutes.js');

const app = express();

// MIDDLEWARES
app.use(cors({
    origin: process.env.CLIENT_URL || "*",
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));

app.use(express.json());

// Connect to database
connectDB();

// API routes
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/income", incomeRoutes);
app.use("/api/v1/expense", expenseRoutes);
app.use("/api/v1/dashboard", dashboardRoutes);

// Serve uploads folder statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Default port fallback
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
