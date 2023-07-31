const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const userRouter = require('./routes/userRoutes');

const app = express();
const PORT = process.env.PORT || 5001;

require('dotenv').config();

const corsOptions = {
    origin: 'http://localhost:3001',
    credentials: true,
    optionSuccessStatus: 200,
};

app.use(cors(corsOptions));

app.use(express.urlencoded({ extended: false }));

app.use(express.json());

app.use(cookieParser());

app.use('/api/auth', userRouter);

mongoose
    .connect(process.env.MONGODB_URL)
    .then(() => console.log('Connect to MongoDB'))
    .catch((err) => console.log(err));

app.listen(PORT, () => console.log(`App is listening on port: ${PORT}`));
