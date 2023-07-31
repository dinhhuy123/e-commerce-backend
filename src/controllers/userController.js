const UserModel = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

let refreshTokens = [];

const getCurrentUser = async (req, res, next) => {
    const user = await UserModel.findOne({ email: req.user.data.email });
    if (!user) return res.status(404).json({ message: 'User not found!' });
    res.status(200).json({ data: user, meta: { accessToken: req.user.meta.accessToken } });
};

const login = async (req, res) => {
    const { email, password } = req.body;

    const foundUser = await UserModel.findOne({ email }).exec();
    if (!foundUser) return res.status(404).json({ message: 'Your email wrong!' });

    const match = bcrypt.compare(password, foundUser.password);
    if (!match) return res.status(404).json({ message: 'Your password wrong!' });

    if (foundUser && match) {
        const accessToken = jwt.sign({ email: foundUser.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20s' });

        const refreshToken = jwt.sign({ email: foundUser.email }, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn: '1d',
        });
        refreshTokens.push(refreshToken);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: false,
            path: '/',
            sameSite: 'strict',
        });

        console.log('accessToken', accessToken);
        console.log('refreshToken', refreshToken);

        const { password, ...others } = foundUser._doc;
        // currentUser.data = { ...others };
        // currentUser.meta = { accessToken };
        res.status(200).json({ data: { ...others }, meta: { accessToken } });
    }
};

const handleRefreshToken = (req, res, next) => {
    console.log('cookies: ', req.cookies);
    const refreshToken = req.cookies.refreshToken;
    console.log('refreshToken', refreshToken);
    console.log('refreshTokens: ', refreshTokens);
    if (!refreshToken) return res.status(401).json("You're not authenticated!");
    if (!refreshTokens.includes(`${refreshToken}`)) return res.status(403).json('RefreshToken is not valid!');

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            console.log(err);
        }
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
        const newAccessToken = jwt.sign({ email: user.email }, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: '20s',
        });
        const newRefreshToken = jwt.sign({ email: user.email }, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn: '1d',
        });
        refreshTokens.push(newRefreshToken);
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: false,
            path: '/',
            sameSite: 'strict',
        });
        res.status(200).json({ accessToken: newAccessToken });
    });
};

const logout = (req, res, next) => {
    refreshTokens = refreshTokens.filter((token) => token !== req.cookies.refreshToken);
    res.clearCookie('refreshToken');
    res.status(200).json('Logged out!');
};

const createAccount = async (req, res, next) => {
    const { fullName, email, password } = req.body;

    if (!(fullName && email && password)) return res.status(422).json({ message: 'The given data was invalid.' });

    const userEmail = await UserModel.findOne({ email }).exec();
    console.log('duplicate: ', userEmail);
    if (userEmail) return res.status(409).json({ message: 'Your email existed!' });

    try {
        const hashedPwd = await bcrypt.hash(password, 10);
        const user = await UserModel.create({
            fullName,
            email,
            password: hashedPwd,
        });
        console.log(user);
        res.status(201).json({ success: `New user ${fullName} is created!` });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

module.exports = { createAccount, login, handleRefreshToken, logout, getCurrentUser };
