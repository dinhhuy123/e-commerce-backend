const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyJWT = (req, res, next) => {
    const token = req.headers.authorization;
    if (token) {
        const accessToken = token.split(' ')[1];
        jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json('Token is not valid');
            }
            req.user = { data: user, meta: { accessToken: accessToken } };
            next();
        });
    } else {
        return res.status(401).json('You are not authenticated!');
    }
};

module.exports = verifyJWT;
