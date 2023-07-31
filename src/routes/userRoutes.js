const express = require('express');
const router = express.Router();
const { createAccount, login, handleRefreshToken, logout, getCurrentUser } = require('../controllers/userController');

const verifyJWT = require('../middleware/verifyJWT');

router.get('/me', verifyJWT, getCurrentUser);
router.post('/login', login);
router.post('/register', createAccount);
router.post('/refresh', handleRefreshToken);
router.post('/logout', verifyJWT, logout);

module.exports = router;
