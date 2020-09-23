const express = require('express');
const router = new express.Router();
const jwt = require('jsonwebtoken');

const { SECRET_KEY } = require('../config');
const ExpressError = require('../expressError');
const User = require('../models/user');

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;

        if (await User.authenticate(username, password)) {
            let token = jwt.sign({ username }, SECRET_KEY);

            await User.updateLoginTimestamp(username);

            return res.json({ token });
        } else {
            throw new ExpressError('Error: Invalid username/password. Please try again.', 400);
        }
    } catch (e) {
        next(e);
    }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async (req, res, next) => {
    try {
        const user = await User.register(req.body);

        if (user) {
            let token = jwt.sign({ username: user.username }, SECRET_KEY);

            await User.updateLoginTimestamp(user.username);

            return res.json({ token });
        }
    } catch (e) {
        next(e);
    }
});

module.exports = router;
