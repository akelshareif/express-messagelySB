/** User class for message.ly */
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require('../config');
const db = require('../db');
const ExpressError = require('../expressError');

/** User of the site. */

class User {
    /** register new user -- returns
     *    {username, password, first_name, last_name, phone}
     */

    static async register({ username, password, first_name, last_name, phone }) {
        const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
        const results = await db.query(
            `INSERT INTO users (username, password, first_name, last_name, phone, join_at)
             VALUES ($1, $2, $3, $4, $5, current_timestamp)
             RETURNING username, password, first_name, last_name, phone, join_at`,
            [username, hashedPassword, first_name, last_name, phone]
        );

        if (results.rows.length === 0) {
            throw new ExpressError('Error: There was an error registering user. Please try again.', 400);
        }

        return results.rows[0];
    }

    /** Authenticate: is this username/password valid? Returns boolean. */

    static async authenticate(username, password) {
        const result = await db.query(`SELECT password FROM users WHERE username=$1`, [username]);

        const user = result.rows[0];
        if (user) {
            if (await bcrypt.compare(password, user.password)) {
                return true;
            } else {
                return false;
            }
        }
    }

    /** Update last_login_at for user */

    static async updateLoginTimestamp(username) {
        const result = await db.query(
            `UPDATE users SET last_login_at = CURRENT_TIMESTAMP
             WHERE username=$1 
             RETURNING last_login_at`,
            [username]
        );
    }

    /** All: basic info on all users:
     * [{username, first_name, last_name, phone}, ...] */

    static async all() {
        const results = await db.query(`SELECT username, first_name, last_name, phone FROM users`);

        return results.rows;
    }

    /** Get: get user by username
     *
     * returns {username,
     *          first_name,
     *          last_name,
     *          phone,
     *          join_at,
     *          last_login_at } */

    static async get(username) {
        const result = await db.query(
            `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users
             WHERE username=$1`,
            [username]
        );

        if (result.rows.length === 0) {
            throw new ExpressError('Error: User not found. Please try again.', 404);
        }

        return result.rows[0];
    }

    /** Return messages from this user.
     *
     * [{id, to_user, body, sent_at, read_at}]
     *
     * where to_user is
     *   {username, first_name, last_name, phone}
     */

    static async messagesFrom(username) {
        const result = await db.query(
            `SELECT m.id, m.body, m.sent_at, m.read_at, m.to_username, u.first_name, u.last_name, u.phone
             FROM messages AS m
             JOIN users AS u ON m.to_username=u.username
             WHERE m.from_username=$1`,
            [username]
        );

        const messages = result.rows.map((m) => {
            const obj = {
                id: m.id,
                body: m.body,
                sent_at: m.sent_at,
                read_at: m.read_at,
                to_user: {
                    username: m.to_username,
                    first_name: m.first_name,
                    last_name: m.last_name,
                    phone: m.phone,
                },
            };
            return obj;
        });

        return messages;
    }

    /** Return messages to this user.
     *
     * [{id, from_user, body, sent_at, read_at}]
     *
     * where from_user is
     *   {id, first_name, last_name, phone}
     */

    static async messagesTo(username) {
        const result = await db.query(
            `SELECT m.id, m.body, m.sent_at, m.read_at, m.from_username, u.first_name, u.last_name, u.phone
             FROM messages AS m
             JOIN users AS u ON m.from_username=u.username
             WHERE m.to_username=$1`,
            [username]
        );

        const messages = result.rows.map((m) => {
            const obj = {
                id: m.id,
                body: m.body,
                sent_at: m.sent_at,
                read_at: m.read_at,
                from_user: {
                    username: m.from_username,
                    first_name: m.first_name,
                    last_name: m.last_name,
                    phone: m.phone,
                },
            };
            return obj;
        });

        return messages;
    }
}

module.exports = User;
