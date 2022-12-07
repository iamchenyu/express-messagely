/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register(username, password, first_name, last_name, phone) {
    const hashedPwd = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPwd, first_name, last_name, phone]
    );
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT username, password, first_name, last_name, phone FROM users WHERE username=$1`,
      [username]
    );
    const user = result.rows[0];
    if (!user) throw new ExpressError("User not exist", 400);
    return await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    await db.query(
      `UPDATE users SET last_login_at = current_timestamp WHERE username = $1`,
      [username]
    );
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
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
      `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username=$1`,
      [username]
    );
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
    const results = await db.query(
      `SELECT id, to_username AS to_user, body, sent_at, read_at FROM messages
       WHERE from_username = $1`,
      [username]
    );

    return Promise.all(
      results.rows.map(async (re) => {
        const { id, body, sent_at, read_at } = re;
        const { rows } = await db.query(
          `SELECT username, first_name, last_name, phone FROM users WHERE username=$1`,
          [re.to_user]
        );
        return {
          id,
          body,
          sent_at,
          read_at,
          to_user: rows[0],
        };
      })
    ).then((data) => data);
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `SELECT id, from_username AS from_user, body, sent_at, read_at FROM messages WHERE to_username=$1`,
      [username]
    );
    return Promise.all(
      results.rows.map(async (re) => {
        const { id, body, sent_at, read_at } = re;
        const { rows } = await db.query(
          `SELECT username, first_name, last_name, phone FROM users WHERE username=$1`,
          [re.from_user]
        );
        return { id, body, sent_at, read_at, from_user: rows[0] };
      })
    ).then((data) => data);
  }
}

module.exports = User;
