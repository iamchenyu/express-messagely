/** Middleware for handling req authorization for routes. */

const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");

/** Middleware: Authenticate user. */

function authenticateJWT(req, res, next) {
  try {
    const tokenFromBody = req.body._token;
    const payload = jwt.verify(tokenFromBody, SECRET_KEY);
    req.user = payload; // create a current user
    return next();
  } catch (err) {
    return next();
  }
}

/** Middleware: Requires user is authenticated. */

function ensureLoggedIn(req, res, next) {
  if (!req.user) {
    const error = new ExpressError("Unauthorized", 401);
    return next(error);
  } else {
    return next();
  }
}

/** Middleware: Requires correct username. Authorized */

function ensureCorrectUser(req, res, next) {
  try {
    if (req.user.username === req.params.username) {
      return next();
    } else {
      const error = new ExpressError("Forbidden", 403);
      return next(error);
    }
  } catch (err) {
    // errors would happen here if we made a request and req.user is undefined
    const error = new ExpressError("Unauthorized", 401);
    return next(error);
  }
}

// end

module.exports = {
  authenticateJWT,
  ensureLoggedIn,
  ensureCorrectUser,
};
