import jwt from "jsonwebtoken";
import { createError } from "./error.js";

export const verifyToken = (req, res, next) => {
  let token = req.cookies.access_token;

  if (!token) {
    console.log(req.headers)
    token = req.headers.access_token
  }

  console.log('im verifying token', token)
  jwt.verify(token, process.env.JWT, (err, user) => {
    if (err) return next(createError(403, "Token is not valid!"));
    req.user = user;
    next()
  });
};