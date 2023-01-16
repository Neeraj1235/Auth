const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const SALT = 10;
const secret = "IKNkjnKNJKj09090#$@!lknlkn";

const hashPassword = async (password) => {
  let salt = await bcrypt.genSalt(SALT);
  // console.log(salt);
  let hash = await bcrypt.hash(password, salt);
  //console.log(hash)
  return hash;
};

const hashCompare = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};

const createToken = async (payload) => {
  let token = await jwt.sign(payload, secret, { expiresIn: "1m" });
  return token;
};

const decodeToken = async (token) => {
  let data = await jwt.decode(token);
  console.log(data);
};

module.exports = { hashPassword, hashCompare, createToken, decodeToken };
