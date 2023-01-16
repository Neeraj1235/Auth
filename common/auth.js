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
  // console.log(data);
  return data;
};

const validate = async (req, res, next) => {
  if (req.headers && req.headers.authorization) {
    // console.log(req.headers.authorization.split(" ")[1]);
    let token = req.headers.authorization.split(" ")[1];
    let data = await decodeToken(token);
    // console.log(data);
    //  console.log(Math.round(Date.now()/1000));
    if (data.exp >= Math.round(Date.now() / 1000)) {
      next();
    } else {
      res.status(401).send({ message: "Token Expired" });
    }
  } else {
    res.status(400).send({
      Message: "No token found",
    });
  }
};

const roleAdmin = async (req, res, next) => {
  if (req.headers && req.headers.authorization) {
    // console.log(req.headers.authorization.split(" ")[1]);
    let token = req.headers.authorization.split(" ")[1];
    let data = await decodeToken(token);
    // console.log(data);
    if (data.role === "admin") {
      next();
    } else {
      res.status(401).send({ message: "Only Admin can access" });
    }
  } else {
    res.status(400).send({
      Message: "No token found",
    });
  }
};

module.exports = {
  hashPassword,
  hashCompare,
  createToken,
  decodeToken,
  validate,
  roleAdmin,
};
