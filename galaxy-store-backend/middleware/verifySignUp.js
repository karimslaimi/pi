const db = require("../models");
const ROLES = db.ROLES;
const User = db.user;

async function checkDuplicateUsernameOrEmail(req, res, next) {
    const usernameExists = await User.findOne({ username: req.body.username }).exec();
    if (usernameExists) {
      return res.status(400).json({ message: "Failed! Username is already in use!" });
    }

    const emailExists = await User.findOne({ email: req.body.email }).exec();
    if (emailExists) {
      return res.status(400).json({ message: "Failed! Email is already in use!" });
    }

    next();
};

let checkRolesExisted = (req, res, next) => {
    if (req.body.roles) {
        for (let i = 0; i < req.body.roles.length; i++) {
            if (!ROLES.includes(req.body.roles[i])) {
                res.status(400).send({
                    message: `Failed! Role ${req.body.roles[i]} does not exist!`
                });
                return;
            }
        }
    }

    next();
};

const verifySignUp = {
    checkDuplicateUsernameOrEmail,
    checkRolesExisted
};

module.exports = verifySignUp;