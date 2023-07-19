const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;
const nodemailer = require('nodemailer');

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = async (req, res) => {
  const { name,firstName,lastName,username, email, password,modePaiement,rib} = req.body;
  
  try {
  // Check if the user already exists in the database
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    if (existingUser.statusCompte === 'bloqué') {
      return res.status(409).json({ message: 'Account is blocked. Contact administrator for assistance.' });
    }
    return res.status(409).json({ message: 'User already exists' });
  }
  
  // Create a new user with the provided information
  const user = new User({
    name,
    firstName,
    lastName,
    username,
    email,
    password: bcrypt.hashSync(password, 8),
    modePaiement,
    rib
  });
  user.statusUser = 'nonConfirmé';
  user.statusCompte = 'actif';
  
  // Save the user to the database
  await user.save();
  
  // Check roles
  const roles = await Role.find({ name: { $in: req.body.roles } }).exec();
  
  if (!roles) {
    return res.status(500).json({ message: 'Error finding roles' });
  }
  
  // Assign roles to the user
  user.roles = roles.map(role => role._id);
  await user.save();
  
  // Send confirmation email to the admin
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'galaxystoreenchere@gmail.com',
      pass: 'mjqpnbrqaodainaj'
    },
  });
  
  const mailOptions = {
    from: 'galaxystoreenchere@gmail.com',
    to: email,
    subject: 'New User Registration',
    html: `
      <p>Hello Admin,</p>
      <p>A new user has registered:</p>
      <p>Username: ${username}</p>
      <p>Email: ${email}</p>
    `,
  };
  
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      return res.status(500).json({ message: 'Error sending email' });
    }
    console.log('Email sent: ' + info.response);
    res.json({ message: 'User registration successful. Confirmation email sent to admin.' });
  });
} catch (error) {
  console.log(error);
  res.status(500).json({ message: 'Error registering user' });
  }
  };  


  exports.signin = async (req, res) => {
    try {
      const user = await User.findOne({ username: req.body.username })
        .populate('roles', '-__v');
        console.log(user);
      if (!user) {
        return res.status(404).send({ message: 'User not found' });
      }
  
      if (user.statusUser === 'nonConfirmé') {
        return res.status(401).send({ message: 'Account not confirmed yet' });
      }
  
      if (user.statusCompte === 'bloqué') {
        return res.status(401).send({ message: 'Account is blocked' });
      }
  
      const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
  
      if (!passwordIsValid) {
        return res.status(401).send({ message: 'Invalid password' });
      }
  
      const token = jwt.sign({ id: user.id }, config.secret, { expiresIn: 86400 });
      
      const authorities = user.roles.map(role => `ROLE_${role.name.toUpperCase()}`);
  
      req.session.token = token;
  
      res.status(200).send({
        id: user._id,
        username: user.username,
        email: user.email,
        roles: authorities,
        token: token,
      });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'Error signing in' });
    }
  };
  


exports.signout = async (req, res) => {
  try {
    req.session = null;
    return res.status(200).send({ message: "You've been signed out!" });
  } catch (err) {
    this.next(err);
  }
};

exports.forgotPassword = async(req, res) => {
  try {
      const { email } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }
      console.log(user.username)
      const resetToken = generateResetToken(); // Générer un token de réinitialisation temporaire côté serveur
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 3600000; // Définir une expiration d'une heure
      const resetPasswordLink = `http://localhost:4200/forget/${resetToken}`;

      await user.save();
      const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
              user: 'galaxystoreenchere@gmail.com',
              pass: 'mjqpnbrqaodainaj'
          },
      });
      const mailOptions = {
          from: 'galaxystoreenchere@gmail.com',
          to: email,
          subject: 'Réinitialisation de mot de passe',
          html: `
          <p>Bonjour,</p>
          <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
          <p>Veuillez cliquer sur le lien suivant pour réinitialiser votre mot de passe :</p>
          <a href="${resetPasswordLink}">${resetPasswordLink}</a>
          <p>Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet e-mail.</p>
        `,
      };

      transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
              console.log(error);
              return res.status(500).json({ message: 'Error sending email' });
          }
          console.log('Email sent: ' + info.response);
          res.json({ message: 'User registration successful. Confirmation email sent to admin.' });
      });
      res.json({ resetToken }); // Renvoyer le token de réinitialisation temporaire au client
  } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'Error resetting password' });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }
    console.log("=>",user.username)
    console.log(newPassword);
    user.password = bcrypt.hashSync(newPassword, 8);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Error resetting password' });
  }
};

function generateResetToken() {
  const resetToken = jwt.sign({ data: 'resetToken' }, 'projetPI-secret-key', { expiresIn: '1h' });
  return resetToken;
}

