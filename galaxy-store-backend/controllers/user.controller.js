const User = require('../models/user.model');
const Role = require('../models/role.model');
const jwt = require('jsonwebtoken');
const config = require("../config/auth.config.js");
const nodemailer = require('nodemailer');
var bcrypt = require("bcryptjs");
class UserController {

    static async getAllUsers(req, res) {
        try {
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;

            const user = await User.findById(userId).populate('roles');
            if (!user) {
                return res.status(404).json({ error: 'Utilisateur introuvable' });
            }

            const hasUserRole = user.roles.some((role) => role.name === 'ADMIN');
            if (!hasUserRole) {
                return res.status(401).json({ error: 'Access Denied' });
            }
            const users = await User.find();
            res.json(users);
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des utilisateurs.' });
        }
    }

    static async confirmUser(req, res) {
        try {
            const { id } = req.params;
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;

            const user = await User.findById(userId).populate('roles');
            if (!user) {
                return res.status(404).json({ error: 'Utilisateur introuvable' });
            }

            const hasUserRole = user.roles.some((role) => role.name === 'ADMIN');
            if (!hasUserRole) {
                return res.status(401).json({ error: 'Access Denied' });
            }
            const utilisateur = await User.findByIdAndUpdate(
                id, { statusUser: 'confirmé' }, { new: true }
            );

            // Send confirmation email to the ADMIN
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'galaxystoreenchere@gmail.com',
      pass: 'mjqpnbrqaodainaj'
    },
  });
  
  const mailOptions = {
    from: 'galaxystoreenchere@gmail.com',
    to: utilisateur.email,
    subject: 'New User Confirmation',
    html: `
      <p>Hello ${utilisateur.firstName} ${utilisateur.name},</p>
      <p>Welcome to our application, you have been confirmed by admin</p>
      <p>You can now log in our application and discover our services</p>
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

            if (utilisateur) {
                res.json(utilisateur);
            } else {
                res.status(404).json({ message: 'Utilisateur introuvable' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors de la confirmation de l\'utilisateur.' });
        }
    }

    static async blockAccount(req, res) {
        try {
            const { id } = req.params;
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;

            const user = await User.findById(userId).populate('roles');
            if (!user) {
                return res.status(404).json({ error: 'Utilisateur introuvable' });
            }

            const hasUserRole = user.roles.some((role) => role.name === 'ADMIN');
            if (!hasUserRole) {
                return res.status(401).json({ error: 'Access Denied' });
            }
            const utilisateur = await User.findByIdAndUpdate(
                id, { statusCompte: 'bloqué' }, { new: true }
            );

            if (utilisateur) {
                res.json(utilisateur);
            } else {
                res.status(404).json({ message: 'Utilisateur introuvable' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors du blocage du compte de l\'utilisateur.' });
        }
    }

    static async unblockAccount(req, res) {
        try {
            const { id } = req.params;
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;

            const user = await User.findById(userId).populate('roles');
            if (!user) {
                return res.status(404).json({ error: 'Utilisateur introuvable' });
            }

            const hasUserRole = user.roles.some((role) => role.name === 'ADMIN');
            if (!hasUserRole) {
                return res.status(401).json({ error: 'Access Denied' });
            }
            const utilisateur = await User.findByIdAndUpdate(
                id, { statusCompte: 'actif' }, { new: true }
            );

            if (utilisateur) {
                res.json(utilisateur);
            } else {
                res.status(404).json({ message: 'Utilisateur introuvable' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors du blocage du compte de l\'utilisateur.' });
        }
    }

    static async deleteUser(req, res) {
        try {
            const { id } = req.params;
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;

            const user = await User.findById(userId).populate('roles');
            if (!user) {
                return res.status(404).json({ error: 'Utilisateur introuvable' });
            }

            const hasUserRole = user.roles.some((role) => role.name === 'ADMIN');
            if (!hasUserRole) {
                return res.status(401).json({ error: 'Access Denied' });
            }
            const deletedUser = await User.findByIdAndDelete(id);

            if (deletedUser) {
                res.json({ message: 'Utilisateur supprimé avec succès' });
            } else {
                res.status(404).json({ message: 'Utilisateur introuvable' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors de la suppression de l\'utilisateur.' });
        }
    }

    static async updateUser(req, res) {
        try {
            const { id } = req.params;
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;

            const user = await User.findById(userId).populate('roles');
            if (!user) {
                return res.status(404).json({ error: 'Utilisateur introuvable' });
            }

            const hasUserRole = user.roles.some((role) => role.name === 'ADMIN');
            if (!hasUserRole) {
                return res.status(401).json({ error: 'Access Denied' });
            }
            const updatedUser = req.body;

            const utilisateur = await User.findByIdAndUpdate(id, updatedUser, { new: true });

            if (utilisateur) {
                res.json(utilisateur);
            } else {
                res.status(404).json({ message: 'Utilisateur introuvable' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors de la mise à jour de l\'utilisateur.' });
        }
    }

    static async getUserProfile(req, res) {
        try {
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;
            const user = await User.findById(userId);
            if (user) {
                const userProfile = {
                    name: user.name,
                    firstName: user.firstName,
                    username: user.username,
                    email: user.email,
                    statusUser: user.statusUser,
                    statusCompte: user.statusCompte,
                    modePaiement: user.modePaiement,
                    rib: user.rib
                };
                res.json(userProfile);
            } else {
                res.status(404).json({ message: 'Utilisateur introuvable' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors de la récupération du profil de l\'utilisateur.' });
        }
    }

    static async updateUserProfile(req, res) {
        try {
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;
            const user = await User.findById(userId);
            const updatedUser = req.body;
            if (!req.body) {
                res.status(500).json({ message: 'Veuillez saisir les informations nécessaires' });
            }
            if (user) {
                updatedUser.password = bcrypt.hashSync(updatedUser.password, 8);
                const utilisateur = await User.findByIdAndUpdate(userId, updatedUser, { new: true });
                res.json(utilisateur)
            } else {
                res.status(404).json({ message: 'Utilisateur introuvable' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors de la récupération du profil de l\'utilisateur.' });
        }
    }

    static async getAllUsersWithRoleUser(req, res) {
        try {
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;

            const user = await User.findById(userId).populate('roles');
            if (!user) {
                return res.status(404).json({ error: 'Utilisateur introuvable' });
            }

            const hasUserRole = user.roles.some((role) => role.name === 'ADMIN');
            if (!hasUserRole) {
                return res.status(401).json({ error: 'Access Denied' });
            }

            const role = await Role.findOne({ name: 'user' });

            if (!role) {
                return res.status(404).json({ error: 'Le rôle "user" n\'existe pas.' });
            }
            const users = await User.find({ roles: role._id }).populate('roles');
            res.json(users);
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des utilisateurs.' });
        }
    }

    static async getAllAdmins(req, res) {
        try {
            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;

            const user = await User.findById(userId).populate('roles');
            if (!user) {
                return res.status(404).json({ error: 'Utilisateur introuvable' });
            }

            const hasUserRole = user.roles.some((role) => role.name === 'ADMIN');
            if (!hasUserRole) {
                return res.status(401).json({ error: 'Access Denied' });
            }
            const role = await Role.findOne({ name: 'ADMIN' });

            if (!role) {
                return res.status(404).json({ error: 'Le rôle "user" n\'existe pas.' });
            }
            const users = await User.find({ roles: role._id }).populate('roles');
            res.json(users);

            res.json(users);
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des utilisateurs.' });
        }
    }
}

module.exports = UserController;