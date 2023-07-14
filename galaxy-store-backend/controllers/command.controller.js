const Commande = require('../models/command');
const Bits = require('../models/bits.js');
const Product = require('../models/product.js')
const User = require('../models/user.model.js')
const jwt = require('jsonwebtoken');
const config = require("../config/auth.config.js");
const moment = require('moment-timezone');

class CommandeController {

    static async getAllCommandes(req, res,next) {
        try {
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          const user = await User.findById(userId).populate('roles');
          if (!user) {
            return res.status(404).json({ error: 'Utilisateur introuvable' });
          }
      
          const hasUserRole = user.roles.some((role) => role.name === 'admin');
          if (!hasUserRole) {
            return res.status(401).json({ error: 'Access Denied' });
          }
          const commandes = await Commande.find();
          res.json(commandes);
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des commandes.' });
        }
      }

      static async getCommandsByUserInBits (req, res) {
        if (!req.headers.authorization) {
          return res.status(406).json({ error: 'Token is null' });
        }
    
        const token = req.headers.authorization.split('Bearer ')[1];
        const decodedToken = jwt.verify(token, config.secret);
        const userId = decodedToken.id;
    
        const user = await User.findById(userId).populate('roles');
        if (!user) {
          return res.status(404).json({ error: 'Utilisateur introuvable' });
        }
    
        const hasUserRole = user.roles.some((role) => role.name === 'user');
        if (!hasUserRole) {
          return res.status(401).json({ error: 'Access Denied' });
        }
    
        try {
          const commands = await Commande.find({ 'receptorOfCommand': user }).populate('bits');    
          res.json(commands);
        } catch (error) {
          console.error(error);
          res.status(500).json({ error: 'Une erreur s\'est produite lors de la récupération des commandes.' });
        }
      }

      static async updateCommande(req, res) {
        try {
          const { id } = req.params;
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          const user = await User.findById(userId).populate('roles');
          if (!user) {
            return res.status(404).json({ error: 'Utilisateur introuvable' });
          }
      
          const hasUserRole = user.roles.some((role) => role.name === 'admin');
          if (!hasUserRole) {
            return res.status(401).json({ error: 'Access Denied' });
          }
          const commandeToBeUpdated  = await Commande.findById(id).exec();
          if (!commandeToBeUpdated) {
            return res.status(404).json({ error: 'Commande introuvable' });
          }
          if(commandeToBeUpdated.status!=="PROCESSING"){
            return res.status(406).json({ error: 'You cannot update this command ' });
          }
          const commande = await Commande.findByIdAndUpdate(id, req.body, { new: true });
          if (commande) {
            res.json(commande);
          } else {
            res.status(404).json({ message: 'La commande demandée n\'a pas été trouvée.' });
          }
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Une erreur est survenue lors de la mise à jour de la commande.' });
        }
      }
    
      static async deleteCommande(req, res) {
        try {
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          const user = await User.findById(userId).populate('roles');
          if (!user) {
            return res.status(404).json({ error: 'Utilisateur introuvable' });
          }
      
          const hasUserRole = user.roles.some((role) => role.name === 'admin');
          if (!hasUserRole) {
            return res.status(401).json({ error: 'Access Denied' });
          }
          const commandeToBeDeleted  = await Commande.findById(req.params.id).exec();
          if(!commandeToBeDeleted){
            return res.status(500).json({ error: 'Commande introuvable!!' });
          }
          if(commandeToBeDeleted.status!=="PROCESSING"){
            return res.status(406).json({ error: 'You cannot delete this command ' });
          }
          const commande = await Commande.findByIdAndDelete(req.params.id);
          if (commande) {
            res.json({ message: 'La commande a été supprimée avec succès.' });
          } else {
            res.status(404).json({ message: 'La commande demandée n\'a pas été trouvée.' });
          }
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Une erreur est survenue lors de la suppression de la commande.' });
        }
      }

      static async createCommandsForBits(req,res) {

        try {
          const { productId } = req.body;
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          const user = await User.findById(userId).populate('roles');
          if (!user) {
            return res.status(404).json({ error: 'Utilisateur introuvable' });
          }
      
          const hasUserRole = user.roles.some((role) => role.name === 'admin');
          if (!hasUserRole) {
            return res.status(401).json({ error: 'Access Denied' });
          }
      
          const product = await Product.findById(productId);
          if (!product) {
            return res.status(404).json({ error: 'Produit introuvable' });
          }
          if(product.status!=='VALIDATED'){
            return res.status(406).json({ error: "Le système ne peut pas générer une commande pour un produit qui n'est pas encore validé encore OU refusé" });
          }
          const endProduct = product.dateFermeture;
          if (endProduct>moment().format('YYYY-MM-DD HH:mm:ss') || endProduct===moment().format('YYYY-MM-DD HH:mm:ss')) {
            return res
              .status(406)
              .json({ error: "Le système ne peut pas générer une commande pour un produit qui n'est pas encore fermé" });
          }
          
          const bit = await Bits.findOne({ product: productId })
            .sort({ bitsSharedDateTime: -1 })
            .populate('user')
            .populate('product')
            .limit(1)
            .exec();
      
          if (!bit) {
            return res.status(404).json({ error: 'Bits introuvable' });
          }
          const commandesExistants = await Commande.countDocuments();
          try {
            const commandExists = await Commande.findOne({ bits: bit._id.toString() }).populate('bits').exec();
            if (commandExists) {
              return res.status(500).json({ error: 'Commande déjà passée' });
            }
          } catch (error) {
            console.error(error);
          }
          const nouvelleCommande = new Commande({
            matriculeCommande: `COM-${(commandesExistants + 1).toString().padStart(8, '0')}`,
            montantCommande: bit.bitsSharePrice,
            bits: bit,
            receptorOfCommand: bit.user,
            proprietaryOfProduct:product.user,
            administator: user,
          });
      
          await nouvelleCommande.save();
          const bits = await Bits.find({ product: productId });

          for (const bit of bits) {
            bit.status = 'closed';
            await bit.save();
           }
          const populatedCommande = await Commande.findById(nouvelleCommande._id)
          .populate('proprietaryOfProduct')
          .populate('receptorOfCommand')
          .populate('administator')
          .populate('bits')
          .exec();
          return res.status(200).json(populatedCommande);
        } catch (error) {
          console.log(error)
          return res.status(500).json({ error: 'Une erreur s\'est produite lors de la création de la commande' });
        }
      }

      static async getAllCommandsProcessing(req,res,next){
        try {
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          const user = await User.findById(userId).populate('roles');
          if (!user) {
            return res.status(404).json({ error: 'Utilisateur introuvable' });
          }
      
          const hasUserRole = user.roles.some((role) => role.name === 'admin');
          if (!hasUserRole) {
            return res.status(401).json({ error: 'Access Denied' });
          }
          const commandes = await Commande.find({ status: "PROCESSING" });
          res.json(commandes);
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des commandes IN PROGRESSING.' });
        }
      }

      static async getAllCommandsValidated(req,res,next){
        try {
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          const user = await User.findById(userId).populate('roles');
          if (!user) {
            return res.status(404).json({ error: 'Utilisateur introuvable' });
          }
      
          const hasUserRole = user.roles.some((role) => role.name === 'admin');
          if (!hasUserRole) {
            return res.status(401).json({ error: 'Access Denied' });
          }
          const commandes = await Commande.find({ status: "COMPLETED" });
          res.json(commandes);
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des commandes COMPLETED.' });
        }
      }

      static async getAllCommandsFactured(req,res,next){
        try {
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          const user = await User.findById(userId).populate('roles');
          if (!user) {
            return res.status(404).json({ error: 'Utilisateur introuvable' });
          }
      
          const hasUserRole = user.roles.some((role) => role.name === 'admin');
          if (!hasUserRole) {
            return res.status(401).json({ error: 'Access Denied' });
          }
          const commandes = await Commande.find({ status: "FACTURED" });
          res.json(commandes);
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des commandes FACTURED.' });
        }
      }
}
module.exports = CommandeController;