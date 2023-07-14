const Bits = require('../models/bits.js');
const Product = require('../models/product.js')
const User = require('../models/user.model.js')
const jwt = require('jsonwebtoken');
const config = require("../config/auth.config.js");
const moment = require('moment-timezone');

class BitsController {

  static async createBits(req, res) {
    try {
      const { bitsShareAmount, productId } = req.body;
      const dateTimeShare = moment().format('YYYY-MM-DD HH:mm:ss');
      if (!bitsShareAmount || !productId) {
        return res.status(400).json({ error: 'Veuillez fournir tous les champs requis' });
      }
      const product = await Product.findById(productId);
      if (!product) {
        return res.status(404).json({ error: 'Produit introuvable' });
      }
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token,config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      const hasUserRole = user.roles.some(role => role.name !== 'user');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
      if(product.user._id.toString() === user._id.toString()){
        return res.status(406).json({error:"This is your own product. you can't share for it !!"})
      }
      const existingBits = await Bits.findOne({ user: userId, product: productId });
      const endProduct = product.dateFermeture;
      if (existingBits) {
        if (endProduct<dateTimeShare || endProduct===dateTimeShare){
            existingBits.status="closed"
            const updatedBits = await existingBits.save();
            console.log('Product closed');
            return res.status(406).json({error:'Product is closed !!'})
          }else{
            if(product.status!=='VALIDATED'){
              return res.status(406).json({error:"Product not validated yet or rejected, you can't share for it!!"})
            }
            existingBits.bitsSharePrice = existingBits.bitsSharePrice+bitsShareAmount;
            existingBits.user=user;
            existingBits.product=product;
            existingBits.bitsSharedDateTime=dateTimeShare;
            existingBits.status="in progress";
            const updatedBits = await existingBits.save();
            console.log('Bits mis à jour');
            return res.status(200).json(updatedBits);
          }
      }else{
        if(endProduct<dateTimeShare || endProduct===dateTimeShare){
          return res.status(406).json({error :"Sorry , the product is closed you can't add a bit share"})
        }
        if(product.status!=='VALIDATED'){
          return res.status(406).json({error:"Product not validated yet or rejected, you can't share for it!!"})
        }
        const newBits = new Bits({
          bitsSharePrice:product.price + bitsShareAmount,
          product: product,
          user:user,
          bitsSharedDateTime:dateTimeShare
        });
        const savedBits = await newBits.save();
        console.log('Nouvelle instance de bits créée :');
        res.status(201).json(savedBits);
      }
    } catch (error) {
      console.error('Erreur lors de la création de bits :', error);
      res.status(500).json({ error: 'Erreur lors de la création de bits' });
    }
  }

  static async getAllBits(req,res,next) {

      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token,config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      const hasUserRole = user.roles.some(role => role.name !== 'admin');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
      try{
      const bitsList = await Bits.find().populate('user').populate('product').exec();
     return res.json(bitsList);
    }catch (error){
      res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des Bits.' });
    }
  }

  static async getUserConnectedBits(req,res,next) {
    const token = req.headers.authorization.split('Bearer ')[1];
    const decodedToken = jwt.verify(token,config.secret);
    const userId = decodedToken.id;
    const user = await User.findById(userId).populate('roles');
    if (!user) {
    return res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    const hasUserRole = user.roles.some(role => role.name !== 'user');
    if (hasUserRole) {
      return res.status(401).json({ error: 'Access Denied' });
    }
    try{
      const bitsList = await Bits.find({ user: userId }).populate('user').populate('product').exec();
      return res.json(bitsList);
    }catch (error){
      res.status(500).json({ message: 'Une erreur est survenue lors de la récupération des Bits.' });
    }

  }

  static async deleteBit(req, res, next) {
    try {
      const { bitId } = req.params;
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token, config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      if(req.params===null){
        return res.status(406).json({ error: "Veuillez donner l'identifiant du bit à supprimer" });
      }
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      
      const hasUserRole = user.roles.some(role => role.name !== 'user');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
      
      const bit = await Bits.findById(bitId);
      if (!bit) {
        return res.status(404).json({ error: 'Bits introuvable' });
      }
      
      if (!bit.user || bit.user._id.toString() !== userId) {
        return res.status(401).json({ error: 'Unauthorized to delete the bit' });
      }

      if(bit.status!=null && bit.status==="closed"){
        return res.status(500).json({error: 'Bit is closed: cannot delete it'})
      }
      
      await Bits.findByIdAndDelete(bitId);
      
      return res.status(200).json({ message: 'Bits supprimé avec succès' });
    } catch (error) {
      console.log(error)
      return res.status(500).json({ error: 'Une erreur est survenue lors de la suppression des bits' });
    }
  }

  static async getAllClosedBits(req,res,next){
    try {
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token, config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      
      const hasUserRole = user.roles.some(role => role.name !== 'admin');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
      const closedBits = await Bits.find({ status: "closed" }).populate('user').populate('product');
      return res.status(200).json(closedBits);
    } catch (error) {
      return res.status(500).json({ error: 'Une erreur est survenue lors de la récupération des bits fermés' });
    }
  }

  static async getAllInProgressBits(req,res,next){
    try {
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token, config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      
      const hasUserRole = user.roles.some(role => role.name !== 'admin');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
      const inProgressBits = await Bits.find({ status: "in progress" }).populate('user').populate('product');
      return res.status(200).json(inProgressBits);
    } catch (error) {
      return res.status(500).json({ error: 'Une erreur est survenue lors de la récupération des bits en cours' });
    }
  }

  static async getAllClosedBitsByUserConnected (req,res,next){
    try {
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token, config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      
      const hasUserRole = user.roles.some(role => role.name !== 'user');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
  
      const closedBits = await Bits.find({ status: "closed", user: userId })
        .populate('user')
        .populate('product');
  
      return res.status(200).json(closedBits);
    } catch (error) {
      return res.status(500).json({ error: 'Une erreur est survenue lors de la récupération des bits fermés' });
    }
  }

  static async getAllProgressBitsByUserConnected (req,res,next){
    try {
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token, config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      
      const hasUserRole = user.roles.some(role => role.name !== 'user');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
  
      const inProgressBits = await Bits.find({ status: "in progress", user: userId })
        .populate('user')
        .populate('product');
  
      return res.status(200).json(inProgressBits);
    } catch (error) {
      return res.status(500).json({ error: 'Une erreur est survenue lors de la récupération des bits en cours' });
    }
  }

  static async getBitById(req,res,next){
    try {
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token, config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      if(req.params===null){
        return res.status(406).json({ error: "Veuillez donner l'identifiant du bit à consulter" });
      }
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      
      const hasUserRole = user.roles.some(role => role.name !== 'admin');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
      const bitId = req.params.id;
      const bit = await Bits.findById(bitId).populate("user").populate("product").exec();
            
      if (!bit) {
        return res.status(404).json({ error: 'Bits introuvable' });
      }   
      return res.status(200).json(bit);
    } catch (error) {
      return res.status(500).json({ error: 'Une erreur est survenue lors de la récupération du bit' });
    }
  }

  static async getBitByIdAndIdUser(req,res,next){
    try {
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token, config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      if(req.params===null){
        return res.status(406).json({ error: "Veuillez donner l'identifiant du bit à consulter" });
      }
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      
      const hasUserRole = user.roles.some(role => role.name !== 'user');
      if (hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
      
      const bitId = req.params.id;
      const bit = await Bits.findById(bitId).populate("user").populate("product").exec();

      if (!bit) {
        return res.status(404).json({ error: 'Bits introuvable' });
      }
      
      if (!bit.user || bit.user._id.toString() !== userId) {
        return res.status(401).json({ error: 'Unauthorized to get the bit' });
      }   

      return res.status(200).json(bit);
    } catch (error) {
      return res.status(500).json({ error: 'Une erreur est survenue lors de la récupération du bit' });
    }
  }

  static async getBitsByProduct(req,res,next){
    try {
      const { productId } = req.params;
      const token = req.headers.authorization.split('Bearer ')[1];
      const decodedToken = jwt.verify(token, config.secret);
      const userId = decodedToken.id;
      const user = await User.findById(userId).populate('roles');
      if(req.params===null){
        return res.status(406).json({ error: "Veuillez donner l'identifiant du bit à consulter" });
      }
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
      }
      
      const hasUserRole = user.roles.some(role => role.name === 'admin' || role.name==='user');
      if (!hasUserRole) {
        return res.status(401).json({ error: 'Access Denied' });
      }
      if(!productId){
        return res.status(500).json({ error: 'Veuiller fournir les informations nécessaires' });
      }
      const product = await Product.findById(productId);
      if (!product) {
        return res.status(404).json({ error: 'Product not found' });
      }
      const historyBitsByProduct = await Bits.find({ product: productId }).populate('user').populate('product')
      .sort({ bitsSharedDateTime: -1 });
      ;
      return res.status(200).json(historyBitsByProduct);
    }catch (error) {
      return res.status(500).json({ error: 'Une erreur est survenue lors de la récupération des bits' });
    }
  }
}
module.exports = BitsController;