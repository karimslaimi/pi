const Product = require('../models/product.js')
const User = require('../models/user.model.js')
const jwt = require('jsonwebtoken');
const config = require("../config/auth.config.js");
const moment = require('moment');
const Category = require('../models/category.js');
const Bits = require('../models/bits.js');
const QRCode = require('qrcode');

class ProductController {

  // add product (only by user)
    static async createProduct(req,res) {
        const { name, price, dateFermeture, categoryId } = req.body;

        if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
        if(!name || !price || !dateFermeture || !categoryId){
            return res.status(500).json({ error: 'Veuillez fournir toutes les informations nécessaires' });
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
          const productExistants = await Product.countDocuments();
          const category = await Category.findById(categoryId);
          if (!category) {
            return res.status(404).json({ error: 'Category not found' });
          }
          const newProduct = new Product({
            name,
            price,
            matricule:`PRO-${(productExistants + 1).toString().padStart(8, '0')}`,
            dateFermeture: moment(dateFermeture).format('YYYY-MM-DD HH:mm:ss'),
            user: user,
            category:category
          });
          try {
            const savedProduct = await newProduct.save();      
            return res.status(201).json(savedProduct);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to create product' });
          }
        }

  // get all products (only by Admin)
    static async getAllProducts(req, res,next) {
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
      
          try {
            const products = await Product.find().populate('user').populate('category');
            return res.status(200).json(products);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to get products' });
          }
        }
    
    // delete a product (by user && not bit)
    static async deleteProduct(req, res) {
          const { productId } = req.params;
      
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }

          if(!productId){
            return res.status(500).json({ error: 'Veuiller fournir les informations nécessaires' });
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
            const product = await Product.findById(productId);
            if (!product) {
              return res.status(404).json({ error: 'Product not found' });
            }
      
            if (product.user.toString() !== userId) {
              return res.status(401).json({ error: "Impossible de supprimer le produit !! Vous n'etes pas le propriétaire" });
            }
            const bits = await Bits.find({ product: productId }).populate('product');
            if (bits.length > 0) {
              return res.status(406).json({ error: "Impossible de mettre à jour le produit !! il est utilisé par des bits" });
            }
      
            await Product.findByIdAndDelete(productId);
            return res.status(200).json({ message: 'Product deleted successfully' });
          } catch (error) {
            return res.status(500).json({ error: 'Failed to delete product' });
          }
        }
    
    // validate a product (only by Admin)
    static async validateProduct(req, res) {
          const { productId } = req.params;
      
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }

          if(!productId){
            return res.status(500).json({ error: 'Veuiller fournir les informations nécessaires' });
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
      
          try {
            const product = await Product.findById(productId);
            if (!product) {
              return res.status(404).json({ error: 'Product not found' });
            }
            if(product.status!=="PROCESSING"){
              return res.status(500).json({ error: 'the status of product is not Processing!! cannot validate it' });
            }
            product.status="VALIDATED" 
            await product.save();
            return res.status(200).json(product);
          } catch (error) {
            console.log(error)
            return res.status(500).json({ error: 'Failed to validate product' });
          }
        }

    // reject a product (only by Admin)
    static async rejectProduct(req, res) {
          const { productId } = req.params;
      
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }

          if(!productId){
            return res.status(500).json({ error: 'Veuiller fournir les informations nécessaires' });
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
      
          try {
            const product = await Product.findById(productId);
            if (!product) {
              return res.status(404).json({ error: 'Product not found' });
            }
            if(product.status!=="PROCESSING"){
              return res.status(500).json({ error: 'the status of product is not Processing!! cannot reject it' });
            }
            product.status="REJECTED" 
            await product.save();
            return res.status(200).json(product);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to validate product' });
          }
        }

    static async updateProduct(req, res) {
          const { productId } = req.params;
          const updateFields = {};
      
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          if (!productId) {
            return res.status(400).json({ error: 'Please provide the product ID' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          try {
            const user = await User.findById(userId).populate('roles');
            if (!user) {
              return res.status(404).json({ error: 'Utilisateur introuvable' });
            }
      
            const hasUserRole = user.roles.some((role) => role.name === 'user');
            if (!hasUserRole) {
              return res.status(401).json({ error: 'Access Denied' });
            }
      
            const product = await Product.findById(productId);
            if (!product) {
              return res.status(404).json({ error: 'Product not found' });
            }
      
            if (product.user.toString() !== userId) {
              return res.status(401).json({ error: "Impossible de mettre à jour le produit !! Vous n'êtes pas le propriétaire" });
            }

            const bits = await Bits.find({ product: productId }).populate('product');
            if (bits.length > 0) {
              return res.status(406).json({ error: "Impossible de mettre à jour le produit !! il est utilisé par des bits" });
            }

            if(product.status!=="PROCESSING"){
              return res.status(406).json({ error: "Impossible de mettre à jour le produit !! il est validé ou rejecté par l'admin" });
            }
      
            if (req.body.name) {
              updateFields.name = req.body.name;
            }
            if (req.body.price) {
              updateFields.price = req.body.price;
            }
            if (req.body.dateFermeture) {
              updateFields.dateFermeture = req.body.dateFermeture;
            }
            if (req.body.categoryId) {
              updateFields.category = req.body.categoryId;
            }
      
            const updatedProduct = await Product.findByIdAndUpdate(productId, { $set: updateFields }, { new: true });
      
            return res.status(200).json(updatedProduct);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to update product' });
          }
        }

    static async getClosedProducts(req, res) {
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
            const dateNow=moment().format('YYYY-MM-DD HH:mm:ss');
            const closedProducts = await Product.find({ dateFermeture: { $lte: dateNow } });
            return res.status(200).json(closedProducts);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to retrieve closed products' });
          }
        }
    
    static async getProductById(req, res) {
          try {
            const { productId } = req.params;

            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;
        
            const user = await User.findById(userId).populate('roles');
            if (!user) {
              return res.status(404).json({ error: 'Utilisateur introuvable' });
            }
        
            const hasUserRole = user.roles.some((role) => role.name === 'admin' || role.name==='user');
            if (!hasUserRole) {
              return res.status(401).json({ error: 'Access Denied' });
            }
            
            const product = await Product.findById(productId).populate('user').populate('category');
            
            if (!product) {
              return res.status(404).json({ error: 'Product not found' });
            }
            
            return res.status(200).json(product);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to retrieve product' });
          }
        }
  


    static async getValidateProducts(req,res,next){
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
        const validateProducts = await Product.find({ status:'VALIDATED'});
        return res.status(200).json(validateProducts);
      } catch (error) {
        return res.status(500).json({ error: 'Failed to retrieve validate products' });
      }
    }

    static async getRejectedProducts(req,res,next){
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
        const rejectProducts = await Product.find({ status:'REJECTED'});
        return res.status(200).json(rejectProducts);
      } catch (error) {
        return res.status(500).json({ error: 'Failed to retrieve rejected products' });
      }
    }

    static async getProcessingProducts(req,res,next){
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
        const processingProducts = await Product.find({ status:'PROCESSING'});
        return res.status(200).json(processingProducts);
      } catch (error) {
        return res.status(500).json({ error: 'Failed to retrire: product in progress' });
      }
    }

    static async getAllProductsByUserConnected(req, res) {
      try {


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
        
        const products = await Product.find({ user: userId });
        
        return res.status(200).json(products);
      } catch (error) {
        return res.status(500).json({ error: 'Failed to retrieve products' });
      }
    }
    

   static async sortValitadedProductsByCategory(req, res) {
     try {
    const { categoryId } = req.params;

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

    const hasUserRole = user.roles.some((role) => role.name === 'admin' || role.name === 'user');
    if (!hasUserRole) {
      return res.status(401).json({ error: 'Access Denied' });
    }

    const category = await Category.findById(categoryId);
    if (!category) {
      return res.status(404).json({ error: 'Category not found' });
    }

    const products = await Product.find({ category: categoryId,  status:'VALIDATED'});

    return res.status(200).json(products);
  } catch (error) {
    return res.status(500).json({ error: 'Failed to sort products by category' });
  }
}
// QR code for a product
   static async generateQRCode(req, res) {
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

    const hasUserRole = user.roles.some((role) => role.name === 'admin' || role.name === 'user');
     if (!hasUserRole) {
      return res.status(401).json({ error: 'Access Denied' });
    }

 
    const { productId } = req.params;
    const product = await Product.findById(productId);
    const qrData = {
      name: product.name,
      price: product.price,
      status: product.status,
      dateFermeture : product.dateFermeture,
    };

      QRCode.toDataURL(JSON.stringify(qrData), (err, url) => {
        if (err) {
          res.status(500).send('Une erreur s\'est produite');
        } else {
          res.send(`<img src="${url}" alt="QR Code"/>`);
        }
      });
    } 
    catch (error) {
      return res.status(500).json({ error: 'Failed to generate QR code' });
    }
}

  static async getClosedAndValidatedProducts(req, res) {
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
        const dateNow=moment().format('YYYY-MM-DD HH:mm:ss');
        const closedAndValidatedProducts = await Product.find({
          dateFermeture: { $lte: dateNow },
          status: 'VALIDATED',
        }).exec();
        return res.status(200).json(closedAndValidatedProducts);
      } catch (error) {
        return res.status(500).json({ error: 'Failed to retrieve closed and validated products' });
      }
    }

  static async getAvailableAndValidatedProducts(req, res) {
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
    
        const hasUserRole = user.roles.some((role) => role.name === 'user');
        if (!hasUserRole) {
          return res.status(401).json({ error: 'Access Denied' });
        }
        const dateNow=moment().format('YYYY-MM-DD HH:mm:ss');
        const availableAndValidatedProducts = await Product.find({
          dateFermeture: { $gt: dateNow },
          status: 'VALIDATED',
        }).populate('user').exec();
        return res.status(200).json(availableAndValidatedProducts);
      } catch (error) {
        return res.status(500).json({ error: 'Failed to retrieve available and validated products' });
      }
    }
}

module.exports = ProductController;
