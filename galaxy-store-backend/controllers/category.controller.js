const Category = require('../models/category.js')
const User = require('../models/user.model.js')
const jwt = require('jsonwebtoken');
const config = require("../config/auth.config.js");
const moment = require('moment');
const Bits = require('../models/bits.js')

class CategoryController {

    static async createCategory(req,res) {

        const { name } = req.body;

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
          //const productExistants = await Product.countDocuments();
          const newCategory = new Category({
            name,
          });
          try {
            const savedCategory = await newCategory.save();      
            return res.status(201).json(savedCategory);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to create category' });
          }
        }
    static async getAllCategorys(req, res,next) {
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
            const categorys = await Category.find();
            return res.status(200).json(categorys);
          } catch (error) {
            console.log(error)
            return res.status(500).json({ error: 'Failed to get categorys' });
          }
        }

    static async deleteCategory(req, res) {
          const { categoryId } = req.params;
      
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }

          if(!categoryId){
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
            const category = await Category.findById(categoryId);
            if (!category) {
              return res.status(404).json({ error: 'Category not found' });
            }
            
            await Category.findByIdAndDelete(categoryId);
            return res.status(200).json({ message: 'Category deleted successfully' });
          } catch (error) {
            return res.status(500).json({ error: 'Failed to delete category' });
          }
        }

    static async updateCategory(req, res) {
          const { categoryId } = req.params;
          const updateFields = {};
      
          if (!req.headers.authorization) {
            return res.status(406).json({ error: 'Token is null' });
          }
      
          if (!categoryId) {
            return res.status(400).json({ error: 'Please provide the category ID' });
          }
      
          const token = req.headers.authorization.split('Bearer ')[1];
          const decodedToken = jwt.verify(token, config.secret);
          const userId = decodedToken.id;
      
          try {
            const user = await User.findById(userId).populate('roles');
            if (!user) {
              return res.status(404).json({ error: 'Utilisateur introuvable' });
            }
      
            const hasUserRole = user.roles.some((role) => role.name === 'admin');
            if (!hasUserRole) {
              return res.status(401).json({ error: 'Access Denied' });
            }
      
            const category = await Category.findById(categoryId);
            if (!category) {
              return res.status(404).json({ error: 'Category not found' });
            }
           
            if (req.body.name) {
              updateFields.name = req.body.name;
            }
    
            const updatedCategory = await Category.findByIdAndUpdate(categoryId, { $set: updateFields }, { new: true });
      
            return res.status(200).json(updatedCategory);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to update category' });
          }
        }
    
    static async getCategoryById(req, res) {
          try {
            const { categoryId } = req.params;

            const token = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = jwt.verify(token, config.secret);
            const userId = decodedToken.id;
        
            const user = await User.findById(userId).populate('roles');
            if (!user) {
              return res.status(404).json({ error: 'Utilisateur introuvable' });
            }
        
            const hasUserRole = user.roles.some((role) => role.name === 'admin' || role.name === 'admin');
            if (!hasUserRole) {
              return res.status(401).json({ error: 'Access Denied' });
            }
            
            const category = await Category.findById(categoryId);
            
            if (!category) {
              return res.status(404).json({ error: 'Category not found' });
            }
            
            return res.status(200).json(category);
          } catch (error) {
            return res.status(500).json({ error: 'Failed to retrieve category' });
          }
        }
     
}

module.exports = CategoryController;