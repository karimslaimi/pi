const Commande = require('../models/command');
const Bits = require('../models/bits.js');
const Product = require('../models/product.js')
const User = require('../models/user.model.js')
const jwt = require('jsonwebtoken');
const config = require("../config/auth.config.js");
const moment = require('moment-timezone');
const Facture = require('../models/facture.model')
const stripe = require('stripe')('sk_test_51NNzwQCep0ThQNikMatfmzagKC9JJHYDMVOJj117y2d79DdSxNGFXT0EMpNGai847MAF771f0PkWAR5qA8iIN9Oh00984fneQE');
const Transaction = require('../models/transaction.model')
class PaymentController{

    static async payFacture(req, res,next) {
        const { idFacture } = req.params;
        const { rib, montant} = req.body;
        if(!idFacture){
          return res.status(404).json({ error: 'Veuiller entrer les informations nécessaires pour effectuer le paiement' });
        }
        const facture  = await Facture.findById(idFacture).populate('command').exec();
        if (!facture) {
          return res.status(404).json({ error: 'Facture introuvable' });
        }
        if(facture.isPayed){
          return res.status(406).json({ error: 'Facture déjà payé' });
        }
        if(facture.isRejected){
          return res.status(406).json({ error: 'Facture déjà rejeté' });
        }
        const command = await Commande.findById(facture.command._id).populate('bits')
        .populate('administator')
        .populate('receptorOfCommand')
        .populate('proprietaryOfProduct').exec();
        if (!command) {
            return res.status(404).json({ error: 'Commande introuvable' });
          }
        const modePaiement = "sepa_debit";
        const nom = command.proprietaryOfProduct.name;
        const email = command.proprietaryOfProduct.email;
        const currency = "EUR"

        try {
            const paiement = await stripe.paymentIntents.create({
              payment_method_types: [modePaiement],
              amount: montant,
              currency: currency,
              payment_method_data: {
                type: 'sepa_debit',
                sepa_debit: {
                  iban: rib,
                },
                billing_details: {
                  name: nom,
                  email:email,
                  address: {
                    line1: '123 Main Street',
                    country:'US'
                  }
                }
              },
            });
            console.log("paiement réussi");
            await Facture.updateOne(
                { _id: idFacture },
                { $set: { status: "PAYED",isPayed:true } }
              );
            await Commande.updateOne(
                { _id: command._id },
                { $set: { status: "COMPLETED" } }
              );
            const transaction = new Transaction({
              ribEmetteur:command.receptorOfCommand.rib,
              ribRecepteur:command.proprietaryOfProduct.rib,
              isDone:true,
              montantTransaction:command.montantCommande,
              datePaiement:moment().format('YYYY-MM-DD HH:mm:ss')
            });
            await transaction.save(); 
            res.send(paiement);
          } catch (error) {
            console.error(error);
            res.status(500).send('Une erreur est survenue lors du paiement.');
          }    }
    
}
module.exports = PaymentController;