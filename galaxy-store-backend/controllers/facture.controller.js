const Commande = require('../models/command');
const jwt = require('jsonwebtoken');
const config = require("../config/auth.config.js");
const PDFDocument = require('pdfkit');
const Facture = require('../models/facture.model');
const Product = require('../models/product')
const fs = require('fs');
const path = require('path');
const os = require('os');
const nodemailer = require('nodemailer');
const User = require('../models/user.model');
const crypto = require('crypto');
const qr = require('qrcode');
const moment = require('moment-timezone');

class FactureController {

    static async generateFacture(req, res,next) {
        const commandeId = req.params.commandeId;
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
        
        const logoPath = path.join(process.cwd(), 'images', 'logo.png');
        try {
            const existingFacture = await Facture.findOne({ command: commandeId });
            if (existingFacture) {
                return res.status(500).json({ error: 'Facture déjà genéré' });
            }
         const facturesExistants = await Facture.countDocuments();
         const matriculeFacture = `FACT-${(facturesExistants + 1).toString().padStart(8, '0')}`;
          const commande = await Commande.findById(commandeId)
            .populate('bits')
            .populate('administator')
            .populate('receptorOfCommand')
            .populate('proprietaryOfProduct');
      
          if (!commande) {
            return res.status(404).json({ message: 'Commande non trouvée' });
          }

          const doc = new PDFDocument();
          const pageWidth = doc.page.width;
          const pageHeight = doc.page.height;
          const cadreWidth = 400;
          const logoWidth = 100;
          const logoHeight = 100;
          const logoX = (pageWidth - logoWidth) / 2;
          const cadreX = (pageWidth - cadreWidth) / 2 -40;
          const cadreY = 50;
          const margeTexte = 10;
          const nombreInformations = 5;
          const hauteurCadre = (nombreInformations * 20) + (margeTexte * 2);
          let positionY = cadreY + margeTexte;
          const receptionistUser = commande.receptorOfCommand.name +' '+commande.receptorOfCommand.firstName;
          const product = await Product.findOne({ _id: commande.bits.product });
          doc.image(logoPath, logoX, 50, { width: logoWidth, height: logoHeight });
          const donneesTableau = [
           ["Facture ID", `${matriculeFacture}`],
           ["Commande ID", `${commande.matriculeCommande}`],
           ["Produit acheté", `${product.name}`],
           ["Montant de la commande", `${commande.montantCommande}`+' €'],
           ["Propriétaire du produit", `${commande.proprietaryOfProduct.name}`+` `+`${commande.proprietaryOfProduct.firstName}`],
           ["Mode de paiement", `${commande.administator.modePaiement}`],
           ["RIB du propriètaire de produit",`${commande.proprietaryOfProduct.rib}`],
           ["Administrateur Responsable", `${commande.administator.name}`+` `+`${commande.administator.firstName}`]
         ];
          const colonne1Largeur = 200;
          const colonne2Largeur = 200;
          const epaisseurBordure = 1;
          doc.image(logoPath, logoX, 50, { width: logoWidth, height: logoHeight });
          doc.lineWidth(epaisseurBordure);
          const congratulatoryMessage = 'Cher(e) client(e), ' + `${receptionistUser}` + ' ,';
          const logoBottomY = 50 + logoHeight;
          doc.y = logoBottomY + 10; 
          doc.fontSize(12).text(congratulatoryMessage, {
          width: cadreWidth,
          align: 'justify',
          lineGap: 18,
          indent: 0,
          });
         positionY += 30;
         const detailMessage = "Nous vous remercions de votre confiance et de votre choix d'avoir fait affaire avec notre application. Veuillez trouver ci-joint la facture correspondant à la prestation de services / à l'achat de produits que vous avez effectué(e) auprès de nous. Cette facture récapitule en détail les produits ou services fournis, ainsi que les montants correspondants. Veuillez prendre note des informations suivantes :";
         doc.fontSize(12).text(detailMessage, {
          width: cadreWidth - (margeTexte * 2),
          align: 'justify',
          lineGap: 10,
          indent: 0,
        });
        positionY += 280;
       for (let i = 0; i < donneesTableau.length; i++) {
         const [libelle, valeur] = donneesTableau[i];
         const celluleX = cadreX + margeTexte;
         const celluleY = positionY - margeTexte;

          doc.fillColor('black').rect(celluleX, celluleY, colonne1Largeur, 20).stroke();
          doc.fillColor('green').rect(celluleX + colonne1Largeur, celluleY, colonne2Largeur, 20).stroke();

          doc.fillColor('black').text(libelle, celluleX + margeTexte, positionY).fontSize(12);
          doc.fillColor('green').text(valeur, celluleX + colonne1Largeur + margeTexte, positionY).fontSize(12);

        positionY += 20;
        }
        const currentDate = moment().format('YYYY-MM-DD HH:mm:ss');
        const oneWeekLater = moment(currentDate).add(7, 'days').format('YYYY-MM-DD HH:mm:ss');
        const additionalParagraph = "Assurez-vous de procéder au paiement avant la date d'échéance qui sera le "+ oneWeekLater;
         doc.moveDown();
         doc.moveDown();
         doc.x = cadreX + margeTexte;
         doc.fillColor('black').fontSize(12).text(additionalParagraph, {
           width: cadreWidth,
           align: 'left',
           lineGap: 10,
           indent: 0,
         });

        const generateQRCode = async (text) => {
          try {
            const qrCodeImage = await qr.toDataURL(text);
            return qrCodeImage;
          } catch (error) {
            console.error('Error generating QR code:', error);
            return null;
          }
        };
        
        const signature = crypto
          .createHash('md5')
          .update(currentDate)
          .digest('hex');
      
        const qrCodeImage = await generateQRCode(signature);
        doc.moveDown();
        doc.moveDown(); 
        doc
        .fontSize(10)
        .fillColor('black')
        .text('Signé Le ' + currentDate, { align: 'right' });
      
      const qrCodeX = cadreX + cadreWidth -17;
      const qrCodeY = positionY + 107; 
      doc.moveDown();
      doc.image(qrCodeImage, qrCodeX, qrCodeY, { width: 100, height: 100 });
  
          let desktopPath;
          if (process.platform === 'win32') {
            desktopPath = path.join(process.env.USERPROFILE, 'Desktop');
          } else {
            desktopPath = path.join(os.homedir(), 'Desktop');
          }
          const facturesDirectory = path.join(desktopPath, 'factures');
          if (!fs.existsSync(facturesDirectory)) {
            fs.mkdirSync(facturesDirectory);
          }
          const fileName = "facture_"+ matriculeFacture +".pdf"
          const filePath = facturesDirectory+'\\'+fileName;
      
          doc.pipe(fs.createWriteStream(filePath));
          doc.end();
          const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
             user: 'galaxystoreenchere@gmail.com',
             pass: 'mjqpnbrqaodainaj'
            },
            });
         const administator = commande.administator.name +' '+commande.administator.firstName;
         const mailOptions = {
           from: 'galaxystoreenchere@gmail.com',
           to: commande.receptorOfCommand.email,
           subject: 'Réception de la facture',
           html: `
          <p>Bonjour Mr/Mme ${receptionistUser},</p>
          <p>J'espère que ce message vous trouve bien. Je vous contacte en tant que administrateur responsable des produits BitShare pour vous envoyer la facture correspondante à votre récente commande.</p>
          <p>Veuillez trouver ci-joint la facture détaillée qui récapitule le produit BitShare que vous avez achetés et le propriétaire de ce produit aussi.</p>
          <p>Assurez-vous de procéder au paiement avant la date d'échéance afin d'éviter tout retard ou problème de traitement de votre commande. Une fois le paiement reçu, nous confirmerons la réception et procéderons à l'expédition de votre commande dans les meilleurs délais.</p>
          <p>Si vous avez des questions ou des préoccupations concernant cette facture ou votre commande, n'hésitez pas à me contacter par courrier électronique à ${commande.administator.email}. Je suis disponible pour vous aider et répondre à toutes vos demandes.</p>
          <p>Cordialement,</p>
          <p>${administator}</p>
          <p>${commande.administator.email}</p>
          <p>Galaxy Store Enchere</p>
         `,
         attachments: [
          {
            filename: 'facture de '+receptionistUser+'.pdf',
            path: filePath
          }
        ]
         };
  
      transporter.sendMail(mailOptions, (error, info) => {
       if (error) {
        console.log(error);
         return res.status(500).json({ message: 'Error sending email' });
          }
       console.log('Email sent: ' + info.response);
        });

        const facture = new Facture({
          matriculeFacture: `FACT-${(facturesExistants + 1).toString().padStart(8, '0')}`,
          command: commande,
          isGenerated: true,
          document: fileName,
          dateEcheance:oneWeekLater,
          status:"PROCESSING"
        });

        await facture.save();
        const updatedCommande = await Commande.updateOne(
          { _id: commandeId },
          { $set: { status: "FACTURED" } }
        );
        return res.status(200).json({ message: 'facture généré avec succés! un mail à été envoyé au récepteur de la commande' });
        } catch (error) {
          console.error('Erreur lors de la génération de la facture PDF', error);
          res.status(500).json({ message: 'Erreur lors de la génération de la facture PDF' });
        }
}
}

module.exports = FactureController;