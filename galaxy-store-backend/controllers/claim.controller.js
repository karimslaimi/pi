const Claim = require('../models/claim.model');

class ClaimController {

  static async getAllClaims(req, res) {
    try {
      // Find all claims
      const claims = await Claim.find();

      res.status(200).json({ claims });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async createClaim(req, res) {
    try {
      const { description, claimType, refId, userId } = req.body;

      let imageUrl = '';

      if (req.file) {
        imageUrl = `${req.protocol}://${req.get("host")}/images/`;
        imageUrl = imageUrl + req.file.filename;
      }

      const claim = await Claim.create({
        description,
        image: imageUrl,
        claimType,
        refId,
        user: userId
      });

      res.status(201).json({ claim });
    } catch (error) {
      res.status(500).json({ error: error });
    }
  }

  static async getClaim(req, res) {
    try {
      const { claimId } = req.params;

      const claim = await Claim.findById(claimId).populate('user');

      if (!claim) {
        return res.status(404).json({ error: 'Claim not found' });
      }

      res.json({ claim });
    } catch (error) {
      res.status(500).json({ error: 'Failed to retrieve claim' });
    }
  }

  static async updateClaim(req, res) {
    try {
      const { claimId } = req.params;
      const { status, reply } = req.body;

      const claim = await Claim.findByIdAndUpdate(
        claimId,
        { status, reply },
        { new: true }
      );

      if (!claim) {
        return res.status(404).json({ error: 'Claim not found' });
      }

      res.json({ claim });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update claim' });
    }
  }

  static async deleteClaim(req, res) {
    try {
      const { claimId } = req.params;

      const claim = await Claim.findByIdAndDelete(claimId);

      if (!claim) {
        return res.status(404).json({ error: 'Claim not found' });
      }

      res.json({ message: 'Claim deleted successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to delete claim' });
    }
  }

  static async getClaimsByUserId(req, res) {
    try {
      const { userId } = req.params;

      const claims = await Claim.find({ user: userId });

      res.status(200).json({ claims });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async getClaimsByStatus(req, res) {
    try {
      const { status } = req.params;

      const claims = await Claim.find({ status });
      
      res.status(200).json({ claims });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}

module.exports = ClaimController;
