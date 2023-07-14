function generateShareableLinks(text, link) {
    return {
        facebook: `https://www.facebook.com/sharer.php?u=${encodeURIComponent(link)}&quote=${encodeURIComponent(text)}`,
        twitter: `https://twitter.com/intent/tweet?url=${encodeURIComponent(link)}&text=${encodeURIComponent(text)}`,
        linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(link)}&title=${encodeURIComponent(text)}`,
        instagram: `https://www.instagram.com/?url=${encodeURIComponent(link)}&caption=${encodeURIComponent(text)}`,
        reddit: `https://www.reddit.com/submit?url=${encodeURIComponent(link)}&title=${encodeURIComponent(text)}`,
    };
}

exports.getSocialMediaLinks = async (req, res, next) => {

    const { text, imagePath } = req.body;

    const shareableLinks = generateShareableLinks(text, imagePath);

    res.json(shareableLinks);
};


