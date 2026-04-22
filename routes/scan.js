const express = require('express');
const router = express.Router();
const {scanURL} = require('../utils/checker');

router.post('/', async(req, res) =>{
    const {url} = req.body;

    if (!url){
        return res.status(400).json({error:"Url is required"});
    }
    try{
        const result = await scanURL(url);
        res.json(result);
    }catch(err){
        console.log("ERROR: ", err)
        res.status(500).json({error: "failed to scan url"});
    }
});
module.exports = router;