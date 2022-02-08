"use strict";

const Security = require("./security.models.js");
const config = require('config');
const SERVER_CFG = config.get("SERVER");
const KEY = SERVER_CFG.api.KEY;
let logger = require("../logger");

module.exports = async (token, user) => {
    var security = new Security(KEY);

    logger.debug(`Decrypting Wallet For ${user.id} ...`);
    let decrypted_token = {
        username: JSON.parse(security.decrypt(token.username, token.iv)),
        token: JSON.parse(security.decrypt(token.token, token.iv)),
        uniqueId: JSON.parse(security.decrypt(token.uniqueId, token.iv))
    };

    logger.info("SUCCESSFULLY DECRYPTED WALLET");
    return decrypted_token;
}