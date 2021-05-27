const configs = require("./config.json");
const express = require("express");
const session = require("express-session");
var SequelizeStore = require("connect-session-sequelize")(session.Store);
const swaggerUi = require('swagger-ui-express');
const morgan = require("morgan");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
var ipaddr = require('ipaddr.js');
const {
    handleError,
    ErrorHandler
} = require("./controllers/error.js")

const swaggerDocument = require("./openapi_dev.json");
const db = require("./models");
var Provider = db.providers;
var Platform = db.platforms;

const https = require("https")

var app = express();

var corsOptionsDelegate = (req, callback) => {
    var validIp = ipaddr.isValid(req.ip);
    var address = ipaddr.process(req.ip);

    if (req.ip == "127.0.0.1") {
        corsOptions = {
            origin: true
        }

        console.log("Valid IP: ", validIp);
        console.log(address.kind());
        console.log(req.ip);

        return callback(null, corsOptions)
    };

    corsOptions = {
        origin: false
    }
    console.log("Valid IP: ", validIp);
    console.log(address.kind());
    console.log(req.ip + " blocked");
    const error = new ErrorHandler(403, "Forbidden");
    return callback(error.message, corsOptions);
}

app.use(cors(corsOptionsDelegate));

app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));

// app.use(session({
//     secret: configs.api.SESSION_SECRET,
//     resave: false,
//     saveUninitialized: true,
//     store: new SequelizeStore({
//         db: db.sequelize,
//     }),
//     cookie: {
//         secure: false
//     }
// }));

// app.use(express.static('public'));

// Create swagger docs
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// logger
var successLogStream = fs.createWriteStream(path.join(__dirname, "logs/success.log"), {
    flags: 'a'
})
var errorLogStream = fs.createWriteStream(path.join(__dirname, "logs/error.log"), {
    flags: 'a'
});

// setup the logger middleware
app.use([morgan('combined', {
        skip: function (req, res) {
            return (res.statusCode <= 599 && res.statusCode >= 400)
        },
        stream: successLogStream
    }),
    morgan('combined', {
        skip: function (req, res) {
            return (res.statusCode <= 399 && res.statusCode >= 100)
        },
        stream: errorLogStream
    })

])

// Auths
require("./controllers/googleAuth.js")(app, configs);

// DATABASE
(async () => {
    try {
        await db.sequelize.sync({
            alter: true,
            alter: {
                drop: false
            }
        });

        // create default providers and platforms
        let providers = await Provider.findAll();
        let platforms = await Platform.findAll();

        if (providers.length < 1) {
            // Create default providers
            await Provider.bulkCreate([{
                name: "google",
                description: "Made by Google Inc"
            }])
        };

        if (platforms.length < 1) {
            let defaultGoogle = await Provider.findAll({
                where: {
                    name: "google"
                }
            })

            if (defaultGoogle.length > 1) {
                throw new ErrorHandler(409, "duplicate Providers");
            }

            // Create default providers
            await Platform.bulkCreate([{
                name: "gmail",
                type: "email",
                providerId: defaultGoogle[0].id
            }])
        };
    } catch (error) {
        console.error(error)
    }
})();

// ROUTES
require("./routes/routes.js").development(app, configs, db);

// error handler
let errorHandler = (err, req, res, next) => {
    if (err.statusCode) {
        return handleError(err, res);
    };

    console.error(err)
}

app.use(errorHandler);

var httpsServer = ""
if ((configs.hasOwnProperty("ssl_api")) && fs.existsSync(configs.ssl_api.CERTIFICATE) && fs.existsSync(configs.ssl_api.KEY) && fs.existsSync(configs.ssl_api.PEM)) {
    let privateKey = fs.readFileSync(configs.ssl_api.KEY, 'utf8');
    let certificate = fs.readFileSync(configs.ssl_api.CERTIFICATE, 'utf8');
    // let certificate = fs.readFileSync(configs.ssl_api.PEM, 'utf8');
    let ca = [
        fs.readFileSync(configs.ssl_api.PEM)
    ]
    let credentials = {
        key: privateKey,
        cert: certificate,
        ca: ca
    };
    httpsServer = https.createServer(credentials, app);
    httpsServer.listen(configs.ssl_api.DEV_API_PORT, "127.0.0.1");
    console.log("Development [+] Running secured on port:", configs.ssl_api.DEV_API_PORT)
    app.runningPort = configs.ssl_api.DEV_API_PORT
    app.is_ssl = true
} else {
    console.log("Development [+] Running in-secured on port:", configs.api.DEV_API_PORT)
    app.listen(configs.api.DEV_API_PORT, "127.0.0.1", 511, () => {
        console.log(`Development server is running on port ${configs.api.DEV_API_PORT}`)
    });
    app.runningPort = configs.api.DEV_API_PORT
    app.is_ssl = false
}