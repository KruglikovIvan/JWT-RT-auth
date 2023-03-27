const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const { promisify } = require('util');

// Create the Express app
const app = express();

// Use CORS and body parser middleware
app.use(cors());
app.use(bodyParser.json());

// Get the private and public keys from environment variables
const privateKey = process.env.JWT_PRIVATE_KEY;
const publicKey = process.env.JWT_PUBLIC_KEY;

// Function to create a token for a given user
function createToken(sub) {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 3600;
    const payload = {
        sub,
        iat: now,
        exp: now + expiresIn,
    };
    // Return a promise to sign the payload with the private key and the RS256 algorithm
    return promisify(jwt.sign)(payload, privateKey, { algorithm: 'RS256' });
}

// Function to validate a token
function validateToken(token) {
    // Return a promise to verify the token with the public key and the RS256 algorithm
    return promisify(jwt.verify)(token, publicKey, { algorithms: ['RS256'] });
}

// Middleware function to authenticate the user based on the token
function authMiddleware(req, res, next) {
    // Get the authorization header from the request
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
        // Return a 401 unauthorized response if the header is not present
        return res.status(401).end();
    }
    // Extract the token from the header
    const [bearer, token] = authorizationHeader.split(' ');
    if (bearer !== 'Bearer' || !token) {
        // Return a 401 unauthorized response if the token is not present
        return res.status(401).end();
    }
    // Validate the token and extract the payload
    validateToken(token)
        .then((payload) => {
            if (payload.exp < Date.now() / 1000) {
                // Return a 401 unauthorized response if the token has expired
                return res.status(401).end();
            }
            // Set the user property on the request object to the subject of the token
            req.user = { sub: payload.sub };
            next();
        })
        .catch(() => {
            // Return a 401 unauthorized response if the token is invalid
            res.status(401).end();
        });
}

// Route to handle login requests
app.post('/login', async (req, res) => {
    try {
        const { username } = req.body;
        // Create a token for the user and send it back in the response
        const token = await createToken(username);
        res.json({ token });
    } catch (err) {
        console.error(err);
        // Return a 500 internal server error response if there is an error
        res.status(500).end();
    }
});

// Default route for handling invalid requests
app.use((req, res) => {
    // Return a 404 not found response for all other requests
    res.status(404).end();
});

// Start the server on port 8080
const server = app.listen(8080, () => {
    console.log(`Server started at http://localhost:${server.address().port}`);
});