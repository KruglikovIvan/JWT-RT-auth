const express = require('express');

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