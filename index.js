const express = require('express')
const crypto = require("node:crypto");
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} = require('@simplewebauthn/server')

if (!globalThis.crypto) {
    globalThis.crypto = crypto;
}

const PORT = 3000
const app = express();
const rpID = process.env.NODE_ENV === 'production' ? 'finger-bio.onrender.com' : 'localhost';
const expectedOrigin = process.env.NODE_ENV === 'production'
    ? 'https://finger-bio.onrender.com'
    : 'http://localhost:3000';

// Update CORS settings for mobile access
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

app.use(express.static('./public'))
app.use(express.json())

// States
const userStore = {}
const challengeStore = {}

app.post('/register', (req, res) => {
    const { username, password } = req.body
    const id = `user_${Date.now()}`

    if(!username || !password){
        return res.status(400).json({ error: 'username and password are required' })
    }
    const user = {
        id,
        username,
        password
    }

    userStore[id] = user

    console.log(`Register successfull`, userStore[id])

    return res.json({ id })

})

app.post('/register-challenge', async (req, res) => {
    const { userId } = req.body

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })

    const user = userStore[userId]

    try {
        const challengePayload = await generateRegistrationOptions({
            rpID,
            rpName: 'My Authentication App',
            userID: userId,
            userName: user.username,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
                authenticatorAttachment: 'platform'
            },
            timeout: 60000,
        });

        challengeStore[userId] = challengePayload.challenge;
        return res.json({ options: challengePayload });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Failed to generate challenge' });
    }
})

app.post('/register-verify', async (req, res) => {
    try {
        const { userId, cred } = req.body;

        // Verification configuration
        const verification = await verifyRegistrationResponse({
            response: cred,
            expectedChallenge: challengeStore[userId],
            expectedOrigin,
            expectedRPID: rpID,
            requireUserVerification: false
        });

        if (verification.verified) {
            // Save the credential to the user's record
            const { registrationInfo } = verification;

            // Store the authenticator data in the user record
            userStore[userId] = {
                ...userStore[userId],
                passkey: {
                    credentialID: Buffer.from(registrationInfo.credentialID),
                    credentialPublicKey: Buffer.from(registrationInfo.credentialPublicKey),
                    counter: registrationInfo.counter,
                }
            };

            console.log('Updated user store:', userStore[userId]);
            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Verification failed' });
        }
    } catch (error) {
        console.error('Verification error:', error);
        res.status(400).json({ error: error.message });
    }
});

app.post('/login-challenge', async (req, res) => {
    try {
        const { userId, username } = req.body;


        console.log(username)

        if (!userStore[userId]) {
            return res.status(404).json({ error: 'user not found!' });
        }
        const user = userStore[userId];
        if (user.username !== username) {
            return res.status(400).json({ error: 'Invalid username' });
        }
        if (!user.passkey) {
            return res.status(400).json({ error: 'No passkey registered for this user' });
        }

        const opts = await generateAuthenticationOptions({
            rpID,
            allowCredentials: [{
                id: user.passkey.credentialID,
                type: 'public-key',
                transports: ['internal'],
            }],
            userVerification: 'preferred',
        });

        challengeStore[userId] = opts.challenge;

        return res.json({ options: opts });
    } catch (error) {
        console.error('Login challenge error:', error);
        return res.status(500).json({ error: error.message });
    }
});

app.post('/login-verify', async (req, res) => {
    try {
        const { userId, cred } = req.body;

        if (!userStore[userId]) {
            return res.status(404).json({ error: 'user not found!' });
        }

        const user = userStore[userId];
        const challenge = challengeStore[userId];

        if (!user.passkey) {
            return res.status(400).json({ error: 'No passkey found for this user' });
        }

        const verification = await verifyAuthenticationResponse({
            response: cred,
            expectedChallenge: challenge,
            expectedOrigin,
            expectedRPID: rpID,
            authenticator: user.passkey,
            requireUserVerification: false
        });

        if (verification.verified) {
            // Update the stored counter
            user.passkey.counter = verification.authenticationInfo.newCounter;
            return res.json({ success: true, userId });
        } else {
            return res.status(400).json({ error: 'Verification failed' });
        }
    } catch (error) {
        console.error('Login verification error:', error);
        return res.status(400).json({ error: error.message });
    }
});


app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server started on PORT:${PORT}`);
    console.log(`Server accessible at http://localhost:${PORT}`);
});