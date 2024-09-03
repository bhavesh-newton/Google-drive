const fs = require('fs');
const express = require('express');
const path = require('path');
const dotenv = require("dotenv");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { connectDB, prismaClient } = require("./config/database");
const port = 3000;

const app = express();
app.use(express.json());
dotenv.config();

app.post('/signup', async (req, res) => {
    const user = req.body;
    const password = await bcrypt.hash(user.password, 10);
    user.password = password;
    try {
        await prismaClient.users.create({
            data: user
        });
        res.send('signup successful')
    } catch (err) {
        res.status(400).send('User already exists')
    }
});

app.post('/auth-token', (req, res) => {
    const refreshToken = req.headers.refreshtoken;
    try {
        const { name, email } = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET);
        const token = jwt.sign({ name, email }, process.env.JWT_SECRET, {
            expiresIn: '24h'
        })
        const newRefreshToken = jwt.sign({ name, email }, process.env.REFRESH_JWT_SECRET, {
            expiresIn: '48h'
        })
        res.send({ token, refreshToken: newRefreshToken })
    } catch (err) {
        res.status(401).send('Unauthorised user')
    }
})

app.post('/signin', async (req, res) => {
    const { email, password } = req.body;
    const user = await prismaClient.users.findUnique({
        where: {
            email: email
        }
    });
    if (user) {
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (isPasswordCorrect) {
            const payload = {
                name: user.name,
                email
            };
            const secret = process.env.JWT_SECRET;
            const refreshSecret = process.env.REFRESH_JWT_SECRET;
            const token = jwt.sign(payload, secret, {
                expiresIn: '24h'
            })
            const refreshToken = jwt.sign(payload, refreshSecret, {
                expiresIn: '48h'
            })
            res.send({ token, refreshToken })
        } else {
            res.status(401).send('Wrong password.')
        }
    } else {
        res.status(404).send("User doesn't exist.")
    }
})

function authenticationMiddleware(req, res, next) {
    try {
        const token = req.headers.authorization
        jwt.verify(authToken, process.env.JWT_SECRET)
        next()
    } catch (err) {
        res.status(401).send("Unauthorized user.")
    }
}





app.get('/user/:userId', authenticationMiddleware, async (req, res) => {
    const { userId } = req.params;
    const user = await prismaClient.users.findUnique({
        where: {
            id: Number(userId)
        }
    })
    res.send({
        id: userId,
        name: user.name,
        email: user.email
    })

})

app.get('/files-and-folders/*', (req, res) => {
    const subPath = req.params[0];
    const folderPath = './shared/' + subPath
    const filesAndFolders = fs.readdirSync(folderPath);
    const result = []
    for (const name of filesAndFolders) {
        const isFolder = fs.statSync(folderPath + "/" + name).isDirectory();
        const data = {
            name,
            type: isFolder ? 'folder' : 'file'
        }
        result.push(data)
    }
    res.send(result)
})

app.get('/file/*', (req, res) => {
    const subPath = req.params[0];
    const filePath = './shared/' + subPath;
    if (fs.existsSync(filePath)) {
        const absolutePath = path.resolve(__dirname, filePath);
        res.sendFile(absolutePath);
    } else {
        res.status(404).send('File not found');
    }
})

app.post('/file/*', (req, res) => {
    const subPath = req.params[0];
    const filePath = './shared/' + subPath;
    if (fs.existsSync(filePath)) {
        res.status(400).send('File already exist.');
    } else {
        const content = req.body;
        fs.writeFileSync(filePath, JSON.stringify(content, null, 2));
        res.send('File created successfully.')
    }
})

connectDB().then(() => {
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
});