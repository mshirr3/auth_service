import fs from 'fs-extra'
privateKey = fs.readFileSync('private.pem', 'utf8')

module.exports = {
    apps: [
        {
            name:'PICTURE_IT',
            script: './src/server.js',
            watch: "true",
            env: {
                NODE_ENV:'production',
                PORT:'3200',
                BASE_URL:"/",
                ACCESS_TOKEN_SECRET: privateKey

            }
        }
    ]
}