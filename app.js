const express = require('express')
const scanRoute = require('./routes/scan')

const app = express()
app.use(express.json())

app.use('/scan', scanRoute);

app.listen(3000, () =>{
    console.log('http://localhost:3000')
})