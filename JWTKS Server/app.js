require("dotenv").config();
const express = require('express')
const app = express()
const cors = require('cors')

app.use(express.static("static"))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cors())

const clientRouter = require('./router/client')
app.use('/', clientRouter)


//port
const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
});
