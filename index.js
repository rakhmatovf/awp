const express = require('express');
const app = express();
const { awpMiddleware } = require('./server');

app.use(awpMiddleware);
app.use(express.static('.'));

app.get('/', (req, res) => {
  res.send('Добро пожаловать в защищенное веб-приложение!');
});

app.listen(5000, () => {
  console.log('Веб-приложение запущено на порту 5000');
});