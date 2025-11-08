const express = require('express');
const app = express();
const { awpMiddleware } = require('./server');

// ✅ Применяем middleware ко ВСЕМ запросам
app.use(awpMiddleware);
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Xavfsiz veb-ilovaga xush kelibsiz!');
});

app.get('/about', (req, res) => {
  res.send('Страница "О нас"');
});

app.listen(5000, () => {
  console.log('Веб-приложение запущено на порту 5000');
});