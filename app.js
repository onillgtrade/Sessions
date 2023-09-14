const express = require('express');
const ejs = require('ejs');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3000;
app.set('views', path.join(__dirname, 'src/views'));

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true
}));

app.get('/', (req, res) => {
    if (req.session.loggedIn) {
        res.render('home', { username: req.session.username});
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, email, password } = req.body;
    const usersData = JSON.parse(fs.readFileSync('./datajson/users-login.json', 'utf8'));

    const user = usersData.find(user => user.username === username);

    if (user && bcrypt.compareSync(password, user.password)) {
        req.session.loggedIn = true;
        req.session.username = username;
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});


app.get('/register', (req, res) => {
  res.render('register', { error: null }); // Pasa 'null' o un mensaje de error vacío
});
app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  const saltRounds = 10;

  const usersData = JSON.parse(fs.readFileSync('./datajson/users-login.json', 'utf8'));

   // Validar el email usando una expresión regular simple.
   const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
   if (!emailRegex.test(email)) {
       return res.render('register', { error: 'Invalid email address' });
   }

   // Validar el password: al menos 8 caracteres y alfanumérico.
   if (password.length < 8 || !/^(?=.*[0-9])(?=.*[a-zA-Z])([a-zA-Z0-9]+)$/.test(password)) {
       return res.render('register', { error: 'Password must be at least 8 characters long and contain at least one letter and one number' });
   }

  const existingUser = usersData.find(user => user.email === email );

  if (existingUser) {
      // El nombre de usuario ya está en uso. Muestra un mensaje de error.
      return res.render('register', { error: 'Change Username or Email used' });
  }

  //Aqui se agregan los datos al Json
  const hashedPassword = bcrypt.hashSync(password, saltRounds);
  usersData.push({ username, email, password: hashedPassword });
  fs.writeFileSync('./datajson/users-login.json', JSON.stringify(usersData, null, 3));
  res.redirect('/login');
});



app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
      if (err) {
          console.error('Error al cerrar la sesión:', err);
      }
      res.redirect('/login');
  });
});


function isAuthenticated(req, res, next) {
  if (req.session.loggedIn) {
      return next(); // El usuario está autenticado, permitir el acceso.
  }
  res.redirect('/login'); // El usuario no está autenticado, redirigir al login.
}

// Aplica el middleware de autenticación a las rutas protegidas.
app.get('/', isAuthenticated);

app.get('/login', (req, res) => {
  if (req.session.loggedIn) {
      res.redirect('/');
  } else {
      res.render('login');
  }
});



app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});
