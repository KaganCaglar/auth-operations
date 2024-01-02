// Database connection
require('./src/config/database');

const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const MongoDBStore = require('connect-mongodb-session')(session);
const authRouter = require('./src/routers/auth_router');
const dashboardRouter = require('./src/routers/dashboard_router'); 
const { MONGODB_URI, PORT, SESSION_SECRET } = process.env;

const sessionStore = new MongoDBStore({
    uri: MONGODB_URI,
    collection: 'sessions'
});

// Winston Logger
const logger = require('./src/config/utils/logger');

app.set('view engine', 'ejs');
app.set('views', path.resolve(__dirname, './src/views'));

app.use(expressLayouts);
app.use(express.static('public'));
app.use("/uploads", express.static(path.join(__dirname, '/src/uploads')));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    },
    store: sessionStore
}));
app.use(flash());
app.use((req, res, next) => {
    res.locals.validation_error = req.flash('validation_error');
    res.locals.success_message = req.flash('success_message');
    res.locals.email = req.flash('email');
    res.locals.firstName = req.flash('firstName');
    res.locals.lastName = req.flash('lastName'); 
    res.locals.password = req.flash('password');
    res.locals.confirmPassword = req.flash('confirmPassword'); 
    res.locals.login_error = req.flash('error');
    next();
});
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: true }));
app.use('/', authRouter);
app.use('/dashboard', dashboardRouter);

app.get('/api', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Cache-Control', 's-max-age=1, stale-while-revalidate');

    res.json({ message: 'hello', counter: req.session.counter, user: req.user });
});

app.listen(process.env.PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
