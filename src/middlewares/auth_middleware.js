const sessionOpened = function (req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    else {
        req.flash('error', ['Please log in first']);
        res.redirect('/login');
    }
}

const notLoggedIn = function (req, res, next) {
    if (!req.isAuthenticated()) {
        return next();
    }
    else {
        res.redirect('/dashboard');
    }
}

module.exports = {
    sessionOpened,
    notLoggedIn
}