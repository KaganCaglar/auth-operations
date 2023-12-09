const sessionOpened = function (req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    else {
        req.flash('error', ['Lütfen önce oturum açın']);
        res.redirect('/login');
    }
}

const notLoggedIn = function (req, res, next) {
    if (!req.isAuthenticated()) {
        return next();
    }
    else {-
        res.redirect('/yonetim');
    }
}

module.exports = {
    sessionOpened,
    notLoggedIn
}