const LocalStrategy = require('passport-local').Strategy;
const User = require('../model/user_model');
const bcrypt = require('bcrypt');

module.exports = function (passport) {
    const options = {
        usernameField: 'email',
        passwordField: 'password'
    };

    passport.use(new LocalStrategy(options, async (email, password, done) => {
        try {
            const foundUser = await User.findOne({ email: email });

            isUserExist(foundUser, done);

            const isPasswordValid = await bcrypt.compare(password, foundUser.password);
            if (!isPasswordValid) {
                return done(null, false, { message: 'Hatalı şifre' });
            } else {
                if (foundUser && foundUser.emailAktif === false) {
                    return done(null, false, { message: 'Lütfen e-postanızı doğrulayın' });
                } else {
                    return done(null, foundUser);
                }
            }
        } catch (err) {
            return done(err);
        }
    }));

    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function (id, done) {
        User.findById(id, function (err, user) {
            if (err || !user) {
                return done(err, null);
            }

            const { id, email, firstName, lastName, password, createdAt, avatar } = user;

            const newUser = {
                id,
                email,
                firstName,
                lastName,
                password,
                createdAt,
                avatar
            };

            done(null, newUser);
        });
    });

    async function isUserExist(user, done) {
        if (!user) {
            return done(null, false, { message: 'Kullanıcı bulunamadı' });
        }
    }
};
