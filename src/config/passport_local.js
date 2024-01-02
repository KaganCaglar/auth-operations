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
            const _foundUser = await User.findOne({ email: email });
            isUserExist(_foundUser)
            

            const sifreKontrol = await bcrypt.compare(password, _foundUser.password);
            if (!sifreKontrol) {
                return done(null, false, { message: 'Password is incorrect' });
            } else {

                if (_foundUser && _foundUser.emailActive === false) {
                    return done(null, false, { message: 'Please confirm your email' });
                }else 
                    return done(null, _foundUser);
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
    creationDate: createdAt,
    avatar
};

done(null, newUser);

        });
    });
    




function  isUserExist(user) {
    if (!user) {
        return done(null, false, { message: 'User not found' });
    }
}
}