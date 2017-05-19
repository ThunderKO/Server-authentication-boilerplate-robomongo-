const jwt = require('jwt-simple');

const User = require('../models/user');

const config = require('../config');

// sub: subject of the token
// iat: issue at time
function tokenForUser(user){
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(request, response, next) {
  // User has already had their email and password auth'd
  // We just need to give them a token
  response.send({ token: tokenForUser(request.user) });
}

exports.signup = function(request, response, next) {
  console.log(request.body);
  const email = request.body.email;
  const password = request.body.password;

  if(!email || !password ) {
    return response.status(422).send({ error: 'You must provide email and password' });
  }

  // See if a user with the given email exists
  User.findOne({ email: email }, function(err, existingUser) {
    if(err) { return next(err); }
    // If a user with email does exists, return an error
    if(existingUser) { return response.status(422).send({ error: 'Email is in use' }); }
    // if a user with email does NOT exist, create and save user record
    const user = new User({
      email: email,
      password: password
    });
    user.save(function(err) {
      if(err) { return next(err); }
    });
    // respond to request indicating the user was created
    response.json({ token: tokenForUser(user) });
  });
};
