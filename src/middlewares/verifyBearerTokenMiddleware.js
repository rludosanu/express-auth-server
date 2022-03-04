const jwt = require('jsonwebtoken');

module.exports = function verifyBearerTokenMiddleware(req, res, next) {
  const { authorization } = req.headers;

  if (typeof authorization !== 'string') {
    return res.status(401).send({ message: 'MISSING_ACCESS_TOKEN' });
  }
  
  const [auth_type, auth_value] = authorization.split(' ');

  if (auth_type !== 'Bearer' || !auth_value) {
    return res.status(401).send({ message: 'MISSING_ACCESS_TOKEN' });
  }

  jwt.verify(auth_value, JWT_SECRET, (error, access_token) => {
    if (error) {
      return res.status(401).send({ message: 'INVALID_ACCESS_TOKEN' });
    }
    req.bearer_token = auth_value;
    return next();
  });
}
