module.exports = (validator) => validator.object({
  email: validator.string().email(),
  password: validator.string().min(8).max(20)
});
