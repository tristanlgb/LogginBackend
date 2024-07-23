const { hashPassword, comparePassword } = require('../utils/hash');
const userDao = require('../daos/userDao');
const jwt = require('jsonwebtoken');
const { sendMail } = require('../utils/mailer');
const UserDto = require('../dtos/userDto');

const register = async (req, res) => {
  const { first_name, last_name, email, password } = req.body;
  const existingUser = await userDao.findUserByEmail(email);
  if (existingUser) {
    return res.status(400).json({ message: 'Email already taken' });
  }

  const hashedPassword = await hashPassword(password);
  const newUser = await userDao.createUser({ first_name, last_name, email, password: hashedPassword });
  
  sendMail(email, 'Welcome', 'Thank you for registering');
  
  return res.status(201).json({ message: 'User created', user: new UserDto(newUser) });
};

const login = async (req, res) => {
  const { username, password } = req.body;
  const user = await userDao.findUserByUsername(username);
  if (!user) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const isValid = await comparePassword(password, user.password);
  if (!isValid) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_PRIVATE_KEY, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/'); // Redirect to home page after successful login
};

const logout = (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ message: 'Logged out successfully' });
};

const getCurrentUser = async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: 'Not authenticated' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_PRIVATE_KEY);
    const user = await userDao.findById(decoded.id);
    const userDto = new UserDto(user);
    res.status(200).json({ user: userDto });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

module.exports = { register, login, logout, getCurrentUser };
