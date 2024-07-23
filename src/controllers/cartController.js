const Cart = require('../models/Cart');
const Ticket = require('../models/Ticket');
const { sendMail } = require('../utils/mailer');
const { AppError, errorDictionary } = require('../utils/errorHandler');

exports.addProductToCart = async (req, res) => {
    try {
        const { cid, pid } = req.params;
        const { quantity } = req.body;

        const cart = await Cart.findById(cid);
        const productIndex = cart.products.findIndex(p => p.product.toString() === pid);

        if (productIndex !== -1) {
            cart.products[productIndex].quantity += quantity;
        } else {
            cart.products.push({ product: pid, quantity });
        }

        await cart.save();
        res.json({ status: 'success', payload: cart });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};

exports.removeProductFromCart = async (req, res) => {
    try {
        const { cid, pid } = req.params;

        const cart = await Cart.findById(cid);
        cart.products = cart.products.filter(p => p.product.toString() !== pid);

        await cart.save();
        res.json({ status: 'success', payload: 
            cart });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};

exports.updateProductQuantity = async (req, res) => {
    try {
        const { cid, pid } = req.params;
        const { quantity } = req.body;

        const cart = await Cart.findById(cid);
        const productIndex = cart.products.findIndex(p => p.product.toString() === pid);

        if (productIndex !== -1) {
            cart.products[productIndex].quantity = quantity;
            await cart.save();
            res.json({ status: 'success', payload: cart });
        } else {
            res.status(404).json({ status: 'error', message: 'Product not found in cart' });
        }
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};

exports.clearCart = async (req, res) => {
    try {
        const { cid } = req.params;

        const cart = await Cart.findById(cid);
        cart.products = [];
        await cart.save();
        res.json({ status: 'success', payload: cart });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};

const newTicket = new Ticket({
    code: Math.random().toString(36).substring(7),
    purchase_datetime: new Date(),
    amount,
    purchaser: req.user.email
});
await newTicket.save();

cart.products = cart.products.filter(p => !unavailableProducts.includes(p.product._id));
await cart.save();

sendMail(req.user.email, 'Purchase Confirmation', 'Thank you for your purchase');

res.json({ status: 'success', payload: newTicket, unavailableProducts });
 try (err) => {
res.status(500).json({ status: 'error', message: err.message });
}
;


