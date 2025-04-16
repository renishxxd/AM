require("dotenv").config();
const express = require("express");
const path = require("path");
const cors = require("cors");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";

app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/ecommerceDB", {

  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("Connected to MongoDB"))
.catch(err => console.error("MongoDB connection error:", err));

const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  profilePicture: { type: String, default: 'default-avatar.png' },
  joinedDate: { type: Date, default: Date.now },
  wishlist: [{
    id: Number,
    name: String,
    price: Number,
    img: String,
    category: String,
    addedAt: Date
  }]
});
const User = mongoose.model("User", UserSchema);

// Order Schema for tracking purchases
const OrderSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [{
    id: Number,
    name: String,
    price: Number,
    quantity: Number,
    img: String
  }],
  totalAmount: Number,
  status: {
    type: String,
    enum: ['pending', 'processing', 'shipped', 'delivered'],
    default: 'pending'
  },
  shippingAddress: String,
  orderDate: { type: Date, default: Date.now }
});
const Order = mongoose.model("Order", OrderSchema);

// UserActivity Schema for tracking user actions
const UserActivitySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  activityType: {
    type: String,
    enum: ['login', 'purchase', 'cart_update', 'customization_request', 'contact_form']
  },
  details: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
});
const UserActivity = mongoose.model("UserActivity", UserActivitySchema);

// Cart Schema
const CartSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [{
    id: Number,
    name: String,
    price: Number,
    quantity: Number,
    img: String
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Cart = mongoose.model("Cart", CartSchema);

// Contact Schema
const ContactSchema = new mongoose.Schema({
  fullName: String,
  email: String,
  phone: String,
  address: String,
  message: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  userEmail: String,
  date: { type: Date, default: Date.now }
});
const Contact = mongoose.model("Contact", ContactSchema);

// Payment Schema (For storing payment details)
const PaymentSchema = new mongoose.Schema({
  customerId: String,
  name: String,
  email: String,
  contact: String,
  address: String,
  paymentMethod: String,
  upi: String,
  cardName: String,
  cardNumber: String,
  expiry: String,
  cvv: String,
  amount: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  userEmail: String,
  date: { type: Date, default: Date.now }
});
const Payment = mongoose.model("Payment", PaymentSchema);

// Customization Schema
const CustomizationSchema = new mongoose.Schema({
  fabricType: String,
  dressType: String,
  color: String,
  size: String,
  quantity: Number,
  phone: String,
  additionalNotes: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  userEmail: String,
  date: { type: Date, default: Date.now }
});
const Customization = mongoose.model("Customization", CustomizationSchema);

// Email Transporter (for sending emails)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Sign Up Route
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Error signing up" });
  }
});

// Sign In Route
app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });
    
    // Track login activity
    await trackActivity(user._id, 'login', { email });

    res.json({ message: "Login successful", token, userId: user._id });
  } catch (error) {
    res.status(500).json({ message: "Error signing in" });
  }
});

// Middleware for authentication
const authMiddleware = (req, res, next) => {
    try {
        const token = req.header("Authorization");
        if (!token) {
            return res.status(401).json({ message: "Access Denied - No Token" });
        }

        // Handle both "Bearer token" and plain token formats
        const tokenString = token.startsWith('Bearer ') ? token.slice(7) : token;
        
        const verified = jwt.verify(tokenString, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        console.error('Auth Error:', err.message);
        res.status(401).json({ message: "Invalid Token", error: err.message });
    }
};

// User Account Route
app.get("/account/:userId", authMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;
    // Verify that the requesting user matches the userId
    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Access Denied" });
    }

    const user = await User.findById(userId).select('-password');
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ 
      message: "Welcome to your account", 
      user: { 
        username: user.username, 
        email: user.email,
        id: user._id
      } 
    });
  } catch (error) {
    res.status(500).json({ message: "Error fetching user data" });
  }
});

// Handle Contact Form Submission (Save to MongoDB + Send Email)
app.post("/send-email", authMiddleware, async (req, res) => {
  try {
    const { fullName, email, phone, address, message } = req.body;
    const user = await User.findById(req.user.userId);
    const newContact = new Contact({ 
      fullName, 
      email, 
      phone, 
      address, 
      message,
      userId: req.user.userId,
      username: user.username,
      userEmail: user.email
    });
    await newContact.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Contact Form Submission",
      text: `Thank you, ${fullName}, for contacting us! We will get back to you soon.`
    };
    
    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: "Details saved and email sent successfully!" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error processing the request." });
  }
});

// Handle Payment Form Submission
app.post("/pay", authMiddleware, async (req, res) => {
  try {
    const { name, email, contact, address, paymentMethod, upi, cardName, cardNumber, expiry, cvv, amount } = req.body;
    const user = await User.findById(req.user.userId);
    const customerId = "CUST" + Math.floor(100000 + Math.random() * 900000);
    const newPayment = new Payment({ 
      customerId, 
      name, 
      email, 
      contact, 
      address, 
      paymentMethod, 
      upi, 
      cardName, 
      cardNumber, 
      expiry, 
      cvv, 
      amount,
      userId: req.user.userId,
      username: user.username,
      userEmail: user.email
    });

    await newPayment.save();
    res.json({ success: true, message: "Payment details saved successfully!", customerId });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error processing the payment." });
  }
});

// Get all payments (admin view)
app.get("/all-payments", authMiddleware, async (req, res) => {
  try {
    const payments = await Payment.find().sort({ date: -1 });
    res.json(payments);
  } catch (error) {
    console.error("Error fetching payments:", error);
    res.status(500).json({ error: "Error fetching payments" });
  }
});

// Get user's payments
app.get("/payments", authMiddleware, async (req, res) => {
  try {
    const payments = await Payment.find({ userId: req.user.userId }).sort({ date: -1 });
    res.json(payments);
  } catch (error) {
    console.error("Error fetching payments:", error);
    res.status(500).json({ error: "Error fetching payments" });
  }
});

app.get("/users", async (req, res) => {
  try {
    const users = await User.find(); // Fetch all user records
    res.json(users); // Return the user records as JSON
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Error fetching users" });
  }
});

// Add a new user
app.post("/users", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User created successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Error creating user" });
  }
});

// Update a user
app.put("/users/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const updatedUser = await User.findByIdAndUpdate(userId, req.body, { new: true });
    if (!updatedUser) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User updated successfully!", user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: "Error updating user" });
  }
});

// Delete a user
app.delete("/users/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const deletedUser = await User.findByIdAndDelete(userId);
    if (!deletedUser) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting user" });
  }
});

// Get all contacts (admin view)
app.get("/all-contacts", authMiddleware, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ date: -1 });
    res.json(contacts);
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ error: "Error fetching contacts" });
  }
});

// Get user's contacts
app.get("/contacts", authMiddleware, async (req, res) => {
  try {
    const contacts = await Contact.find({ userId: req.user.userId }).sort({ date: -1 });
    res.json(contacts);
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ error: "Error fetching contacts" });
  }
});

// Get all customizations (admin view)
app.get("/customizations", authMiddleware, async (req, res) => {
  try {
    // Check if user is admin (you can implement your own admin check logic)
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // For now, we'll return all customizations
    const customizations = await Customization.find().sort({ date: -1 });
    console.log("Found customizations:", customizations.length);
    res.json(customizations);
  } catch (error) {
    console.error("Error fetching customizations:", error);
    res.status(500).json({ error: "Error fetching customizations" });
  }
});

// Handle Customization Form Submission
app.post("/submit-customization", authMiddleware, async (req, res) => {
  console.log("Received customization request:", req.body);
  try {
    const user = await User.findById(req.user.userId);
    const newCustomization = new Customization({
      ...req.body,
      userId: req.user.userId,
      username: user.username,
      userEmail: user.email
    });
    console.log("Saving customization to database...");

    await newCustomization.save();
    res.json({ message: "Customization request submitted successfully!" });
  } catch (error) {
    console.error("Error saving customization request:", error);
    res.status(500).json({ error: "Error saving request" });
  }
});

// Static Routes
app.get("/signin", (req, res) => {
  res.sendFile(path.join(__dirname, "signin.html"));
});

app.get("/account.html", (req, res) => {
  res.sendFile(path.join(__dirname, "account.html"));
});

app.get("/code", authMiddleware, (req, res) => {
  try {
    res.sendFile(path.join(__dirname, "code.html"));
  } catch (error) {
    console.error("Error serving code.html:", error);
    res.status(500).send("Error loading the page");
  }
});

app.get("/code.html", authMiddleware, (req, res) => {
  try {
    res.sendFile(path.join(__dirname, "code.html"));
  } catch (error) {
    console.error("Error serving code.html:", error);
    res.status(500).send("Error loading the page");
  }
});

// Cart Routes
// Get user's cart
app.get("/cart", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    let cart = await Cart.findOne({ userId });
    
    if (!cart) {
      // Create a new cart if it doesn't exist
      cart = new Cart({ userId, items: [] });
      await cart.save();
    }
    
    res.json({ cart });
  } catch (error) {
    console.error("Error fetching cart:", error);
    res.status(500).json({ error: "Error fetching cart" });
  }
});

// Add item to cart
app.post("/cart/add", authMiddleware, async (req, res) => {
  try {
    console.log("Add to cart request received:", req.body);
    console.log("User ID from token:", req.user.userId);
    
    const userId = req.user.userId;
    const { id, name, price, quantity, img } = req.body;
    
    let cart = await Cart.findOne({ userId });
    console.log("Existing cart:", cart);
    
    if (!cart) {
      // Create a new cart if it doesn't exist
      cart = new Cart({ userId, items: [] });
      console.log("Created new cart for user");
    }
    
    // Check if item already exists in cart
    const existingItemIndex = cart.items.findIndex(item => item.id === id);
    console.log("Existing item index:", existingItemIndex);
    
    if (existingItemIndex !== -1) {
      // Update quantity if item exists
      cart.items[existingItemIndex].quantity += quantity;
      console.log("Updated existing item quantity");
    } else {
      // Add new item
      cart.items.push({ id, name, price, quantity, img });
      console.log("Added new item to cart");
    }
    
    cart.updatedAt = new Date();
    await cart.save();
    
    // Track cart update activity
    await trackActivity(userId, 'cart_update', { 
      action: 'add', 
      item: { id, name, quantity } 
    });

    console.log("Cart saved successfully");
    
    res.json({ message: "Item added to cart successfully", cart });
  } catch (error) {
    console.error("Error adding to cart:", error);
    res.status(500).json({ error: "Error adding to cart" });
  }
});

// Remove item from cart
app.post("/cart/remove", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.body;
    
    let cart = await Cart.findOne({ userId });
    
    if (!cart) {
      return res.status(404).json({ error: "Cart not found" });
    }
    
    // Remove item from cart
    cart.items = cart.items.filter(item => item.id !== id);
    cart.updatedAt = new Date();
    await cart.save();
    
    res.json({ message: "Item removed from cart successfully", cart });
  } catch (error) {
    console.error("Error removing from cart:", error);
    res.status(500).json({ error: "Error removing from cart" });
  }
});

// Update item quantity in cart
app.put("/cart/update", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id, quantity } = req.body;
    
    let cart = await Cart.findOne({ userId });
    
    if (!cart) {
      return res.status(404).json({ error: "Cart not found" });
    }
    
    // Find and update item quantity
    const itemIndex = cart.items.findIndex(item => item.id === id);
    if (itemIndex === -1) {
      return res.status(404).json({ error: "Item not found in cart" });
    }
    
    cart.items[itemIndex].quantity = quantity;
    cart.updatedAt = new Date();
    await cart.save();
    
    res.json({ message: "Cart updated successfully", cart });
  } catch (error) {
    console.error("Error updating cart:", error);
    res.status(500).json({ error: "Error updating cart" });
  }
});

// Clear cart
app.delete("/cart/clear", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    let cart = await Cart.findOne({ userId });
    
    if (!cart) {
      return res.status(404).json({ error: "Cart not found" });
    }
    
    // Clear all items
    cart.items = [];
    cart.updatedAt = new Date();
    await cart.save();
    
    res.json({ message: "Cart cleared successfully", cart });
  } catch (error) {
    console.error("Error clearing cart:", error);
    res.status(500).json({ error: "Error clearing cart" });
  }
});

// Add new endpoint to get user profile data
app.get("/profile/:userId", authMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Verify that the requesting user matches the userId
    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Access Denied" });
    }

    // Get user data
    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Get user's orders
    const orders = await Order.find({ userId }).sort({ orderDate: -1 });

    // Get user's activities
    const activities = await UserActivity.find({ userId })
      .sort({ timestamp: -1 })
      .limit(10);

    // Get user's cart
    const cart = await Cart.findOne({ userId });

    // Get user's customization requests
    const customizations = await Customization.find({ userId })
      .sort({ date: -1 });

    res.json({
      user: {
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture,
        joinedDate: user.joinedDate
      },
      orders,
      activities,
      cart,
      customizations
    });
  } catch (error) {
    console.error("Error fetching profile data:", error);
    res.status(500).json({ message: "Error fetching profile data" });
  }
});

// Add activity tracking middleware
const trackActivity = async (userId, activityType, details) => {
  try {
    const activity = new UserActivity({
      userId,
      activityType,
      details
    });
    await activity.save();
  } catch (error) {
    console.error("Error tracking activity:", error);
  }
};

// Reports Endpoints
app.get("/reports/analytics", authMiddleware, async (req, res) => {
    try {
        const { period } = req.query;
        const startDate = getStartDate(period);
        
        const payments = await Payment.find({
            date: { $gte: startDate }
        });

        const totalSales = payments.reduce((sum, payment) => sum + parseFloat(payment.amount || 0), 0);
        const totalOrders = payments.length;
        const avgOrderValue = totalOrders > 0 ? totalSales / totalOrders : 0;

        // Calculate trends (comparing with previous period)
        const previousStartDate = getPreviousPeriodStartDate(period);
        const previousPayments = await Payment.find({
            date: { $gte: previousStartDate, $lt: startDate }
        });

        const previousTotalSales = previousPayments.reduce((sum, payment) => sum + parseFloat(payment.amount || 0), 0);
        const previousTotalOrders = previousPayments.length;
        const previousAvgOrderValue = previousTotalOrders > 0 ? previousTotalSales / previousTotalOrders : 0;

        const salesTrend = calculateTrend(totalSales, previousTotalSales);
        const ordersTrend = calculateTrend(totalOrders, previousTotalOrders);
        const aovTrend = calculateTrend(avgOrderValue, previousAvgOrderValue);

        // Find top selling product
        const orders = await Order.find({
            orderDate: { $gte: startDate }
        });
        const productSales = {};
        orders.forEach(order => {
            order.items.forEach(item => {
                if (!productSales[item.name]) {
                    productSales[item.name] = 0;
                }
                productSales[item.name] += item.quantity;
            });
        });
        const topProduct = Object.entries(productSales)
            .sort((a, b) => b[1] - a[1])[0]?.[0] || '-';

        // Get historical data for the last 12 months
        const historicalData = {};
        for (let i = 0; i < 12; i++) {
            const monthStart = new Date(startDate);
            monthStart.setMonth(monthStart.getMonth() - i);
            const monthEnd = new Date(monthStart);
            monthEnd.setMonth(monthEnd.getMonth() + 1);

            const monthPayments = await Payment.find({
                date: { $gte: monthStart, $lt: monthEnd }
            });

            const monthSales = monthPayments.reduce((sum, payment) => sum + parseFloat(payment.amount || 0), 0);
            const monthName = monthStart.toLocaleString('default', { month: 'short' });
            historicalData[monthName] = monthSales;
        }

        res.json({
            totalSales,
            totalOrders,
            avgOrderValue,
            salesTrend,
            ordersTrend,
            aovTrend,
            topProduct,
            historicalData
        });
    } catch (error) {
        console.error("Error fetching analytics:", error);
        res.status(500).json({ error: "Error fetching analytics" });
    }
});

app.get("/reports/product-sales", authMiddleware, async (req, res) => {
    try {
        const { period } = req.query;
        const startDate = getStartDate(period);

        const orders = await Order.find({
            orderDate: { $gte: startDate }
        });

        const productData = {};
        orders.forEach(order => {
            order.items.forEach(item => {
                if (!productData[item.name]) {
                    productData[item.name] = {
                        name: item.name,
                        image: item.img,
                        category: item.category,
                        totalSales: 0,
                        quantitySold: 0,
                        revenue: 0
                    };
                }
                productData[item.name].quantitySold += item.quantity;
                productData[item.name].revenue += item.price * item.quantity;
                productData[item.name].totalSales++;
            });
        });

        // Calculate trends
        const previousStartDate = getPreviousPeriodStartDate(period);
        const previousOrders = await Order.find({
            orderDate: { $gte: previousStartDate, $lt: startDate }
        });

        const previousProductData = {};
        previousOrders.forEach(order => {
            order.items.forEach(item => {
                if (!previousProductData[item.name]) {
                    previousProductData[item.name] = {
                        quantitySold: 0,
                        revenue: 0
                    };
                }
                previousProductData[item.name].quantitySold += item.quantity;
                previousProductData[item.name].revenue += item.price * item.quantity;
            });
        });

        const products = Object.values(productData).map(product => ({
            ...product,
            trend: calculateTrend(product.revenue, previousProductData[product.name]?.revenue || 0)
        }));

        res.json(products);
    } catch (error) {
        console.error("Error fetching product sales:", error);
        res.status(500).json({ error: "Error fetching product sales" });
    }
});

app.get("/reports/turnover", authMiddleware, async (req, res) => {
    try {
        const { period } = req.query;
        const startDate = getStartDate(period);

        const payments = await Payment.find({
            date: { $gte: startDate }
        });

        // Monthly turnover
        const monthlyData = {};
        payments.forEach(payment => {
            const month = new Date(payment.date).toLocaleString('default', { month: 'short' });
            if (!monthlyData[month]) {
                monthlyData[month] = 0;
            }
            monthlyData[month] += parseFloat(payment.amount || 0);
        });

        // Yearly turnover
        const yearlyData = {};
        payments.forEach(payment => {
            const year = new Date(payment.date).getFullYear();
            if (!yearlyData[year]) {
                yearlyData[year] = 0;
            }
            yearlyData[year] += parseFloat(payment.amount || 0);
        });

        res.json({
            monthly: {
                labels: Object.keys(monthlyData),
                values: Object.values(monthlyData)
            },
            yearly: {
                labels: Object.keys(yearlyData),
                values: Object.values(yearlyData)
            }
        });
    } catch (error) {
        console.error("Error fetching turnover data:", error);
        res.status(500).json({ error: "Error fetching turnover data" });
    }
});

app.get("/reports/sales-analysis", authMiddleware, async (req, res) => {
    try {
        const { period } = req.query;
        const startDate = getStartDate(period);

        const orders = await Order.find({
            orderDate: { $gte: startDate }
        });

        // Category-wise sales
        const categorySales = {};
        orders.forEach(order => {
            order.items.forEach(item => {
                if (!categorySales[item.category]) {
                    categorySales[item.category] = 0;
                }
                categorySales[item.category] += item.price * item.quantity;
            });
        });

        // Sales trend
        const salesTrend = {};
        const days = 30; // Last 30 days
        for (let i = 0; i < days; i++) {
            const date = new Date(startDate);
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];
            salesTrend[dateStr] = 0;
        }

        orders.forEach(order => {
            const dateStr = order.orderDate.toISOString().split('T')[0];
            if (salesTrend[dateStr] !== undefined) {
                order.items.forEach(item => {
                    salesTrend[dateStr] += item.price * item.quantity;
                });
            }
        });

        res.json({
            categories: {
                labels: Object.keys(categorySales),
                values: Object.values(categorySales)
            },
            trend: {
                labels: Object.keys(salesTrend).reverse(),
                values: Object.values(salesTrend).reverse()
            }
        });
    } catch (error) {
        console.error("Error fetching sales analysis:", error);
        res.status(500).json({ error: "Error fetching sales analysis" });
    }
});

// Add new endpoint for past sales records
app.get("/reports/past-sales", authMiddleware, async (req, res) => {
    try {
        const { period } = req.query;
        const startDate = getStartDate(period);

        // Get all payments within the period
        const payments = await Payment.find({
            date: { $gte: startDate }
        }).sort({ date: -1 });

        // Get corresponding orders
        const orders = await Order.find({
            orderDate: { $gte: startDate }
        }).sort({ orderDate: -1 });

        // Combine payment and order data
        const salesRecords = payments.map(payment => {
            const order = orders.find(o => o.userId.toString() === payment.userId.toString());
            return {
                date: payment.date,
                customerId: payment.customerId,
                customerName: payment.name,
                paymentMethod: payment.paymentMethod,
                amount: payment.amount,
                items: order ? order.items.map(item => ({
                    name: item.name,
                    quantity: item.quantity,
                    price: item.price,
                    total: item.price * item.quantity
                })) : [],
                totalItems: order ? order.items.reduce((sum, item) => sum + item.quantity, 0) : 0
            };
        });

        res.json(salesRecords);
    } catch (error) {
        console.error("Error fetching past sales:", error);
        res.status(500).json({ error: "Error fetching past sales" });
    }
});

// Wishlist endpoints
app.get('/wishlist', authMiddleware, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.user.email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ wishlist: user.wishlist || [] });
    } catch (error) {
        console.error('Error fetching wishlist:', error);
        res.status(500).json({ error: 'Failed to fetch wishlist' });
    }
});

app.post('/wishlist/add', authMiddleware, async (req, res) => {
    try {
        const { id, name, price, img, category } = req.body;
        const user = await User.findOne({ email: req.user.email });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if item already exists in wishlist
        const existingItem = user.wishlist.find(item => item.id === id);
        if (existingItem) {
            return res.status(400).json({ error: 'Item already in wishlist' });
        }

        // Add new item to wishlist
        user.wishlist.push({
            id,
            name,
            price,
            img,
            category,
            addedAt: new Date()
        });

        await user.save();
        res.json({ message: 'Item added to wishlist successfully' });
    } catch (error) {
        console.error('Error adding to wishlist:', error);
        res.status(500).json({ error: 'Failed to add item to wishlist' });
    }
});

app.post('/wishlist/remove', authMiddleware, async (req, res) => {
    try {
        const { id } = req.body;
        const user = await User.findOne({ email: req.user.email });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Remove item from wishlist
        user.wishlist = user.wishlist.filter(item => item.id !== id);
        await user.save();
        
        res.json({ message: 'Item removed from wishlist successfully' });
    } catch (error) {
        console.error('Error removing from wishlist:', error);
        res.status(500).json({ error: 'Failed to remove item from wishlist' });
    }
});

// Helper functions
function getStartDate(period) {
    const now = new Date();
    switch (period) {
        case 'today':
            return new Date(now.setHours(0, 0, 0, 0));
        case 'yesterday': {
            const yesterday = new Date(now);
            yesterday.setDate(yesterday.getDate() - 1);
            yesterday.setHours(0, 0, 0, 0);
            return yesterday;
        }
        case 'week':
            return new Date(now.setDate(now.getDate() - now.getDay()));
        case 'lastWeek': {
            const lastWeekStart = new Date(now);
            lastWeekStart.setDate(lastWeekStart.getDate() - lastWeekStart.getDay() - 7);
            lastWeekStart.setHours(0, 0, 0, 0);
            return lastWeekStart;
        }
        case 'month':
            return new Date(now.getFullYear(), now.getMonth(), 1);
        case 'lastMonth': {
            const lastMonth = new Date(now);
            lastMonth.setMonth(lastMonth.getMonth() - 1);
            lastMonth.setDate(1);
            lastMonth.setHours(0, 0, 0, 0);
            return lastMonth;
        }
        case 'year':
            return new Date(now.getFullYear(), 0, 1);
        case 'lastYear': {
            const lastYear = new Date(now);
            lastYear.setFullYear(lastYear.getFullYear() - 1);
            lastYear.setMonth(0);
            lastYear.setDate(1);
            lastYear.setHours(0, 0, 0, 0);
            return lastYear;
        }
        default:
            return new Date(0); // All time
    }
}

function getPreviousPeriodStartDate(period) {
    const now = new Date();
    switch (period) {
        case 'today':
            return new Date(now.setDate(now.getDate() - 1));
        case 'yesterday': {
            const dayBeforeYesterday = new Date(now);
            dayBeforeYesterday.setDate(dayBeforeYesterday.getDate() - 2);
            dayBeforeYesterday.setHours(0, 0, 0, 0);
            return dayBeforeYesterday;
        }
        case 'week': {
            const lastWeek = new Date(now);
            lastWeek.setDate(lastWeek.getDate() - lastWeek.getDay() - 7);
            return lastWeek;
        }
        case 'lastWeek': {
            const twoWeeksAgo = new Date(now);
            twoWeeksAgo.setDate(twoWeeksAgo.getDate() - twoWeeksAgo.getDay() - 14);
            twoWeeksAgo.setHours(0, 0, 0, 0);
            return twoWeeksAgo;
        }
        case 'month': {
            const lastMonth = new Date(now);
            lastMonth.setMonth(lastMonth.getMonth() - 1);
            lastMonth.setDate(1);
            return lastMonth;
        }
        case 'lastMonth': {
            const twoMonthsAgo = new Date(now);
            twoMonthsAgo.setMonth(twoMonthsAgo.getMonth() - 2);
            twoMonthsAgo.setDate(1);
            twoMonthsAgo.setHours(0, 0, 0, 0);
            return twoMonthsAgo;
        }
        case 'year': {
            const lastYear = new Date(now);
            lastYear.setFullYear(lastYear.getFullYear() - 1);
            lastYear.setMonth(0);
            lastYear.setDate(1);
            return lastYear;
        }
        case 'lastYear': {
            const twoYearsAgo = new Date(now);
            twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
            twoYearsAgo.setMonth(0);
            twoYearsAgo.setDate(1);
            twoYearsAgo.setHours(0, 0, 0, 0);
            return twoYearsAgo;
        }
        default:
            return new Date(0);
    }
}

function calculateTrend(current, previous) {
    if (previous === 0) return 0;
    return Math.round(((current - previous) / previous) * 100);
}

// Add error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ 
        error: "An error occurred", 
        message: err.message 
    });
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
