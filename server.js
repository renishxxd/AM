require("dotenv").config();
const express = require("express");
const path = require("path");
const cors = require("cors");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Razorpay = require('razorpay');
const crypto = require('crypto');
const ExcelJS = require('exceljs');

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

// Connect to MongoDB with debug logging
mongoose.set('debug', true); // Enable mongoose debug mode
mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/ecommerceDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log("Connected to MongoDB successfully");
  console.log("Database:", mongoose.connection.db.databaseName);
  console.log("Host:", mongoose.connection.host);
  console.log("Port:", mongoose.connection.port);
  initializeDatabase();
})
.catch(err => {
  console.error("MongoDB connection error:", err);
  process.exit(1);
});

// Function to initialize database with some default data
async function initializeDatabase() {
  try {
    // Check if we have any users
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      console.log("Initializing database with default data...");
      
      // Create a default admin user
      const hashedPassword = await bcrypt.hash("admin123", 10);
      const adminUser = new User({
        username: "admin",
        email: "admin@example.com",
        password: hashedPassword,
        joinedDate: new Date()
      });
      await adminUser.save();

      // Create some sample orders
      const sampleOrder = new Order({
        userId: adminUser._id,
        items: [{
          id: 1,
          name: "Sample Product",
          price: 1000,
          quantity: 2,
          img: "sample.jpg"
        }],
        totalAmount: 2000,
        subtotal: 1800,
        tax: 200,
        status: "delivered",
        shippingAddress: "Sample Address",
        shippingDetails: {
          name: "Admin User",
          email: "admin@example.com",
          phone: "1234567890",
          address: "Sample Address"
        },
        paymentMethod: "cod",
        createdAt: new Date(),
        updatedAt: new Date()
      });
      await sampleOrder.save();

      // Create sample user activity
      const sampleActivity = new UserActivity({
        userId: adminUser._id,
        activityType: "purchase",
        details: {
          orderId: sampleOrder._id,
          amount: 2000,
          items: sampleOrder.items
        },
        timestamp: new Date()
      });
      await sampleActivity.save();

      console.log("Database initialized with default data");
    }
  } catch (error) {
    console.error("Error initializing database:", error);
  }
}

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
  subtotal: Number,
  tax: Number,
  status: {
    type: String,
    enum: ['pending', 'processing', 'shipped', 'delivered'],
    default: 'pending'
  },
  shippingAddress: String,
  shippingDetails: {
    name: String,
    email: String,
    phone: String,
    address: String
  },
  paymentMethod: String,
  paymentId: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

OrderSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
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
        Product_Name: String,
        Product_size: String,
        Product_price: Number,
        Quantity: Number,
        Product_Image: String,
        _id: mongoose.Schema.Types.ObjectId
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    __v: { type: Number, default: 0 }
});

const Cart = mongoose.model("Cart", CartSchema);

// Contact Schema
const ContactSchema = new mongoose.Schema({
  name: String,
  email: String,
  subject: String,
  message: String,
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
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
  date: { type: Date, default: Date.now },
  status: String
});
const Customization = mongoose.model("Customization", CustomizationSchema);

// Comprehensive Order Details Schema
const OrderDetailsSchema = new mongoose.Schema({
    orderId: {
        type: String,
        required: true,
        unique: true
    },
    customerDetails: {
        name: String,
        email: String,
        contact: String,
        address: String
    },
    orderDate: {
        type: Date,
        default: Date.now
    },
    paymentDetails: {
        paymentId: String,
        paymentMethod: String,
        amount: Number,
        subtotal: Number,
        gst: Number,
        status: {
            type: String,
            enum: ['pending', 'successful', 'failed'],
            default: 'pending'
        },
        transactionDate: {
            type: Date,
            default: Date.now
        }
    },
    products: [{
        Product_Name: String,
        Product_size: String,
        Product_price: Number,
        Quantity: Number,
        Product_Image: String,
        itemTotal: Number
    }],
    orderStatus: {
        type: String,
        enum: ['processing', 'shipped', 'delivered', 'cancelled'],
        default: 'processing'
    },
    shippingDetails: {
        trackingNumber: String,
        carrier: String,
        estimatedDelivery: Date
    }
});

const OrderDetails = mongoose.model("OrderDetails", OrderDetailsSchema);

// Email Transporter (for sending emails)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Initialize Razorpay
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
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
    const { name, email, contact, address, paymentMethod, amount, subtotal, gst, cartItems } = req.body;
    const user = await User.findById(req.user.userId);
    const customerId = "CUST" + Math.floor(100000 + Math.random() * 900000);

    // Create a new order
    const order = new Order({
      userId: req.user.userId,
      items: cartItems,
      totalAmount: amount,
      subtotal: subtotal,
      tax: gst,
      status: 'pending',
      shippingAddress: address,
      paymentMethod: 'cod',
      shippingDetails: {
        name,
        email,
        phone: contact,
        address
      }
    });
    
    await order.save();

    // Save payment details
    const newPayment = new Payment({ 
      customerId, 
      orderId: order._id,
      name, 
      email, 
      contact, 
      address, 
      paymentMethod, 
      amount,
      currency: 'INR',
      status: 'pending',
      userId: req.user.userId,
      username: user.username,
      userEmail: user.email
    });

    await newPayment.save();

    // Track purchase activity
    await trackActivity(req.user.userId, 'purchase', { 
      orderId: order._id,
      amount: amount,
      items: cartItems
    });

    res.json({ 
      success: true, 
      message: "Payment details saved successfully!", 
      customerId,
      orderId: order._id 
    });
  } catch (error) {
    console.error("Error processing payment:", error);
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

// Update customization order status
app.put("/api/customization/:id/status", authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['pending', 'confirmed', 'completed'].includes(status)) {
      return res.status(400).json({ message: "Invalid status. Must be 'pending', 'confirmed', or 'completed'" });
    }

    const customization = await Customization.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    if (!customization) {
      return res.status(404).json({ message: "Customization order not found" });
    }

    res.json(customization);
  } catch (error) {
    console.error("Error updating customization status:", error);
    res.status(500).json({ message: "Error updating customization status" });
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
        const { name, size, price, quantity, img } = req.body;
        
        let cart = await Cart.findOne({ userId });
        console.log("Existing cart:", cart);
        
        if (!cart) {
            // Create a new cart if it doesn't exist
            cart = new Cart({ 
                userId, 
                items: [],
                createdAt: new Date(),
                updatedAt: new Date(),
                __v: 0
            });
            console.log("Created new cart for user");
        }
        
        // Create new item with MongoDB ObjectId
        const newItem = {
            Product_Name: name,
            Product_size: size,
            Product_price: price,
            Quantity: quantity,
            Product_Image: img,
            _id: new mongoose.Types.ObjectId()
        };
        
        cart.items.push(newItem);
        cart.updatedAt = new Date();
        await cart.save();
        
        // Track cart update activity
        await trackActivity(userId, 'cart_update', { 
            action: 'add', 
            item: { name, quantity } 
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
    cart.items = cart.items.filter(item => item._id.toString() !== id);
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
    const itemIndex = cart.items.findIndex(item => item._id.toString() === id);
    if (itemIndex === -1) {
      return res.status(404).json({ error: "Item not found in cart" });
    }
    
    cart.items[itemIndex].Quantity = quantity;
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

// Get user profile data including orders, activities, and customizations
app.get("/profile/:userId", authMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Check if the requesting user matches the profile being accessed
    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Unauthorized access to profile" });
    }

    // Fetch user data
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Fetch orders with payment details
    const orders = await Order.find({ userId })
      .sort({ createdAt: -1 });

    // Fetch user activities
    const activities = await UserActivity.find({ userId })
      .sort({ timestamp: -1 })
      .limit(10);

    // Format activity descriptions
    const formattedActivities = activities.map(activity => {
      let description = '';
      switch (activity.activityType) {
        case 'login':
          description = 'Logged in successfully';
          break;
        case 'purchase':
          const itemCount = activity.details.items.length;
          const totalAmount = formatCurrency(activity.details.amount);
          description = `Purchased ${itemCount} item${itemCount > 1 ? 's' : ''} for ${totalAmount}`;
          break;
        case 'cart_update':
          description = `${activity.details.action === 'add' ? 'Added' : 'Removed'} ${activity.details.item.name} ${activity.details.action === 'add' ? 'to' : 'from'} cart`;
          break;
        case 'customization_request':
          description = `Requested customization for ${activity.details.dressType}`;
          break;
        case 'contact_form':
          description = 'Submitted a contact form';
          break;
        default:
          description = 'Performed an action';
      }
      return {
        description,
        timestamp: activity.timestamp,
        type: activity.activityType
      };
    });

    // Fetch user customizations
    const customizations = await Customization.find({ userId })
      .sort({ date: -1 })
      .select({
        _id: 1,
        fabricType: 1,
        dressType: 1,
        color: 1,
        size: 1,
        quantity: 1,
        phone: 1,
        additionalNotes: 1,
        status: 1,
        date: 1
      });

    // Format customization data
    const formattedCustomizations = customizations.map(custom => ({
      _id: custom._id,
      details: `${custom.dressType} - ${custom.fabricType} (${custom.color}, Size: ${custom.size}, Qty: ${custom.quantity})`,
      status: custom.status || 'Pending',
      additionalNotes: custom.additionalNotes,
      phone: custom.phone,
      date: custom.date
    }));

    // Fetch payment details
    const payments = await Payment.find({ userId })
      .sort({ date: -1 });

    // Combine order and payment information
    const ordersWithPayments = orders.map(order => {
      const payment = payments.find(p => p.orderId && order._id && p.orderId.toString() === order._id.toString());
      return {
        ...order.toObject(),
        payment: payment ? {
          customerId: payment.customerId,
          status: payment.status || 'pending',
          paymentMethod: payment.paymentMethod || 'N/A'
        } : {
          status: 'pending',
          paymentMethod: 'N/A'
        }
      };
    });

    res.json({
      user: {
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture
      },
      orders: ordersWithPayments,
      activities: formattedActivities,
      customizations: formattedCustomizations
    });
  } catch (error) {
    console.error("Error fetching profile data:", error);
    res.status(500).json({ message: "Error fetching profile data" });
  }
});

// Helper function to format currency
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-IN', {
        style: 'currency',
        currency: 'INR'
    }).format(amount);
}

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

// Contact form endpoints
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    const contact = new Contact({
      name,
      email,
      subject,
      message
    });
    await contact.save();
    res.status(201).json({ message: "Contact form submitted successfully" });
  } catch (error) {
    console.error("Error submitting contact form:", error);
    res.status(500).json({ message: "Error submitting contact form" });
  }
});

// Get all contact form submissions (protected route)
app.get("/api/contacts", authMiddleware, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json(contacts);
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ message: "Error fetching contacts" });
  }
});

// Update contact status (approve/reject)
app.put("/api/contact/:id/status", authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    const contact = await Contact.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    if (!contact) {
      return res.status(404).json({ message: "Contact not found" });
    }
    res.json(contact);
  } catch (error) {
    console.error("Error updating contact status:", error);
    res.status(500).json({ message: "Error updating contact status" });
  }
});

// Delete contact
app.delete("/api/contact/:id", authMiddleware, async (req, res) => {
  try {
    const contact = await Contact.findByIdAndDelete(req.params.id);
    if (!contact) {
      return res.status(404).json({ message: "Contact not found" });
    }
    res.json({ message: "Contact deleted successfully" });
  } catch (error) {
    console.error("Error deleting contact:", error);
    res.status(500).json({ message: "Error deleting contact" });
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

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Add error handling middleware at the top level
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    error: "An error occurred", 
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

// Create order endpoint
app.post('/create-order', authMiddleware, async (req, res) => {
    try {
        const { amount, currency, receipt } = req.body;

        const options = {
            amount: amount,
            currency: currency,
            receipt: receipt
        };

        const order = await razorpay.orders.create(options);
        res.json(order);
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Failed to create order' });
    }
});

// Verify payment endpoint
app.post('/verify-payment', authMiddleware, async (req, res) => {
    try {
        const { 
            razorpay_payment_id, 
            razorpay_order_id, 
            razorpay_signature,
            amount,
            subtotal,
            gst,
            name,
            email,
            contact,
            address,
            cartItems
        } = req.body;

        console.log("Received cart items:", cartItems); // Debug log

        // Create the signature
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body.toString())
            .digest('hex');

        // Verify the signature
        if (expectedSignature === razorpay_signature) {
            const customerId = "CUST" + Math.floor(100000 + Math.random() * 900000);

            // Create a new order
            const order = new Order({
                userId: req.user.userId,
                items: cartItems,
                totalAmount: amount,
                subtotal: subtotal,
                tax: gst,
                status: 'processing',
                shippingAddress: address,
                paymentId: razorpay_payment_id,
                paymentMethod: 'razorpay',
                shippingDetails: {
                    name,
                    email,
                    phone: contact,
                    address
                }
            });
            
            await order.save();

            // Save payment details
            const payment = new Payment({
                customerId,
                paymentId: razorpay_payment_id,
                orderId: order._id,
                amount: amount,
                currency: 'INR',
                status: 'completed',
                userId: req.user.userId,
                paymentMethod: 'razorpay',
                name,
                email,
                contact,
                address,
                date: new Date()
            });

            await payment.save();

            // Ensure cart items are properly formatted
            const formattedProducts = cartItems.map(item => ({
                ...item,
                itemTotal: item.Product_price * item.Quantity
            }));

            console.log("Formatted products:", formattedProducts); // Debug log

            // Store in OrderDetails collection for record keeping
            const orderDetails = new OrderDetails({
                orderId: order._id.toString(),
                customerDetails: {
                    name,
                    email,
                    contact,
                    address
                },
                paymentDetails: {
                    paymentId: razorpay_payment_id,
                    paymentMethod: 'razorpay',
                    amount: parseFloat(amount),
                    subtotal: parseFloat(subtotal),
                    gst: parseFloat(gst),
                    status: 'successful',
                    transactionDate: new Date()
                },
                products: formattedProducts,
                orderStatus: 'processing',
                orderDate: new Date()
            });

            console.log("Order details before save:", orderDetails); // Debug log

            await orderDetails.save();

            // Track purchase activity
            await trackActivity(req.user.userId, 'purchase', { 
                orderId: order._id,
                amount: amount,
                items: cartItems,
                paymentMethod: 'razorpay'
            });

            res.json({ 
                success: true,
                orderId: order._id,
                customerId: customerId
            });
        } else {
            res.status(400).json({ error: 'Invalid signature' });
        }
    } catch (error) {
        console.error('Error verifying payment:', error);
        console.error('Error details:', error.message);
        console.error('Stack trace:', error.stack);
        res.status(500).json({ error: 'Failed to verify payment' });
    }
});

// Dashboard API Routes
app.get('/api/products/low-stock', authMiddleware, async (req, res) => {
    try {
        const lowStockItems = await Order.aggregate([
            {
                $group: {
                    _id: {
                        id: "$items.id",
                        name: "$items.name",
                        category: "$items.category"
                    },
                    totalQuantity: { $sum: "$items.quantity" }
                }
            },
            {
                $match: {
                    totalQuantity: { $lte: 5 }
                }
            },
            {
                $project: {
                    _id: 0,
                    id: "$_id.id",
                    name: "$_id.name",
                    category: "$_id.category",
                    stock: "$totalQuantity"
                }
            }
        ]);
        res.json(lowStockItems);
    } catch (error) {
        console.error('Error fetching low stock items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
    try {
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
        const sixtyDaysAgo = new Date(now.getTime() - (60 * 24 * 60 * 60 * 1000));

        // Get current period stats
        const [currentRevenue, currentCustomers, currentOrders, currentPurchases] = await Promise.all([
            Order.aggregate([
                { $match: { createdAt: { $gte: thirtyDaysAgo } } },
                { $group: { _id: null, total: { $sum: "$totalAmount" } } }
            ]).exec(),
            User.countDocuments({ joinedDate: { $gte: thirtyDaysAgo } }).exec(),
            Order.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }).exec(),
            UserActivity.countDocuments({ 
                activityType: 'purchase',
                timestamp: { $gte: thirtyDaysAgo }
            }).exec()
        ]);

        // Get previous period stats
        const [previousRevenue, previousCustomers, previousOrders, previousPurchases] = await Promise.all([
            Order.aggregate([
                { $match: { createdAt: { $gte: sixtyDaysAgo, $lt: thirtyDaysAgo } } },
                { $group: { _id: null, total: { $sum: "$totalAmount" } } }
            ]).exec(),
            User.countDocuments({ joinedDate: { $gte: sixtyDaysAgo, $lt: thirtyDaysAgo } }).exec(),
            Order.countDocuments({ createdAt: { $gte: sixtyDaysAgo, $lt: thirtyDaysAgo } }).exec(),
            UserActivity.countDocuments({ 
                activityType: 'purchase',
                timestamp: { $gte: sixtyDaysAgo, $lt: thirtyDaysAgo }
            }).exec()
        ]);

        // Get monthly revenue data
        const monthlyRevenue = await Order.aggregate([
            {
                $group: {
                    _id: {
                        year: { $year: "$createdAt" },
                        month: { $month: "$createdAt" }
                    },
                    total: { $sum: "$totalAmount" }
                }
            },
            { $sort: { "_id.year": 1, "_id.month": 1 } }
        ]).exec();

        // Get top selling products
        const topProducts = await Order.aggregate([
            { $unwind: "$items" },
            {
                $group: {
                    _id: {
                        id: "$items.id",
                        name: "$items.name"
                    },
                    totalQuantity: { $sum: "$items.quantity" },
                    totalRevenue: { $sum: { $multiply: ["$items.price", "$items.quantity"] } }
                }
            },
            { $sort: { totalQuantity: -1 } },
            { $limit: 5 }
        ]).exec();

        // Calculate trends
        const calculateTrend = (current, previous) => {
            if (previous === 0) return current > 0 ? 100 : 0;
            return ((current - previous) / previous * 100).toFixed(2);
        };

        // Format monthly data
        const monthlyData = monthlyRevenue.map(item => ({
            month: `${item._id.year}-${String(item._id.month).padStart(2, '0')}`,
            revenue: item.total
        }));

        const stats = {
            totalRevenue: currentRevenue[0]?.total || 0,
            totalCustomers: currentCustomers || 0,
            totalOrders: currentOrders || 0,
            conversionRate: currentCustomers > 0 ? ((currentPurchases / currentCustomers) * 100).toFixed(2) : 0,
            revenueTrend: calculateTrend(
                currentRevenue[0]?.total || 0,
                previousRevenue[0]?.total || 0
            ),
            customerTrend: calculateTrend(currentCustomers, previousCustomers),
            orderTrend: calculateTrend(currentOrders, previousOrders),
            conversionTrend: calculateTrend(
                (currentPurchases / currentCustomers) * 100,
                (previousPurchases / previousCustomers) * 100
            ),
            monthlyData: monthlyData,
            topProducts: topProducts.map(p => ({
                name: p._id.name,
                quantity: p.totalQuantity,
                revenue: p.totalRevenue
            }))
        };

        res.json(stats);
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/analytics/revenue', authMiddleware, async (req, res) => {
    try {
        const period = req.query.period || 'month';
        const now = new Date();
        let startDate;
        let groupBy;

        if (period === 'year') {
            startDate = new Date(now.getFullYear(), 0, 1);
            groupBy = { $month: "$createdAt" };
        } else {
            startDate = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
            groupBy = { 
                $dateToString: { 
                    format: "%Y-%m-%d", 
                    date: "$createdAt" 
                } 
            };
        }

        const revenueData = await Order.aggregate([
            { $match: { createdAt: { $gte: startDate } } },
            {
                $group: {
                    _id: groupBy,
                    revenue: { $sum: "$totalAmount" },
                    netProfit: { 
                        $sum: { 
                            $multiply: ["$totalAmount", 0.3] // Assuming 30% profit margin
                        } 
                    }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        const labels = revenueData.map(d => d._id);
        const revenue = revenueData.map(d => d.revenue);
        const netProfit = revenueData.map(d => d.netProfit);

        res.json({ labels, revenue, netProfit });
    } catch (error) {
        console.error('Error fetching revenue data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/analytics/sales-by-region', authMiddleware, async (req, res) => {
    try {
        const salesByRegion = await Order.aggregate([
            {
                $group: {
                    _id: "$shippingDetails.address",
                    sales: { $sum: "$totalAmount" }
                }
            },
            {
                $project: {
                    _id: 0,
                    region: "$_id",
                    sales: 1
                }
            },
            { $sort: { sales: -1 } },
            { $limit: 5 }
        ]);

        const regions = salesByRegion.map(r => r.region);
        const sales = salesByRegion.map(r => r.sales);

        res.json({ regions, sales });
    } catch (error) {
        console.error('Error fetching sales by region:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/analytics/top-products', authMiddleware, async (req, res) => {
    try {
        const topProducts = await Order.aggregate([
            { $unwind: "$items" },
            {
                $group: {
                    _id: {
                        id: "$items.id",
                        name: "$items.name"
                    },
                    sales: { $sum: "$items.quantity" }
                }
            },
            {
                $project: {
                    _id: 0,
                    name: "$_id.name",
                    sales: 1
                }
            },
            { $sort: { sales: -1 } },
            { $limit: 5 }
        ]);

        res.json({ products: topProducts });
    } catch (error) {
        console.error('Error fetching top products:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/analytics/order-status', authMiddleware, async (req, res) => {
    try {
        const startDate = new Date(new Date().getTime() - (30 * 24 * 60 * 60 * 1000));
        
        const orderData = await Order.aggregate([
            { $match: { createdAt: { $gte: startDate } } },
            {
                $group: {
                    _id: {
                        $dateToString: {
                            format: "%Y-%m-%d",
                            date: "$createdAt"
                        }
                    },
                    orders: { $sum: 1 }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        const labels = orderData.map(d => d._id);
        const orders = orderData.map(d => d.orders);

        res.json({ labels, orders });
    } catch (error) {
        console.error('Error fetching order status data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin Dashboard Statistics API
app.get('/api/admin/stats', authMiddleware, async (req, res) => {
    try {
        // Get total orders
        const totalOrders = await Order.countDocuments();
        
        // Get total users (excluding admin)
        const totalUsers = await User.countDocuments({ email: { $ne: 'admin@gmail.com' } });
        
        // Calculate total revenue
        const revenueData = await Order.aggregate([
            {
                $group: {
                    _id: null,
                    totalRevenue: { $sum: "$totalAmount" }
                }
            }
        ]);
        
        const totalRevenue = revenueData.length > 0 ? revenueData[0].totalRevenue : 0;

        res.json({
            success: true,
            stats: {
                totalOrders,
                totalUsers,
                totalRevenue
            }
        });
    } catch (error) {
        console.error('Error fetching admin stats:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching admin statistics'
        });
    }
});

// API endpoint to save comprehensive order details
app.post("/api/save-order-details", authMiddleware, async (req, res) => {
    try {
        const {
            orderId,
            customerDetails,
            paymentDetails,
            products
        } = req.body;

        // Calculate item totals and overall totals
        const productsWithTotals = products.map(product => ({
            ...product,
            itemTotal: product.Product_price * product.Quantity
        }));

        const subtotal = productsWithTotals.reduce((sum, product) => sum + product.itemTotal, 0);
        const gst = subtotal * 0.18;
        const totalAmount = subtotal + gst;

        const orderDetails = new OrderDetails({
            orderId,
            customerDetails,
            paymentDetails: {
                ...paymentDetails,
                amount: totalAmount,
                subtotal,
                gst
            },
            products: productsWithTotals
        });

        await orderDetails.save();

        res.status(201).json({
            success: true,
            message: "Order details saved successfully",
            orderDetails
        });
    } catch (error) {
        console.error("Error saving order details:", error);
        res.status(500).json({
            success: false,
            message: "Error saving order details",
            error: error.message
        });
    }
});

// API endpoint to get order details by orderId
app.get("/api/order-details/:orderId", authMiddleware, async (req, res) => {
    try {
        const orderDetails = await OrderDetails.findOne({ orderId: req.params.orderId });
        if (!orderDetails) {
            return res.status(404).json({
                success: false,
                message: "Order details not found"
            });
        }

        res.json({
            success: true,
            orderDetails
        });
    } catch (error) {
        console.error("Error fetching order details:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching order details",
            error: error.message
        });
    }
});

// API endpoint to get all orders for a customer
app.get("/api/customer-orders", authMiddleware, async (req, res) => {
    try {
        const orders = await OrderDetails.find({
            "customerDetails.email": req.user.email
        }).sort({ orderDate: -1 });

        res.json({
            success: true,
            orders
        });
    } catch (error) {
        console.error("Error fetching customer orders:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching customer orders",
            error: error.message
        });
    }
});

// API endpoint to update order status
app.put("/api/order-status/:orderId", authMiddleware, async (req, res) => {
    try {
        const { orderStatus, trackingNumber, carrier, estimatedDelivery } = req.body;

        const orderDetails = await OrderDetails.findOne({ orderId: req.params.orderId });
        if (!orderDetails) {
            return res.status(404).json({
                success: false,
                message: "Order not found"
            });
        }

        orderDetails.orderStatus = orderStatus;
        if (trackingNumber && carrier && estimatedDelivery) {
            orderDetails.shippingDetails = {
                trackingNumber,
                carrier,
                estimatedDelivery: new Date(estimatedDelivery)
            };
        }

        await orderDetails.save();

        res.json({
            success: true,
            message: "Order status updated successfully",
            orderDetails
        });
    } catch (error) {
        console.error("Error updating order status:", error);
        res.status(500).json({
            success: false,
            message: "Error updating order status",
            error: error.message
        });
    }
});

// Get all order details
app.get("/api/order-details", authMiddleware, async (req, res) => {
    try {
        // Fetch all orders and sort by date in descending order
        const orders = await OrderDetails.find()
            .sort({ orderDate: -1 });

        res.json({
            success: true,
            orders
        });
    } catch (error) {
        console.error("Error fetching order details:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching order details",
            error: error.message
        });
    }
});

// Add this with other static routes
app.get("/product.html", authMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, "product.html"));
});

// Get report data
app.get("/api/reports/summary", authMiddleware, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const start = startDate ? new Date(startDate) : new Date(new Date().setDate(new Date().getDate() - 30));
    const end = endDate ? new Date(endDate) : new Date();

    // Get total orders
    const totalOrders = await Order.countDocuments({
      createdAt: { $gte: start, $lte: end }
    });

    // Get total revenue
    const revenueData = await Order.aggregate([
      {
        $match: {
          createdAt: { $gte: start, $lte: end },
          status: { $ne: 'cancelled' }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: "$totalAmount" }
        }
      }
    ]);
    const totalRevenue = revenueData[0]?.total || 0;

    // Get customization orders
    const totalCustomizations = await Customization.countDocuments({
      createdAt: { $gte: start, $lte: end }
    });

    // Get order status breakdown
    const orderStatusBreakdown = await Order.aggregate([
      {
        $match: {
          createdAt: { $gte: start, $lte: end }
        }
      },
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 }
        }
      }
    ]);

    // Get daily revenue for the period
    const dailyRevenue = await Order.aggregate([
      {
        $match: {
          createdAt: { $gte: start, $lte: end },
          status: { $ne: 'cancelled' }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          revenue: { $sum: "$totalAmount" },
          orders: { $sum: 1 }
        }
      },
      {
        $sort: { "_id": 1 }
      }
    ]);

    res.json({
      totalOrders,
      totalRevenue,
      totalCustomizations,
      orderStatusBreakdown,
      dailyRevenue
    });
  } catch (error) {
    console.error("Error generating report:", error);
    res.status(500).json({ message: "Error generating report" });
  }
});

// Download report as Excel
app.get("/api/reports/download", async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const start = startDate ? new Date(startDate) : new Date(new Date().setDate(new Date().getDate() - 30));
    const end = endDate ? new Date(endDate) : new Date();

    // Create a new Excel workbook
    const workbook = new ExcelJS.Workbook();
    
    // Orders Sheet
    const ordersSheet = workbook.addWorksheet('Orders');
    ordersSheet.columns = [
      { header: 'Order ID', key: 'orderId' },
      { header: 'Date', key: 'date' },
      { header: 'Customer', key: 'customer' },
      { header: 'Amount', key: 'amount' },
      { header: 'Status', key: 'status' }
    ];

    const orders = await Order.find({
      createdAt: { $gte: start, $lte: end }
    }).populate('userId');

    orders.forEach(order => {
      ordersSheet.addRow({
        orderId: order._id.toString(),
        date: order.createdAt.toLocaleDateString(),
        customer: order.shippingDetails?.name || 'N/A',
        amount: order.totalAmount,
        status: order.status
      });
    });

    // Customizations Sheet
    const customizationsSheet = workbook.addWorksheet('Customizations');
    customizationsSheet.columns = [
      { header: 'ID', key: 'id' },
      { header: 'Date', key: 'date' },
      { header: 'Customer', key: 'customer' },
      { header: 'Specifications', key: 'specs' },
      { header: 'Status', key: 'status' }
    ];

    const customizations = await Customization.find({
      createdAt: { $gte: start, $lte: end }
    });

    customizations.forEach(custom => {
      customizationsSheet.addRow({
        id: custom._id.toString(),
        date: custom.createdAt.toLocaleDateString(),
        customer: custom.customerName,
        specs: custom.specifications,
        status: custom.status
      });
    });

    // Revenue Summary Sheet
    const summarySheet = workbook.addWorksheet('Summary');
    const dailyRevenue = await Order.aggregate([
      {
        $match: {
          createdAt: { $gte: start, $lte: end },
          status: { $ne: 'cancelled' }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          revenue: { $sum: "$totalAmount" },
          orders: { $sum: 1 }
        }
      },
      {
        $sort: { "_id": 1 }
      }
    ]);

    summarySheet.columns = [
      { header: 'Date', key: 'date' },
      { header: 'Revenue', key: 'revenue' },
      { header: 'Orders', key: 'orders' }
    ];

    dailyRevenue.forEach(day => {
      summarySheet.addRow({
        date: day._id,
        revenue: day.revenue,
        orders: day.orders
      });
    });

    // Set response headers
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=report-${start.toISOString().split('T')[0]}-to-${end.toISOString().split('T')[0]}.xlsx`);

    // Write to response
    await workbook.xlsx.write(res);
    res.end();
  } catch (error) {
    console.error("Error downloading report:", error);
    res.status(500).json({ message: "Error downloading report" });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
