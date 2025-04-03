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

app.use(cors());
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

// User Schema (For Authentication)
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String
});
const User = mongoose.model("User", UserSchema);

// Contact Schema (For storing contact form submissions)
const ContactSchema = new mongoose.Schema({
  fullName: String,
  email: String,
  phone: String,
  address: String,
  message: String,
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
  additionalNotes: String
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
    res.json({ message: "Login successful", token, userId: user._id });
  } catch (error) {
    res.status(500).json({ message: "Error signing in" });
  }
});

// Middleware for authentication
const authMiddleware = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "Access Denied" });

  try {
    const verified = jwt.verify(token.replace("Bearer ", ""), JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid Token" });
  }
};

// User Account Route
app.get("/account/:userId", async (req, res) => {
  const userId = req.params.userId;
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: "User not found" });

res.json({ message: "Welcome to your account", user: { username: user.username, email: user.email, role: user.role } });

});

// Handle Contact Form Submission (Save to MongoDB + Send Email)
app.post("/send-email", async (req, res) => {
  try {
    const { fullName, email, phone, address, message } = req.body;
    const newContact = new Contact({ fullName, email, phone, address, message });
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
app.post("/pay", async (req, res) => {
  try {
    const { name, email, contact, address, paymentMethod, upi, cardName, cardNumber, expiry, cvv, amount } = req.body;
    const customerId = "CUST" + Math.floor(100000 + Math.random() * 900000);
    const newPayment = new Payment({ customerId, name, email, contact, address, paymentMethod, upi, cardName, cardNumber, expiry, cvv, amount });

    await newPayment.save();
    res.json({ success: true, message: "Payment details saved successfully!", customerId });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error processing the payment." });
  }
});

app.get("/payments", async (req, res) => {
  try {
    const payments = await Payment.find(); // Fetch all payment records
    res.json(payments); // Return the payment records as JSON
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

app.get("/contacts", async (req, res) => {
  try {
    const contacts = await Contact.find(); // Fetch all contact records
    res.json(contacts); // Return the contact records as JSON
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ error: "Error fetching contacts" });
  }
});

app.get("/customizations", async (req, res) => {
  try {
    const customizations = await Customization.find(); // Fetch all customization records
    res.json(customizations); // Return the customization records as JSON
  } catch (error) {
    console.error("Error fetching customizations:", error);
    res.status(500).json({ error: "Error fetching customizations" });
  }
});

// Handle Customization Form Submission
app.post("/submit-customization", async (req, res) => {


  console.log("Received customization request:", req.body); // Log the incoming request data
  try {
    const newCustomization = new Customization(req.body);
    console.log("Saving customization to database..."); // Log before saving

    await newCustomization.save();
    res.json({ message: "Customization request submitted successfully!" });
  } catch (error) {
    console.error("Error saving customization request:", error); // Log any errors
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
  res.sendFile(__dirname + "/code.html");
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
