// 🌐 Laptop Booking Backend - Auth System + Laptop & Booking APIs + Admin Features

const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const fs = require("fs-extra");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = 3000;

// 🧠 Secret Key & OTP Store
const SECRET_KEY = "super_secret_key";
const otpStore = {};
const OTP_EXPIRATION_TIME = 5 * 60 * 1000; // 5 minutes

app.use(cors());
app.use(bodyParser.json());

// 🔄 Helper Functions to Read/Write JSON Files
const readJSONFile = (filePath) => fs.readJsonSync(filePath);
const writeJSONFile = (filePath, data) => fs.writeJsonSync(filePath, data, { spaces: 2 });

// 📁 File Paths
const usersFilePath = './data/users.json';
const laptopsFilePath = './data/laptops.json';
const bookingsFilePath = './data/bookings.json';

// 🔄 Load Data
let users = [];
let laptops = [];
let bookings = [];

try {
  users = readJSONFile(usersFilePath);
  laptops = readJSONFile(laptopsFilePath);
  bookings = readJSONFile(bookingsFilePath);
} catch (err) {
  console.error("❌ Failed to load JSON files:", err);
}

// Rate limiting for OTP
const otpRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 1,
  message: "Too many requests, please try again after 5 minutes"
});

// 🔐 Forgot Password - OTP
app.post("/api/auth/forgot-password", otpRateLimit, (req, res) => {
  const { email } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  const otp = crypto.randomInt(100000, 999999);
  const otpExpirationTime = Date.now() + OTP_EXPIRATION_TIME;
  otpStore[email] = { otp, expiration: otpExpirationTime };

  // Mock email sending
  res.json({ message: `OTP sent to ${email}`, otp });
});

// التحقق من OTP وتحديث كلمة المرور
app.post("/api/auth/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  const otpRecord = otpStore[email];
  if (!otpRecord) return res.status(400).json({ message: "OTP not found" });

  // التحقق من صلاحية الـ OTP
  const currentTime = Date.now();
  if (currentTime > otpRecord.expiration) {
    delete otpStore[email]; // إزالة الـ OTP بعد انتهائه
    return res.status(400).json({ message: "OTP has expired" });
  }

  // التحقق من صحة الـ OTP
  if (otpRecord.otp !== parseInt(otp)) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  // تحديث كلمة المرور
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  user.password = hashedPassword;

  // إزالة OTP بعد استخدامها
  delete otpStore[email];

  res.json({ message: "Password reset successfully" });
});

// 🔐 Register
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = users.find(u => u.email === email);
  if (existingUser) return res.status(400).json({ message: "Email already registered" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length + 1,
    name,
    email,
    password: hashedPassword,
    role: "customer",
    created_at: new Date().toISOString()
  };
  users.push(newUser);
  writeJSONFile(usersFilePath, users);
  res.status(201).json({ message: "User registered successfully" });
});

// 🔐 Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: "30m" });
  res.json({ message: "User Login successfully", token });
});

// 🛡️ Auth Middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch {
    res.sendStatus(403);
  }
}

// 🛡️ Admin Middleware
function adminMiddleware(req, res, next) {
  if (req.user.role !== "admin") return res.sendStatus(403);
  next();
}

// 🔐 Get My Profile
app.get("/api/auth/me", authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.sendStatus(404);
  const { password, ...userData } = user;
  res.json(userData);
});

// 🔁 Promote user to Admin
app.post("/api/auth/promote", authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.sendStatus(404);
  user.role = "admin";
  writeJSONFile(usersFilePath, users);
  res.json({ message: "User promoted to admin successfully" });
});

// 🔍 Admin: Get all users
app.get("/api/admin/users", authMiddleware, adminMiddleware, (req, res) => {
  const allUsers = users.map(({ password, ...rest }) => rest);
  res.json(allUsers);
});

// ❌ Admin: Delete user
app.delete("/api/admin/users/:id", authMiddleware, adminMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  const index = users.findIndex(u => u.id === userId);
  if (index === -1) return res.status(404).json({ message: "User not found" });
  users.splice(index, 1);
  writeJSONFile(usersFilePath, users);
  res.json({ message: "User deleted successfully" });
});

// 📝 Admin: Update user
app.put("/api/admin/users/:id", authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ message: "User not found" });

  const { name, email, password, role } = req.body;
  if (name) user.name = name;
  if (email) user.email = email;
  if (password) user.password = await bcrypt.hash(password, 10);
  if (role) user.role = role;

  writeJSONFile(usersFilePath, users);
  res.json({ message: "User updated successfully", user });
});

// 💻 Get all laptops
app.get("/api/laptops",authMiddleware , (req, res) => {
  res.json(laptops);
});

// 💼 Admin: Add new laptop
app.post("/api/laptops", authMiddleware, adminMiddleware, (req, res) => {
  const { brand, model, cpu, ram, storage, daily_price, image_url } = req.body;
  const newLaptop = {
    id: laptops.length + 1,
    brand,
    model,
    cpu,
    ram,
    storage,
    available: true,
    daily_price,
    image_url
  };
  laptops.push(newLaptop);
  writeJSONFile(laptopsFilePath, laptops);
  res.status(201).json({ message: "Laptop added successfully", laptop: newLaptop });
});

// 💼 Admin: Delete laptop
app.delete("/api/laptops/:id", authMiddleware, adminMiddleware, (req, res) => {
  const laptopId = parseInt(req.params.id);
  const index = laptops.findIndex(l => l.id === laptopId);
  if (index === -1) return res.status(404).json({ message: "Laptop not found" });
  laptops.splice(index, 1);
  writeJSONFile(laptopsFilePath, laptops);
  res.json({ message: "Laptop deleted successfully" });
});

// 📥 Book a laptop
app.post("/api/bookings", authMiddleware, (req, res) => {
  const { laptop_id, start_date, end_date } = req.body;
  const laptop = laptops.find(l => l.id === Number(laptop_id));
  if (!laptop || !laptop.available) return res.status(400).json({ message: "Laptop not available" });

  const days = (new Date(end_date) - new Date(start_date)) / (1000 * 60 * 60 * 24) + 1;
  const total_price = laptop.daily_price * days;

  const booking = {
    id: bookings.length + 1,
    laptop_id,
    user_id: req.user.id,
    start_date,
    end_date,
    status: "confirmed",
    total_price,
    created_at: new Date().toISOString()
  };

  bookings.push(booking);
  laptop.available = false;
  writeJSONFile(bookingsFilePath, bookings);
  writeJSONFile(laptopsFilePath, laptops);

  res.status(201).json({ message: "Booking confirmed", booking });
});

// 📄 My bookings
app.get("/api/bookings", authMiddleware, (req, res) => {
  const userBookings = bookings.filter(b => b.user_id === req.user.id);
  res.json(userBookings);
});

// ❌ Cancel booking
app.delete("/api/bookings/:id/cancel", authMiddleware, (req, res) => {
  const bookingId = parseInt(req.params.id);
  const booking = bookings.find(b => b.id === bookingId && b.user_id === req.user.id);
  if (!booking) return res.status(404).json({ message: "Booking not found or you don't have permission" });

  const bookingTime = new Date(booking.created_at);
  const now = new Date();
  const timeDifference = (now - bookingTime) / (1000 * 60 * 60); // hours

  if (timeDifference > 24) {
    return res.status(400).json({ message: "Booking cannot be cancelled after 24 hours" });
  }

  booking.status = "cancelled";
  const laptop = laptops.find(l => l.id === booking.laptop_id);
  if (laptop) laptop.available = true;

  writeJSONFile(bookingsFilePath, bookings);
  writeJSONFile(laptopsFilePath, laptops);

  res.json({ message: "Booking cancelled successfully", booking });
});
// 🔄 تحديث الحجز (PUT)
app.put("/api/bookings/:id/update", authMiddleware, (req, res) => {
  const bookingId = parseInt(req.params.id);
  const { start_date, end_date, status } = req.body;

  console.log("Booking ID to update:", bookingId); // تحقق من الـ ID

  // ابحث عن الحجز باستخدام الـ ID وتأكد أن المستخدم هو من قام بالحجز
  const booking = bookings.find(b => b.id === bookingId && b.user_id === req.user.id);

  if (!booking) {
    return res.status(404).json({ message: "Booking not found or you don't have permission" });
  }

  // تحديث التاريخ إذا تم تمرير قيم جديدة
  if (start_date) booking.start_date = start_date;
  if (end_date) booking.end_date = end_date;
  if (status) booking.status = status;

  // حساب السعر الإجمالي بناءً على التواريخ الجديدة
  const laptop = laptops.find(l => l.id === booking.laptop_id);
  if (laptop) {
    const days = (new Date(booking.end_date) - new Date(booking.start_date)) / (1000 * 60 * 60 * 24) + 1;
    booking.total_price = laptop.daily_price * days;
  }

  // حفظ البيانات الجديدة
  writeJSONFile(bookingsFilePath, bookings);

  res.json({ message: "Booking updated successfully", booking });
});

// ✅ Server Status
app.get("/", (req, res) => {
  res.send("✅ Laptop Booking Server is Running!");
});

// ⚠️ Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(PORT, () => {
  console.log(`✅ Laptop booking server running at http://localhost:${PORT}`);
});
