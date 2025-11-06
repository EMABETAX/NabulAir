// server-auto-fix.js - VERSIONE RENDER.COM
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'nabulair_dev_secret_2025';

// MongoDB per Render.com (usa MongoDB Atlas)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/nabulair';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Serve il file HTML principale
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB connesso'))
  .catch(err => console.error('❌ MongoDB:', err));

// Schema utente
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'reseller', 'customer'], default: 'customer' },
  resellerCode: String,
  company: String,
  email: String,
  isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', userSchema);

// Schema dispositivo
const deviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true },
  deviceName: { type: String, required: true },
  systemType: { type: String, required: true },
  owner: { type: String, required: true },
  resellerCode: { type: String, required: true },
  isOnline: { type: Boolean, default: false },
  activeAlerts: { type: Number, default: 0 },
  lastSeen: Date,
  firmwareVersion: { type: String, default: '1.0' },
  location: String,
  ownerEmail: String
});

const Device = mongoose.model('Device', deviceSchema);

async function autoSetup() {
  console.log('🔄 Auto-setup database...');
  
  try {
    await User.deleteMany({});
    
    const users = [
      { username: 'admin', password: await bcrypt.hash('Admin123!', 12), role: 'admin', company: 'NabulAir HQ' },
      { username: 'rivenditore_nord', password: await bcrypt.hash('Admin123!', 12), role: 'reseller', resellerCode: 'RES_NORD', company: 'Nord Italia' },
      { username: 'rivenditore_sud', password: await bcrypt.hash('Admin123!', 12), role: 'reseller', resellerCode: 'RES_SUD', company: 'Sud Italia' },
      { username: 'cliente_demo', password: await bcrypt.hash('Admin123!', 12), role: 'customer', company: 'Cliente Demo', resellerCode: 'RES_NORD' }
    ];
    
    await User.insertMany(users);
    console.log('✅ Database utenti inizializzato');
  } catch (error) {
    console.log('ℹ️  Database già inizializzato');
  }
}

// ============ API ROUTES ============

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username, isActive: true });
    if (!user) return res.status(400).json({ error: 'Credenziali non valide' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Credenziali non valide' });

    const token = jwt.sign(
      { username: user.username, role: user.role, resellerCode: user.resellerCode },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: {
        username: user.username,
        role: user.role,
        resellerCode: user.resellerCode,
        company: user.company
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Errore server' });
  }
});

// Registrazione
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, company, email, role, resellerCode } = req.body;
    
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: 'Username già esistente' });

    const hashedPassword = await bcrypt.hash(password, 12);
    
    const newUser = new User({
      username,
      password: hashedPassword,
      company,
      email,
      role,
      resellerCode: role === 'reseller' ? resellerCode : (role === 'customer' ? resellerCode : undefined)
    });

    await newUser.save();
    res.json({ success: true, message: 'Utente registrato con successo' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Errore durante la registrazione' });
  }
});

// API Devices (compatibili con il frontend)
app.get('/api/devices', async (req, res) => {
  try {
    const devices = await Device.find();
    res.json({ success: true, devices });
  } catch (error) {
    res.status(500).json({ error: 'Errore nel caricamento dispositivi' });
  }
});

app.post('/api/devices', async (req, res) => {
  try {
    const newDevice = new Device(req.body);
    await newDevice.save();
    res.json({ success: true, device: newDevice });
  } catch (error) {
    res.status(500).json({ error: 'Errore nella creazione dispositivo' });
  }
});

// API Rivenditori e Clienti
app.get('/api/resellers', async (req, res) => {
  try {
    const resellers = await User.find({ role: 'reseller', isActive: true });
    res.json({ success: true, resellers });
  } catch (error) {
    res.status(500).json({ error: 'Errore nel caricamento rivenditori' });
  }
});

app.get('/api/customers', async (req, res) => {
  try {
    const { resellerCode } = req.query;
    let query = { role: 'customer', isActive: true };
    
    if (resellerCode) {
      query.resellerCode = resellerCode;
    }
    
    const customers = await User.find(query);
    res.json({ success: true, customers });
  } catch (error) {
    res.status(500).json({ error: 'Errore nel caricamento clienti' });
  }
});

// Reset protetto
app.get('/api/force-reset', async (req, res) => {
  if (req.query.key === 'dev-only-reset-2025') {
    await autoSetup();
    res.json({ success: true, message: 'Reset completato' });
  } else {
    res.status(403).json({ error: 'Chiave di reset richiesta' });
  }
});

// Health check per Render
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.listen(PORT, async () => {
  await autoSetup();
  console.log(`🚀 Server NabulAir avviato su porta ${PORT}`);
  console.log('👤 Credenziali demo: admin / Admin123!');
});