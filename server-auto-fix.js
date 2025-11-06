// server-auto-fix.js - VERSIONE COMPLETA PER RENDER
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'nabulair_dev_secret_2025';

// MongoDB per Render.com
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

// ============ SCHEMI DATABASE ============

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'reseller', 'customer'], default: 'customer' },
  resellerCode: String,
  company: String,
  email: String,
  isActive: { type: Boolean, default: true }
});

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

const telemetrySchema = new mongoose.Schema({
  deviceId: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  status: String,
  cicloAttivo: Boolean,
  secondiRimanenti: Number,
  volumeAcquaL: Number
});

const alertSchema = new mongoose.Schema({
  deviceId: String,
  type: { type: String, enum: ['offline', 'error', 'maintenance', 'warning'] },
  message: String,
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
  resolved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const commandSchema = new mongoose.Schema({
  deviceId: { type: String, required: true },
  type: { type: String, enum: ['start_cycle', 'stop_cycle', 'reboot'] },
  status: { type: String, enum: ['pending', 'sent', 'acknowledged', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Device = mongoose.model('Device', deviceSchema);
const Telemetry = mongoose.model('Telemetry', telemetrySchema);
const Alert = mongoose.model('Alert', alertSchema);
const Command = mongoose.model('Command', commandSchema);

// ============ MIDDLEWARE ============

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token richiesto' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token non valido' });
    req.user = user;
    next();
  });
};

// ============ AUTO-SETUP ============

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

// ============ API ENDPOINTS ============

// 🔐 AUTENTICAZIONE
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

// 👥 GESTIONE UTENTI
app.get('/api/resellers', authenticateToken, async (req, res) => {
  try {
    const resellers = await User.find({ role: 'reseller', isActive: true });
    res.json({ success: true, resellers });
  } catch (error) {
    res.status(500).json({ error: 'Errore nel caricamento rivenditori' });
  }
});

app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    let query = { role: 'customer', isActive: true };
    
    if (req.user.role === 'admin' && req.query.resellerCode) {
      query.resellerCode = req.query.resellerCode;
    } else if (req.user.role === 'reseller') {
      query.resellerCode = req.user.resellerCode;
    } else if (req.user.role === 'customer') {
      return res.json({ success: true, customers: [] });
    }
    
    const customers = await User.find(query);
    res.json({ success: true, customers });
  } catch (error) {
    res.status(500).json({ error: 'Errore nel caricamento clienti' });
  }
});

// 📱 GESTIONE DISPOSITIVI
app.get('/api/devices', authenticateToken, async (req, res) => {
  try {
    let filter = {};
    
    if (req.user.role === 'reseller') {
      filter.resellerCode = req.user.resellerCode;
    } else if (req.user.role === 'customer') {
      filter.owner = req.user.username;
    }

    const devices = await Device.find(filter);
    
    // Aggiungi telemetria e allerte
    const devicesWithDetails = await Promise.all(
      devices.map(async (device) => {
        const latestTelemetry = await Telemetry.findOne({ deviceId: device.deviceId })
          .sort({ timestamp: -1 });
        
        const activeAlerts = await Alert.countDocuments({ 
          deviceId: device.deviceId, 
          resolved: false 
        });

        return {
          ...device.toObject(),
          latestTelemetry: latestTelemetry || {},
          activeAlerts,
          isOnline: device.isOnline
        };
      })
    );

    res.json({ success: true, devices: devicesWithDetails });
  } catch (error) {
    console.error('Error loading devices:', error);
    res.status(500).json({ error: 'Errore nel caricamento dispositivi' });
  }
});

app.post('/api/devices', authenticateToken, async (req, res) => {
  try {
    const deviceData = req.body;
    
    // Controllo permessi
    if (req.user.role === 'reseller' && deviceData.resellerCode !== req.user.resellerCode) {
      return res.status(403).json({ error: 'Puoi registrare solo dispositivi per il tuo rivenditore' });
    }

    const existingDevice = await Device.findOne({ deviceId: deviceData.deviceId });
    if (existingDevice) {
      return res.status(400).json({ error: 'ID dispositivo già esistente' });
    }

    const device = new Device(deviceData);
    await device.save();

    res.json({ 
      success: true, 
      message: 'Dispositivo registrato con successo',
      device 
    });
  } catch (error) {
    console.error('Error adding device:', error);
    res.status(500).json({ error: 'Errore durante la registrazione' });
  }
});

app.get('/api/devices/:deviceId', authenticateToken, async (req, res) => {
  try {
    const device = await Device.findOne({ deviceId: req.params.deviceId });
    if (!device) return res.status(404).json({ error: 'Dispositivo non trovato' });

    // Controllo permessi
    if (req.user.role === 'reseller' && device.resellerCode !== req.user.resellerCode) {
      return res.status(403).json({ error: 'Accesso negato' });
    }
    if (req.user.role === 'customer' && device.owner !== req.user.username) {
      return res.status(403).json({ error: 'Accesso negato' });
    }

    const telemetry = await Telemetry.find({ deviceId: req.params.deviceId })
      .sort({ timestamp: -1 })
      .limit(20);

    res.json({
      success: true,
      device,
      telemetry
    });
  } catch (error) {
    res.status(500).json({ error: 'Errore nel caricamento dispositivo' });
  }
});

// 📊 DASHBOARD
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    let deviceFilter = {};
    
    if (req.user.role === 'reseller') {
      deviceFilter.resellerCode = req.user.resellerCode;
    } else if (req.user.role === 'customer') {
      deviceFilter.owner = req.user.username;
    }

    const totalDevices = await Device.countDocuments(deviceFilter);
    const onlineDevices = await Device.countDocuments({ ...deviceFilter, isOnline: true });
    const activeAlerts = await Alert.countDocuments({ resolved: false });

    res.json({
      success: true,
      dashboard: {
        totalDevices,
        deviceStatus: {
          online: onlineDevices,
          offline: totalDevices - onlineDevices
        },
        alertSeverity: {
          high: activeAlerts,
          medium: 0,
          low: 0
        },
        recentActivity: totalDevices * 10
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Errore nel caricamento dashboard' });
  }
});

// 🚨 GESTIONE ALLERTE
app.get('/api/alerts', authenticateToken, async (req, res) => {
  try {
    let deviceFilter = [];
    
    if (req.user.role === 'reseller') {
      const devices = await Device.find({ resellerCode: req.user.resellerCode });
      deviceFilter = devices.map(d => d.deviceId);
    } else if (req.user.role === 'customer') {
      const devices = await Device.find({ owner: req.user.username });
      deviceFilter = devices.map(d => d.deviceId);
    }

    const filter = { resolved: false };
    if (deviceFilter.length > 0) {
      filter.deviceId = { $in: deviceFilter };
    }

    const alerts = await Alert.find(filter).sort({ createdAt: -1 });
    res.json({ success: true, alerts });
  } catch (error) {
    res.status(500).json({ error: 'Errore nel caricamento allerte' });
  }
});

app.patch('/api/alerts/:alertId/resolve', authenticateToken, async (req, res) => {
  try {
    await Alert.findByIdAndUpdate(req.params.alertId, { resolved: true });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Errore nella risoluzione allerta' });
  }
});

// 🎮 COMANDI DISPOSITIVI
app.post('/api/commands', authenticateToken, async (req, res) => {
  try {
    const { deviceId, type, payload } = req.body;
    
    const command = new Command({
      deviceId,
      type,
      payload,
      status: 'sent'
    });
    
    await command.save();
    
    // Simula invio comando (in produzione sarebbe via WebSocket)
    setTimeout(async () => {
      await Command.findByIdAndUpdate(command._id, { status: 'acknowledged' });
    }, 1000);

    res.json({ 
      success: true, 
      message: 'Comando inviato',
      commandId: command._id 
    });
  } catch (error) {
    res.status(500).json({ error: 'Errore nell\'invio comando' });
  }
});

// 📡 TELEMETRIA (per dispositivi ESP32)
app.post('/api/telemetry', async (req, res) => {
  try {
    const telemetryData = req.body;
    
    const telemetry = new Telemetry(telemetryData);
    await telemetry.save();

    // Aggiorna stato dispositivo
    await Device.findOneAndUpdate(
      { deviceId: telemetryData.deviceId },
      { 
        lastSeen: new Date(),
        isOnline: true
      }
    );

    res.json({ success: true, message: "Telemetria ricevuta" });
  } catch (error) {
    console.error('Telemetry error:', error);
    res.status(500).json({ error: 'Errore processing telemetria' });
  }
});

// 🛠 UTILITY
app.get('/api/force-reset', async (req, res) => {
  if (req.query.key === 'dev-only-reset-2025') {
    await autoSetup();
    res.json({ success: true, message: 'Reset completato' });
  } else {
    res.status(403).json({ error: 'Chiave di reset richiesta' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============ AVVIO SERVER ============

app.listen(PORT, async () => {
  await autoSetup();
  console.log(`🚀 Server NabulAir avviato su porta ${PORT}`);
  console.log('👤 Credenziali demo: admin / Admin123!');
  console.log(`🌐 App: http://localhost:${PORT}`);
});