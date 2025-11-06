// server.js - NABULAIR PRO - SISTEMA COMPLETO (ESP32 + WEB + MOBILE)
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configurazione
const JWT_SECRET = process.env.JWT_SECRET || 'nabulair_super_secret_key_2025';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/nabulair';
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      connectSrc: ["'self'", "http://localhost:3001", "ws:", "wss:"],
    },
  },
}));

// Connessione MongoDB
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connesso'))
.catch(err => console.error('❌ MongoDB:', err));

// ==============================
// MODELLI DATABASE
// ==============================

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'reseller', 'customer'], default: 'customer' },
  resellerCode: String,
  company: String,
  email: String,
  isActive: { type: Boolean, default: true },
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});

const DeviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true },
  deviceName: { type: String, required: true },
  resellerCode: { type: String, required: true },
  owner: { type: String, required: true },
  ownerEmail: String,
  ownerPhone: String,
  systemType: { type: String, enum: ['pro', 'pro_duo', 'pro_duo_plus'], required: true },
  firmwareVersion: { type: String, default: '4.1' },
  lastSeen: { type: Date, default: Date.now },
  status: { type: String, enum: ['online', 'offline', 'maintenance'], default: 'offline' },
  location: {
    address: String,
    city: String,
    province: String,
    postalCode: String,
    coordinates: { lat: Number, lng: Number }
  },
  installationDate: { type: Date, default: Date.now },
  warrantyExpiry: Date,
  notes: String,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const TelemetrySchema = new mongoose.Schema({
  deviceId: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  status: String,
  systemType: String,
  cicloAttivo: Boolean,
  lavaggioAttivo: Boolean,
  secondiRimanenti: Number,
  volumeAcquaL: Number,
  prossimaAttivazione: String,
  cicliOggi: Number,
  consumoInsettMl: Number,
  volumeTotaleL: Number,
  systemMetrics: {
    freeHeap: Number,
    minHeap: Number,
    uptimeMs: Number,
    wifiClients: Number
  }
});

const AlertSchema = new mongoose.Schema({
  deviceId: String,
  type: { type: String, enum: ['offline', 'error', 'maintenance', 'warning'] },
  message: String,
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
  resolved: { type: Boolean, default: false },
  resolvedAt: Date,
  resolvedBy: String,
  createdAt: { type: Date, default: Date.now }
});

const CommandSchema = new mongoose.Schema({
  commandId: { type: String, unique: true, default: uuidv4 },
  deviceId: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['start_cycle', 'stop_cycle', 'start_wash', 'stop_wash', 'reboot', 'update_config'] 
  },
  payload: mongoose.Schema.Types.Mixed,
  status: { 
    type: String, 
    enum: ['pending', 'sent', 'acknowledged', 'failed'], 
    default: 'pending' 
  },
  sentAt: Date,
  acknowledgedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

// Modelli
const User = mongoose.model('User', UserSchema);
const Device = mongoose.model('Device', DeviceSchema);
const Telemetry = mongoose.model('Telemetry', TelemetrySchema);
const Alert = mongoose.model('Alert', AlertSchema);
const Command = mongoose.model('Command', CommandSchema);

// ==============================
// WEBSOCKET - GESTIONE CLIENTI
// ==============================

const connectedClients = new Map();

wss.on('connection', (ws) => {
  ws.isDevice = false;
  ws.deviceId = null;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      if (data.type === 'device_auth') {
        ws.isDevice = true;
        ws.deviceId = data.deviceId;
        connectedClients.set(ws, { deviceId: data.deviceId, isDevice: true });
        console.log(`🔌 Dispositivo connesso: ${data.deviceId}`);
        return;
      }

      if (data.type === 'user_auth') {
        jwt.verify(data.token, JWT_SECRET, (err, user) => {
          if (!err) {
            connectedClients.set(ws, { user, isDevice: false });
          }
        });
        return;
      }

      if (data.type === 'command_ack' && ws.isDevice) {
        Command.findOneAndUpdate(
          { commandId: data.commandId, deviceId: ws.deviceId },
          { 
            status: 'acknowledged', 
            acknowledgedAt: new Date(),
            result: data.result 
          },
          { new: true }
        ).then(cmd => {
          if (cmd) {
            broadcastToUser(ws.deviceId, { type: 'command_update', command: cmd });
          }
        });
      }
    } catch (error) {
      console.error('❌ WebSocket message error:', error);
    }
  });

  ws.on('close', () => {
    if (ws.isDevice && ws.deviceId) {
      console.log(`🔌 Dispositivo disconnesso: ${ws.deviceId}`);
    }
    connectedClients.delete(ws);
  });
});

function broadcastToUser(deviceId, message) {
  for (const [ws, info] of connectedClients) {
    if (!info.isDevice && info.user) {
      Device.findOne({ deviceId }).then(device => {
        if (device && (
          info.user.role === 'admin' ||
          (info.user.role === 'reseller' && device.resellerCode === info.user.resellerCode) ||
          (info.user.role === 'customer' && device.owner === info.user.username)
        )) {
          ws.send(JSON.stringify(message));
        }
      });
    }
  }
}

function sendToDevice(deviceId, message) {
  for (const [ws, info] of connectedClients) {
    if (info.isDevice && info.deviceId === deviceId) {
      ws.send(JSON.stringify(message));
      return true;
    }
  }
  return false;
}

// ==============================
// MIDDLEWARE
// ==============================

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

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Richiesto ruolo admin' });
  }
  next();
};

// ==============================
// FUNZIONI DI SUPPORTO
// ==============================

async function getDeviceIdsByReseller(resellerCode) {
  const devices = await Device.find({ resellerCode, isActive: true }).select('deviceId');
  return devices.map(d => d.deviceId);
}

async function getDeviceIdsByOwner(owner) {
  const devices = await Device.find({ owner, isActive: true }).select('deviceId');
  return devices.map(d => d.deviceId);
}

// ==============================
// ENDPOINT PUBBLICI (PER DISPOSITIVI ESP32)
// ==============================

app.get('/status', async (req, res) => {
  const deviceId = req.query.id;
  if (!deviceId) {
    return res.status(400).json({ error: 'Parametro "id" mancante' });
  }

  try {
    const device = await Device.findOne({ deviceId, isActive: true });
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo non registrato' });
    }

    res.json({
      success: true,
      systemType: device.systemType,
      firmwareVersion: device.firmwareVersion,
      config: {
        maxCyclesPerDay: 10,
        washDurationSec: 120,
        pump1Enabled: true,
        pump2Enabled: device.systemType !== 'pro',
        insectPumpEnabled: true
      }
    });
  } catch (error) {
    console.error('❌ Errore /status:', error);
    res.status(500).json({ error: 'Errore interno' });
  }
});

app.post('/api/telemetry', async (req, res) => {
  try {
    const telemetryData = req.body;
    if (!telemetryData.deviceId) {
      return res.status(400).json({ error: 'deviceId richiesto' });
    }

    const telemetry = new Telemetry(telemetryData);
    await telemetry.save();

    await Device.findOneAndUpdate(
      { deviceId: telemetryData.deviceId },
      { 
        lastSeen: new Date(),
        status: 'online',
        firmwareVersion: telemetryData.firmwareVersion,
        systemType: telemetryData.systemType
      }
    );

    broadcastToUser(telemetryData.deviceId, { 
      type: 'telemetry_update', 
      data: telemetryData 
    });

    res.json({ success: true, message: "Telemetria ricevuta" });
  } catch (error) {
    console.error('❌ Errore telemetria:', error);
    res.status(500).json({ error: 'Errore processing telemetria' });
  }
});

app.post('/api/alerts/device', async (req, res) => {
  try {
    const { deviceId, type, message, severity = 'medium' } = req.body;
    if (!deviceId || !type || !message) {
      return res.status(400).json({ error: 'Dati insufficienti' });
    }

    const alert = new Alert({ deviceId, type, message, severity });
    await alert.save();

    broadcastToUser(deviceId, { type: 'new_alert', alert });
    res.json({ success: true, alertId: alert._id });
  } catch (error) {
    console.error('❌ Errore segnalazione allerta:', error);
    res.status(500).json({ error: 'Errore' });
  }
});

// ==============================
// ENDPOINT UTENTE (WEB/APP)
// ==============================

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username, isActive: true });
    if (!user) return res.status(400).json({ error: 'Credenziali non valide' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Credenziali non valide' });

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username, 
        role: user.role,
        resellerCode: user.resellerCode 
      }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        resellerCode: user.resellerCode,
        company: user.company
      }
    });
  } catch (error) {
    console.error('❌ Errore login:', error);
    res.status(500).json({ error: 'Errore durante il login' });
  }
});

// Lista Rivenditori (solo admin)
app.get('/api/resellers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const resellers = await User.find(
      { role: 'reseller', isActive: true },
      { password: 0, __v: 0 }
    ).sort({ company: 1 });
    res.json({ success: true, resellers });
  } catch (error) {
    console.error('❌ Errore rivenditori:', error);
    res.status(500).json({ error: 'Errore nel recupero rivenditori' });
  }
});

// 👇 NUOVO ENDPOINT: Lista Clienti per Rivenditore
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    let filter = { role: 'customer', isActive: true };

    if (req.user.role === 'reseller') {
      filter.resellerCode = req.user.resellerCode;
    } else if (req.user.role === 'admin' && req.query.resellerCode) {
      filter.resellerCode = req.query.resellerCode;
    } else if (req.user.role === 'admin') {
      // Se admin non specifica, restituisce vuoto (per evitare sovraccarico)
      return res.json({ success: true, customers: [] });
    } else {
      return res.status(403).json({ error: 'Accesso negato' });
    }

    const customers = await User.find(filter, { 
      password: 0, __v: 0, isActive: 0, lastLogin: 0 
    }).sort({ username: 1 });

    res.json({ success: true, customers });
  } catch (error) {
    console.error('❌ Errore recupero clienti:', error);
    res.status(500).json({ error: 'Errore nel recupero clienti' });
  }
});

// Registrazione Nuovo Dispositivo
app.post('/api/devices', authenticateToken, async (req, res) => {
  try {
    const deviceData = req.body;
    
    if (req.user.role === 'reseller' && deviceData.resellerCode !== req.user.resellerCode) {
      return res.status(403).json({ error: 'Puoi registrare solo dispositivi per il tuo rivenditore' });
    }

    const existingDevice = await Device.findOne({ deviceId: deviceData.deviceId });
    if (existingDevice) {
      return res.status(400).json({ error: 'ID dispositivo già esistente' });
    }

    if (req.user.role === 'admin') {
      const resellerExists = await User.findOne({ 
        resellerCode: deviceData.resellerCode, 
        role: 'reseller' 
      });
      if (!resellerExists) {
        return res.status(400).json({ error: 'Codice rivenditore non valido' });
      }

      const customerExists = await User.findOne({ 
        username: deviceData.owner, 
        role: 'customer',
        resellerCode: deviceData.resellerCode
      });
      if (!customerExists) {
        return res.status(400).json({ error: 'Cliente non trovato per questo rivenditore' });
      }
    }

    const device = new Device({
      ...deviceData,
      warrantyExpiry: deviceData.warrantyExpiry || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
    });

    await device.save();
    console.log(`✅ Dispositivo registrato: ${deviceData.deviceId} per ${deviceData.resellerCode}`);

    res.status(201).json({ 
      success: true, 
      message: 'Dispositivo registrato con successo',
      device: {
        deviceId: device.deviceId,
        deviceName: device.deviceName,
        resellerCode: device.resellerCode,
        owner: device.owner,
        systemType: device.systemType
      }
    });
  } catch (error) {
    console.error('❌ Errore registrazione dispositivo:', error);
    res.status(500).json({ error: 'Errore durante la registrazione' });
  }
});

// Lista Dispositivi
app.get('/api/devices', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    
    let filter = { isActive: true };
    
    if (req.user.role === 'reseller') {
      filter.resellerCode = req.user.resellerCode;
    } else if (req.user.role === 'customer') {
      filter.owner = req.user.username;
    }

    if (req.user.role === 'admin' && req.query.resellerCode) {
      filter.resellerCode = req.query.resellerCode;
    }

    const [devices, total] = await Promise.all([
      Device.find(filter)
        .sort({ lastSeen: -1 })
        .skip(skip)
        .limit(limit)
        .select('-__v')
        .lean(),
      Device.countDocuments(filter)
    ]);

    const devicesWithTelemetry = await Promise.all(
      devices.map(async (device) => {
        const [latestTelemetry, activeAlerts] = await Promise.all([
          Telemetry.findOne({ deviceId: device.deviceId })
            .sort({ timestamp: -1 })
            .select('status cicloAttivo lavaggioAttivo secondiRimanenti timestamp')
            .limit(1)
            .lean(),
          Alert.countDocuments({ 
            deviceId: device.deviceId, 
            resolved: false 
          })
        ]);

        return {
          ...device,
          latestTelemetry: latestTelemetry || {},
          activeAlerts,
          isOnline: device.status === 'online'
        };
      })
    );

    res.json({ 
      success: true, 
      devices: devicesWithTelemetry,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      },
      userRole: req.user.role
    });
  } catch (error) {
    console.error('❌ Errore dispositivi:', error);
    res.status(500).json({ error: 'Errore nel recupero dispositivi' });
  }
});

// Dettaglio Dispositivo
app.get('/api/devices/:deviceId', authenticateToken, async (req, res) => {
  try {
    const device = await Device.findOne({ deviceId: req.params.deviceId });
    if (!device) return res.status(404).json({ error: 'Dispositivo non trovato' });

    if (req.user.role === 'reseller' && device.resellerCode !== req.user.resellerCode) {
      return res.status(403).json({ error: 'Accesso negato' });
    }
    if (req.user.role === 'customer' && device.owner !== req.user.username) {
      return res.status(403).json({ error: 'Accesso negato' });
    }

    const [telemetry, alerts] = await Promise.all([
      Telemetry.find({ 
        deviceId: req.params.deviceId,
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }).sort({ timestamp: -1 }).limit(100),
      Alert.find({ 
        deviceId: req.params.deviceId,
        resolved: false 
      }).sort({ createdAt: -1 })
    ]);

    res.json({
      success: true,
      device,
      telemetry,
      alerts
    });
  } catch (error) {
    console.error('❌ Errore dettaglio dispositivo:', error);
    res.status(500).json({ error: 'Errore nel recupero dettagli' });
  }
});

// Dashboard Statistiche
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    let deviceFilter = { isActive: true };
    
    if (req.user.role === 'reseller') {
      deviceFilter.resellerCode = req.user.resellerCode;
    } else if (req.user.role === 'customer') {
      deviceFilter.owner = req.user.username;
    }

    const [deviceStats, alertStats, totalDevices, recentActivity] = await Promise.all([
      Device.aggregate([
        { $match: deviceFilter },
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]),
      Alert.aggregate([
        { 
          $match: { 
            resolved: false,
            ...(req.user.role === 'reseller' && {
              deviceId: { $in: await getDeviceIdsByReseller(req.user.resellerCode) }
            }),
            ...(req.user.role === 'customer' && {
              deviceId: { $in: await getDeviceIdsByOwner(req.user.username) }
            })
          } 
        },
        { $group: { _id: '$severity', count: { $sum: 1 } } }
      ]),
      Device.countDocuments(deviceFilter),
      Telemetry.countDocuments({ 
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
      })
    ]);

    const deviceStatus = deviceStats.reduce((acc, curr) => {
      acc[curr._id] = curr.count;
      return acc;
    }, { online: 0, offline: 0, maintenance: 0 });

    const alertSeverity = alertStats.reduce((acc, curr) => {
      acc[curr._id] = curr.count;
      return acc;
    }, { high: 0, medium: 0, low: 0 });

    res.json({
      success: true,
      dashboard: {
        totalDevices,
        deviceStatus,
        alertSeverity,
        recentActivity,
        lastUpdate: new Date()
      }
    });
  } catch (error) {
    console.error('❌ Errore dashboard:', error);
    res.status(500).json({ error: 'Errore nel recupero dashboard' });
  }
});

// Lista Allerte
app.get('/api/alerts', authenticateToken, async (req, res) => {
  try {
    let filter = { resolved: false };
    if (req.user.role === 'reseller') {
      const ids = await getDeviceIdsByReseller(req.user.resellerCode);
      filter.deviceId = { $in: ids };
    } else if (req.user.role === 'customer') {
      const ids = await getDeviceIdsByOwner(req.user.username);
      filter.deviceId = { $in: ids };
    }
    if (req.query.deviceId) filter.deviceId = req.query.deviceId;

    const alerts = await Alert.find(filter).sort({ createdAt: -1 }).limit(50);
    res.json({ success: true, alerts });
  } catch (error) {
    console.error('❌ Errore allerte:', error);
    res.status(500).json({ error: 'Errore' });
  }
});

// Risolvi Allerta
app.patch('/api/alerts/:alertId/resolve', authenticateToken, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.alertId);
    if (!alert) return res.status(404).json({ error: 'Allerta non trovata' });

    const device = await Device.findOne({ deviceId: alert.deviceId });
    if (!device || 
        (req.user.role === 'reseller' && device.resellerCode !== req.user.resellerCode) ||
        (req.user.role === 'customer' && device.owner !== req.user.username)) {
      return res.status(403).json({ error: 'Accesso negato' });
    }

    alert.resolved = true;
    alert.resolvedAt = new Date();
    alert.resolvedBy = req.user.username;
    await alert.save();

    broadcastToUser(alert.deviceId, { type: 'alert_resolved', alertId: alert._id });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Errore risoluzione allerta:', error);
    res.status(500).json({ error: 'Errore' });
  }
});

// Invia Comando a Dispositivo
app.post('/api/commands', authenticateToken, async (req, res) => {
  try {
    const { deviceId, type, payload = {} } = req.body;
    if (!deviceId || !type) {
      return res.status(400).json({ error: 'deviceId e type richiesti' });
    }

    const device = await Device.findOne({ deviceId, isActive: true });
    if (!device || 
        (req.user.role === 'reseller' && device.resellerCode !== req.user.resellerCode) ||
        (req.user.role === 'customer' && device.owner !== req.user.username)) {
      return res.status(403).json({ error: 'Accesso negato' });
    }

    const command = new Command({ deviceId, type, payload });
    await command.save();

    const sent = sendToDevice(deviceId, {
      type: 'command',
      commandId: command.commandId,
      action: type,
      params: payload
    });

    if (sent) {
      command.status = 'sent';
      command.sentAt = new Date();
      await command.save();
    }

    res.json({ 
      success: true, 
      commandId: command.commandId,
      delivered: sent 
    });
  } catch (error) {
    console.error('❌ Errore invio comando:', error);
    res.status(500).json({ error: 'Errore' });
  }
});

// Stato Comando
app.get('/api/commands/:commandId', authenticateToken, async (req, res) => {
  try {
    const command = await Command.findOne({ commandId: req.params.commandId });
    if (!command) return res.status(404).json({ error: 'Comando non trovato' });

    const device = await Device.findOne({ deviceId: command.deviceId });
    if (!device || 
        (req.user.role === 'reseller' && device.resellerCode !== req.user.resellerCode) ||
        (req.user.role === 'customer' && device.owner !== req.user.username)) {
      return res.status(403).json({ error: 'Accesso negato' });
    }

    res.json({ success: true, command });
  } catch (error) {
    console.error('❌ Errore stato comando:', error);
    res.status(500).json({ error: 'Errore' });
  }
});

// ==============================
// INIZIALIZZAZIONE DATABASE
// ==============================

async function initializeDatabase() {
  try {
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      console.log('📝 Inizializzazione database...');
      const hashedPassword = await bcrypt.hash('Admin123!', 12);
      await User.create([
        { username: 'admin', password: hashedPassword, role: 'admin', company: 'NabulAir HQ', email: 'admin@nabulair.com' },
        { username: 'rivenditore_nord', password: hashedPassword, role: 'reseller', resellerCode: 'RES_NORD', company: 'Rivenditore Nord Italia', email: 'nord@nabulair.com' },
        { username: 'cliente_demo', password: hashedPassword, role: 'customer', resellerCode: 'RES_NORD', company: 'Cliente Demo', email: 'cliente@demo.com' }
      ]);
      console.log('✅ Database inizializzato');
    }
  } catch (error) {
    console.error('❌ Errore inizializzazione:', error);
  }
}

// ==============================
// ROUTE SPA (ULTIMA!)
// ==============================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==============================
// GESTIONE ERRORI
// ==============================

app.use((err, req, res, next) => {
  console.error('❌ Errore non gestito:', err);
  res.status(500).json({ error: 'Errore interno del server' });
});

// ==============================
// AVVIO SERVER
// ==============================

async function startServer() {
  await initializeDatabase();
  server.listen(PORT, () => {
    console.log(`\n🚀 NabulAir Pro - Sistema Completo`);
    console.log(`📍 Porta: ${PORT}`);
    console.log(`🌐 Web: http://localhost:${PORT}`);
    console.log(`📡 ESP32 /status: http://<server>:${PORT}/status?id=NABUL001`);
    console.log('\n👤 CREDENZIALI DEMO:');
    console.log('   Admin: admin / Admin123!');
    console.log('   Rivenditore: rivenditore_nord / Admin123!');
    console.log('   Cliente: cliente_demo / Admin123!');
    console.log('\n✅ Sistema pronto per Nabulair Pro, Pro Duo, Pro Duo Plus!');
  });
}

startServer();