const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configurazione
const JWT_SECRET = process.env.JWT_SECRET || 'nabulair_super_secret_2025';
const PORT = process.env.PORT || 3000;

// Connessione MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/nabulair', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Schemi Database
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'reseller', 'customer'], default: 'customer' },
    resellerCode: { type: String }, // Codice univoco per rivenditore
    managedDevices: [{ type: String }], // Lista dispositivi gestiti
    company: String,
    email: String,
    phone: String,
    createdAt: { type: Date, default: Date.now }
});

const DeviceSchema = new mongoose.Schema({
    deviceId: { type: String, required: true, unique: true },
    deviceName: String,
    resellerCode: { type: String, required: true },
    owner: { type: String, required: true },
    systemType: { type: String, enum: ['pro', 'pro_duo', 'pro_duo_plus'] },
    firmwareVersion: String,
    lastSeen: { type: Date, default: Date.now },
    status: { type: String, enum: ['online', 'offline', 'maintenance'], default: 'offline' },
    location: {
        address: String,
        city: String,
        coordinates: {
            lat: Number,
            lng: Number
        }
    },
    installationDate: Date,
    warrantyExpiry: Date,
    createdAt: { type: Date, default: Date.now }
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
    },
    alerts: [{
        type: { type: String, enum: ['info', 'warning', 'error'] },
        message: String,
        timestamp: Date
    }]
});

const FirmwareSchema = new mongoose.Schema({
    version: { type: String, required: true },
    filePath: String,
    releaseDate: { type: Date, default: Date.now },
    changelog: String,
    compatibleDevices: [String],
    isActive: { type: Boolean, default: false }
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

// Modelli
const User = mongoose.model('User', UserSchema);
const Device = mongoose.model('Device', DeviceSchema);
const Telemetry = mongoose.model('Telemetry', TelemetrySchema);
const Firmware = mongoose.model('Firmware', FirmwareSchema);
const Alert = mongoose.model('Alert', AlertSchema);

// Middleware di Autenticazione
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token richiesto' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token non valido' });
        }
        req.user = user;
        next();
    });
};

// Middleware per Admin
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Accesso negato: richiesto ruolo admin' });
    }
    next();
};

// WebSocket per aggiornamenti in tempo reale
const connectedClients = new Map();

wss.on('connection', (ws, req) => {
    console.log('🔌 Nuova connessione WebSocket');
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'auth') {
                // Autenticazione WebSocket
                jwt.verify(data.token, JWT_SECRET, (err, user) => {
                    if (!err) {
                        connectedClients.set(ws, user);
                        console.log(`✅ WebSocket autenticato: ${user.username}`);
                    }
                });
            }
        } catch (error) {
            console.error('Errore WebSocket:', error);
        }
    });

    ws.on('close', () => {
        connectedClients.delete(ws);
        console.log('🔌 Connessione WebSocket chiusa');
    });
});

// Funzione per broadcast aggiornamenti
function broadcastToClients(userFilter, data) {
    connectedClients.forEach((user, ws) => {
        if (ws.readyState === WebSocket.OPEN) {
            // Filtra per permessi utente
            if (userFilter(user)) {
                ws.send(JSON.stringify(data));
            }
        }
    });
}

// =============================================
// ENDPOINT AUTHENTICAZIONE
// =============================================

// Registrazione (solo admin può creare rivenditori)
app.post('/api/register', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { username, password, role, resellerCode, company, email, phone } = req.body;

        // Verifica se l'utente esiste già
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username già esistente' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        const user = new User({
            username,
            password: hashedPassword,
            role,
            resellerCode,
            company,
            email,
            phone
        });

        await user.save();

        res.json({ 
            success: true, 
            message: 'Utente creato con successo',
            user: {
                id: user._id,
                username: user.username,
                role: user.role,
                resellerCode: user.resellerCode,
                company: user.company
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore durante la registrazione' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: 'Credenziali non valide' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Credenziali non valide' });
        }

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
        res.status(500).json({ error: 'Errore durante il login' });
    }
});

// =============================================
// ENDPOINT GESTIONE DISPOSITIVI
// =============================================

// Registrazione nuovo dispositivo
app.post('/api/devices/register', async (req, res) => {
    try {
        const { deviceId, deviceName, resellerCode, owner, systemType, location } = req.body;

        // Verifica se il dispositivo esiste già
        const existingDevice = await Device.findOne({ deviceId });
        if (existingDevice) {
            return res.status(400).json({ error: 'Dispositivo già registrato' });
        }

        const device = new Device({
            deviceId,
            deviceName,
            resellerCode,
            owner,
            systemType,
            location,
            installationDate: new Date(),
            warrantyExpiry: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 anno
        });

        await device.save();

        // Aggiungi dispositivo al rivenditore
        await User.findOneAndUpdate(
            { resellerCode },
            { $addToSet: { managedDevices: deviceId } }
        );

        res.json({ 
            success: true, 
            message: 'Dispositivo registrato con successo',
            device 
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore durante la registrazione del dispositivo' });
    }
});

// Lista dispositivi (filtrata per permessi)
app.get('/api/devices', authenticateToken, async (req, res) => {
    try {
        let filter = {};
        
        if (req.user.role === 'reseller') {
            filter.resellerCode = req.user.resellerCode;
        } else if (req.user.role === 'customer') {
            // I customer vedono solo i propri dispositivi
            filter.owner = req.user.username;
        }
        // Admin vede tutto (nessun filtro)

        const devices = await Device.find(filter)
            .sort({ lastSeen: -1 })
            .select('-__v');

        // Aggiungi telemetria recente per ogni dispositivo
        const devicesWithTelemetry = await Promise.all(
            devices.map(async (device) => {
                const latestTelemetry = await Telemetry.findOne({ deviceId: device.deviceId })
                    .sort({ timestamp: -1 })
                    .select('status cicloAttivo lavaggioAttivo secondiRimanenti timestamp')
                    .limit(1);

                const activeAlerts = await Alert.countDocuments({ 
                    deviceId: device.deviceId, 
                    resolved: false 
                });

                return {
                    ...device.toObject(),
                    latestTelemetry: latestTelemetry || {},
                    activeAlerts
                };
            })
        );

        res.json({ success: true, devices: devicesWithTelemetry });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel recupero dispositivi' });
    }
});

// Dettaglio dispositivo
app.get('/api/devices/:deviceId', authenticateToken, async (req, res) => {
    try {
        const device = await Device.findOne({ deviceId: req.params.deviceId });
        
        if (!device) {
            return res.status(404).json({ error: 'Dispositivo non trovato' });
        }

        // Controllo permessi
        if (req.user.role === 'reseller' && device.resellerCode !== req.user.resellerCode) {
            return res.status(403).json({ error: 'Accesso negato al dispositivo' });
        }

        if (req.user.role === 'customer' && device.owner !== req.user.username) {
            return res.status(403).json({ error: 'Accesso negato al dispositivo' });
        }

        // Telemetria recente (ultime 24 ore)
        const telemetry = await Telemetry.find({ 
            deviceId: req.params.deviceId,
            timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        }).sort({ timestamp: -1 }).limit(100);

        // Allerta attive
        const alerts = await Alert.find({ 
            deviceId: req.params.deviceId,
            resolved: false 
        }).sort({ createdAt: -1 });

        // Statistiche
        const stats = await Telemetry.aggregate([
            { $match: { deviceId: req.params.deviceId } },
            { $sort: { timestamp: -1 } },
            { $limit: 1000 },
            {
                $group: {
                    _id: null,
                    avgUptime: { $avg: '$systemMetrics.uptimeMs' },
                    avgHeap: { $avg: '$systemMetrics.freeHeap' },
                    totalCycles: { $sum: '$cicliOggi' },
                    totalConsumption: { $sum: '$consumoInsettMl' }
                }
            }
        ]);

        res.json({
            success: true,
            device,
            telemetry,
            alerts,
            statistics: stats[0] || {}
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel recupero dettagli dispositivo' });
    }
});

// =============================================
// ENDPOINT TELEMETRIA
// =============================================

// Ricezione telemetria dai dispositivi
app.post('/api/telemetry', async (req, res) => {
    try {
        const telemetryData = req.body;
        
        console.log('📡 Telemetria ricevuta:', telemetryData.deviceId);

        // Salva telemetria
        const telemetry = new Telemetry(telemetryData);
        await telemetry.save();

        // Aggiorna ultimo contatto dispositivo
        await Device.findOneAndUpdate(
            { deviceId: telemetryData.deviceId },
            { 
                lastSeen: new Date(),
                status: 'online',
                firmwareVersion: telemetryData.firmwareVersion || 'N/A'
            }
        );

        // Controlla allerta
        await checkAlerts(telemetryData);

        // Broadcast aggiornamento in tempo reale
        broadcastToClients(
            (user) => hasDeviceAccess(user, telemetryData.deviceId),
            {
                type: 'telemetry_update',
                deviceId: telemetryData.deviceId,
                data: telemetryData
            }
        );

        res.json({ success: true, message: "Telemetria ricevuta" });
    } catch (error) {
        console.error('Errore telemetria:', error);
        res.status(500).json({ error: 'Errore processing telemetria' });
    }
});

// Funzione per controllare allerta
async function checkAlerts(telemetryData) {
    const alerts = [];

    // Controllo offline (se non visto da più di 10 minuti)
    const lastSeen = await Device.findOne({ deviceId: telemetryData.deviceId }).select('lastSeen');
    if (lastSeen && (Date.now() - lastSeen.lastSeen.getTime() > 10 * 60 * 1000)) {
        alerts.push({
            deviceId: telemetryData.deviceId,
            type: 'offline',
            message: 'Dispositivo tornato online dopo periodo di offline',
            severity: 'medium'
        });
    }

    // Controllo memoria bassa
    if (telemetryData.systemMetrics && telemetryData.systemMetrics.freeHeap < 30000) {
        alerts.push({
            deviceId: telemetryData.deviceId,
            type: 'warning',
            message: `Memoria bassa: ${telemetryData.systemMetrics.freeHeap} bytes liberi`,
            severity: 'high'
        });
    }

    // Salva allerta
    for (const alert of alerts) {
        const existingAlert = await Alert.findOne({
            deviceId: alert.deviceId,
            type: alert.type,
            resolved: false
        });

        if (!existingAlert) {
            const newAlert = new Alert(alert);
            await newAlert.save();

            // Notifica in tempo reale
            broadcastToClients(
                (user) => hasDeviceAccess(user, alert.deviceId),
                {
                    type: 'alert_created',
                    alert: newAlert
                }
            );
        }
    }
}

// =============================================
// ENDPOINT GESTIONE ALLERTE
// =============================================

// Lista allerta
app.get('/api/alerts', authenticateToken, async (req, res) => {
    try {
        let deviceFilter = await getAccessibleDevices(req.user);

        const alerts = await Alert.find({ 
            deviceId: { $in: deviceFilter },
            resolved: req.query.resolved === 'true' 
        })
        .populate('deviceId', 'deviceName systemType')
        .sort({ createdAt: -1 })
        .limit(50);

        res.json({ success: true, alerts });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel recupero allerta' });
    }
});

// Risolvi allerta
app.patch('/api/alerts/:alertId/resolve', authenticateToken, async (req, res) => {
    try {
        const alert = await Alert.findById(req.params.alertId);
        
        if (!alert) {
            return res.status(404).json({ error: 'Allerta non trovata' });
        }

        // Controllo permessi
        const hasAccess = await hasDeviceAccess(req.user, alert.deviceId);
        if (!hasAccess) {
            return res.status(403).json({ error: 'Accesso negato' });
        }

        alert.resolved = true;
        alert.resolvedAt = new Date();
        alert.resolvedBy = req.user.username;
        await alert.save();

        // Notifica in tempo reale
        broadcastToClients(
            (user) => hasDeviceAccess(user, alert.deviceId),
            {
                type: 'alert_resolved',
                alert
            }
        );

        res.json({ success: true, message: 'Allerta risolta', alert });
    } catch (error) {
        res.status(500).json({ error: 'Errore nella risoluzione allerta' });
    }
});

// =============================================
// ENDPOINT FIRMWARE OTA (Over-The-Air)
// =============================================

// Lista firmware disponibili
app.get('/api/firmware', authenticateToken, async (req, res) => {
    try {
        const firmware = await Firmware.find({ isActive: true })
            .sort({ releaseDate: -1 })
            .select('-filePath');

        res.json({ success: true, firmware });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel recupero firmware' });
    }
});

// Upload nuovo firmware (solo admin)
app.post('/api/firmware', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { version, changelog, compatibleDevices } = req.body;

        const firmware = new Firmware({
            version,
            changelog,
            compatibleDevices,
            filePath: `/firmware/${version}.bin` // Path simulato
        });

        await firmware.save();

        res.json({ success: true, message: 'Firmware caricato', firmware });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel caricamento firmware' });
    }
});

// Check aggiornamenti firmware (chiamato dai dispositivi)
app.get('/api/firmware/check-update/:deviceId', async (req, res) => {
    try {
        const device = await Device.findOne({ deviceId: req.params.deviceId });
        if (!device) {
            return res.status(404).json({ error: 'Dispositivo non trovato' });
        }

        const latestFirmware = await Firmware.findOne({
            compatibleDevices: device.systemType,
            isActive: true
        }).sort({ releaseDate: -1 });

        if (!latestFirmware) {
            return res.json({ updateAvailable: false });
        }

        // Simula versione corrente (in produzione sarebbe dal dispositivo)
        const currentVersion = '4.1'; // Versione di default

        res.json({
            updateAvailable: latestFirmware.version !== currentVersion,
            latestVersion: latestFirmware.version,
            changelog: latestFirmware.changelog,
            fileUrl: `http://${req.get('host')}/api/firmware/download/${latestFirmware.version}`
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel check aggiornamenti' });
    }
});

// Download firmware
app.get('/api/firmware/download/:version', async (req, res) => {
    try {
        const firmware = await Firmware.findOne({ version: req.params.version });
        if (!firmware) {
            return res.status(404).json({ error: 'Firmware non trovato' });
        }

        // Simula download (in produzione servirebbe file reale)
        res.json({
            success: true,
            message: 'Download firmware simulato',
            version: firmware.version,
            fileSize: '1.2MB', // Dummy data
            downloadUrl: firmware.filePath
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel download firmware' });
    }
});

// =============================================
// ENDPOINT TELEASSISTENZA
// =============================================

// Comando remoto al dispositivo
app.post('/api/devices/:deviceId/command', authenticateToken, async (req, res) => {
    try {
        const { command, parameters } = req.body;
        const deviceId = req.params.deviceId;

        // Controllo permessi
        const hasAccess = await hasDeviceAccess(req.user, deviceId);
        if (!hasAccess) {
            return res.status(403).json({ error: 'Accesso negato' });
        }

        // Invia comando via WebSocket
        broadcastToClients(
            (user) => user.role === 'device', // I dispositivi ascoltano su canale speciale
            {
                type: 'device_command',
                deviceId,
                command,
                parameters,
                issuedBy: req.user.username,
                timestamp: new Date()
            }
        );

        // Log comando
        await new Alert({
            deviceId,
            type: 'info',
            message: `Comando inviato: ${command} da ${req.user.username}`,
            severity: 'low'
        }).save();

        res.json({ 
            success: true, 
            message: 'Comando inviato al dispositivo',
            command: {
                type: command,
                parameters,
                issuedAt: new Date()
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore nell\'invio comando' });
    }
});

// Sessioni di teleassistenza
app.post('/api/assistance/sessions', authenticateToken, async (req, res) => {
    try {
        const { deviceId, description } = req.body;

        // Controllo permessi
        const hasAccess = await hasDeviceAccess(req.user, deviceId);
        if (!hasAccess) {
            return res.status(403).json({ error: 'Accesso negato' });
        }

        const session = {
            sessionId: generateSessionId(),
            deviceId,
            technician: req.user.username,
            description,
            startTime: new Date(),
            status: 'active'
        };

        // In produzione, salveresti nel database
        // SessioniAttive.set(session.sessionId, session);

        res.json({ 
            success: true, 
            message: 'Sessione di assistenza avviata',
            session 
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore nell\'avvio sessione assistenza' });
    }
});

// =============================================
// ENDPOINT REPORT E STATISTICHE
// =============================================

// Dashboard statistiche
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        let deviceFilter = await getAccessibleDevices(req.user);

        const stats = await Promise.all([
            // Contatori dispositivi
            Device.aggregate([
                { $match: { deviceId: { $in: deviceFilter } } },
                { $group: { _id: '$status', count: { $sum: 1 } } }
            ]),
            // Contatori allerta
            Alert.aggregate([
                { $match: { deviceId: { $in: deviceFilter }, resolved: false } },
                { $group: { _id: '$severity', count: { $sum: 1 } } }
            ]),
            // Statistiche utilizzo
            Telemetry.aggregate([
                { $match: { deviceId: { $in: deviceFilter } } },
                { $sort: { timestamp: -1 } },
                { $limit: 1000 },
                {
                    $group: {
                        _id: null,
                        totalCycles: { $sum: '$cicliOggi' },
                        totalConsumption: { $sum: '$consumoInsettMl' },
                        avgUptime: { $avg: '$systemMetrics.uptimeMs' }
                    }
                }
            ])
        ]);

        const deviceStatus = stats[0].reduce((acc, curr) => {
            acc[curr._id] = curr.count;
            return acc;
        }, {});

        const alertSeverity = stats[1].reduce((acc, curr) => {
            acc[curr._id] = curr.count;
            return acc;
        }, {});

        const usageStats = stats[2][0] || {};

        res.json({
            success: true,
            dashboard: {
                totalDevices: deviceFilter.length,
                deviceStatus,
                alertSeverity,
                usageStats,
                lastUpdate: new Date()
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel recupero dashboard' });
    }
});

// =============================================
// FUNZIONI DI SUPPORTO
// =============================================

// Verifica accesso dispositivo
async function hasDeviceAccess(user, deviceId) {
    if (user.role === 'admin') return true;
    
    const device = await Device.findOne({ deviceId });
    if (!device) return false;

    if (user.role === 'reseller') {
        return device.resellerCode === user.resellerCode;
    }

    if (user.role === 'customer') {
        return device.owner === user.username;
    }

    return false;
}

// Lista dispositivi accessibili
async function getAccessibleDevices(user) {
    let filter = {};
    
    if (user.role === 'reseller') {
        filter.resellerCode = user.resellerCode;
    } else if (user.role === 'customer') {
        filter.owner = user.username;
    }

    const devices = await Device.find(filter).select('deviceId');
    return devices.map(d => d.deviceId);
}

// Genera ID sessione
function generateSessionId() {
    return 'sess_' + Math.random().toString(36).substr(2, 9);
}

// =============================================
// ENDPOINT ADMIN
// =============================================

// Gestione utenti (solo admin)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .select('-password -__v')
            .sort({ createdAt: -1 });

        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel recupero utenti' });
    }
});

// Statistiche globali (solo admin)
app.get('/api/admin/statistics', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const stats = await Promise.all([
            Device.countDocuments(),
            User.countDocuments(),
            Telemetry.countDocuments(),
            Alert.countDocuments({ resolved: false }),
            Device.aggregate([
                { $group: { _id: '$systemType', count: { $sum: 1 } } }
            ])
        ]);

        res.json({
            success: true,
            statistics: {
                totalDevices: stats[0],
                totalUsers: stats[1],
                totalTelemetry: stats[2],
                activeAlerts: stats[3],
                devicesByType: stats[4]
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel recupero statistiche' });
    }
});

// =============================================
// SERVIZIO WEB INTERFACE
// =============================================

// Serve interfaccia web
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

// =============================================
// INIZIALIZZAZIONE SERVER
// =============================================

// Creazione utente admin iniziale (solo prima esecuzione)
async function initializeAdmin() {
    const adminExists = await User.findOne({ role: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('admin123', 12);
        const admin = new User({
            username: 'admin',
            password: hashedPassword,
            role: 'admin',
            company: 'NabulAir',
            email: 'admin@nabulair.com'
        });
        await admin.save();
        console.log('👑 Utente admin creato: admin / admin123');
    }
}

server.listen(PORT, async () => {
    await initializeAdmin();
    console.log(`🚀 Server NabulAir Monitor attivo su porta ${PORT}`);
    console.log(`📊 Interfaccia web: http://localhost:${PORT}`);
    console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
});

// Gestione graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🛑 Ricevuto SIGTERM, arresto graceful...');
    server.close(() => {
        console.log('✅ Server arrestato');
        process.exit(0);
    });
});
