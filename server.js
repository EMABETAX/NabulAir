const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Endpoint per ricevere telemetria
app.post('/telemetry', (req, res) => {
    console.log('📡 Dati ricevuti:', req.body);
    res.json({ success: true, message: "Dati ricevuti" });
});

// Endpoint di test
app.get('/devices', (req, res) => {
    res.json([{ device_id: "TEST", status: "online" }]);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server attivo su porta ${PORT}`);
});
