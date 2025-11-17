const WebSocket = require('ws');

// ✅ REPLACE WITH YOUR ACTUAL TOKEN
const AUTH_TOKEN = 'your-jwt-token-here'; // Get from browser cookies
const WS_URL = `wss://websocket-chats.onrender.com?token=${AUTH_TOKEN}`;

console.log('🔌 Testing authenticated WebSocket connection');
console.log('🎫 Token:', AUTH_TOKEN.substring(0, 20) + '...');

const ws = new WebSocket(WS_URL);

ws.on('open', () => {
  console.log('✅ Connected!');
});

ws.on('message', (data) => {
  const message = JSON.parse(data.toString());
  console.log('📨 Received:', message);
  
  if (message.event === 'authenticated') {
    console.log('🎉 AUTHENTICATION SUCCESS!');
  }
});

ws.on('error', (error) => {
  console.error('❌ Error:', error.message);
});

ws.on('close', (code, reason) => {
  console.log(`🔌 Closed: ${code} - ${reason}`);
});

setTimeout(() => {
  ws.close();
}, 5000);