// websocket-server.js
const WebSocket = require('ws');
const http = require('http');
const prisma = require('./prisma-wa');
const cookie = require('cookie');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const connections = new Map(); // roomId -> Set of clients

const PORT = process.env.PORT || 3001;
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

// Add this after line 11 (after PORT declaration)
const express = require('express');
const app = express();

// Health check endpoint to prevent Render sleep
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    connections: connections.size
  });
});

// Self-ping mechanism to prevent Render sleep
let keepAliveInterval = null;

function startKeepAlive() {
  // Only enable on production (Render)
  if (process.env.NODE_ENV === 'production' && process.env.RENDER_SERVICE_NAME) {
    const PING_INTERVAL = 2 * 60 * 1000; // 2 minutes
    const serviceUrl = process.env.RENDER_EXTERNAL_URL || `https://${process.env.RENDER_SERVICE_NAME}.onrender.com`;
    
    console.log('🔄 Keep-alive enabled:', serviceUrl);
    
    keepAliveInterval = setInterval(async () => {
      try {
        const http = require('https');
        const startTime = Date.now();
        
        http.get(`${serviceUrl}/health`, (res) => {
          const duration = Date.now() - startTime;
          console.log(`✅ Keep-alive ping successful (${duration}ms) - Status: ${res.statusCode}`);
        }).on('error', (err) => {
          console.error('❌ Keep-alive ping failed:', err.message);
        });
        
      } catch (error) {
        console.error('❌ Keep-alive error:', error.message);
      }
    }, PING_INTERVAL);
    
    // Initial ping after 30 seconds
    setTimeout(() => {
      console.log('🔄 Sending initial keep-alive ping...');
      const http = require('https');
      http.get(`${serviceUrl}/health`, () => {
        console.log('✅ Initial ping sent');
      }).on('error', (err) => {
        console.error('❌ Initial ping failed:', err.message);
      });
    }, 30000);
  } else {
    console.log('ℹ️ Keep-alive disabled (development mode)');
  }
}

// Stop keep-alive on shutdown
function stopKeepAlive() {
  if (keepAliveInterval) {
    clearInterval(keepAliveInterval);
    console.log('🛑 Keep-alive stopped');
  }
}

// Create HTTP server with Express
const server = http.createServer(app);

// ✅ Unified encryption function (matches encryption.ts format)
function encryptMessage(content) {
  try {
    const key = Buffer.from(process.env.CHAT_ENCRYPTION_KEY, 'hex');
    
    if (key.length !== 32) {
      throw new Error('CHAT_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)');
    }
    
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    let encrypted = cipher.update(content, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    const authTag = cipher.getAuthTag();
    
    const combined = Buffer.concat([iv, encrypted, authTag]);
    const encryptedContent = combined.toString('base64');
    
    const contentHash = crypto
      .createHash('sha256')
      .update(content)
      .digest('hex');
    
    return { encryptedContent, contentHash };
  } catch (error) {
    console.error('Encryption error:', error);
    throw error;
  }
}

// ✅ Unified decryption function (matches encryption.ts format)
function decryptMessage(encryptedData) {
  try {
    const key = Buffer.from(process.env.CHAT_ENCRYPTION_KEY, 'hex');
    
    if (key.length !== 32) {
      throw new Error('CHAT_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)');
    }
    
    const combined = Buffer.from(encryptedData, 'base64');
    
    const iv = combined.subarray(0, IV_LENGTH);
    const authTag = combined.subarray(combined.length - AUTH_TAG_LENGTH);
    const encrypted = combined.subarray(IV_LENGTH, combined.length - AUTH_TAG_LENGTH);
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted.toString('utf8');
  } catch (error) {
    console.error('Decryption error:', error);
    return encryptedData;
  }
}

// ✅ ENHANCED AVATAR URL GENERATOR with Red/White/Black Color Scheme
function generateAvatarUrl(userId, avatarIndex, avatarSeed, avatarStyle = 'avataaars', size = 64) {
  // Red and White shades (matching AvatarGenerator component)
  const redShades = ['ff0000', 'dc2626', 'ef4444', 'f87171', 'fca5a5', 'b91c1c', '991b1b', 'e11d48', 'be123c'];
  const whiteShades = ['ffffff', 'fafafa', 'f5f5f5', 'f0f0f0', 'e5e5e5', 'e8e8e8', 'ececec'];
  
  // Select colors based on avatar index
  const primaryRed = redShades[avatarIndex % redShades.length];
  const secondaryRed = redShades[(avatarIndex + 3) % redShades.length];
  const primaryWhite = whiteShades[avatarIndex % whiteShades.length];
  const secondaryWhite = whiteShades[(avatarIndex + 2) % whiteShades.length];
  
  // Build dicebear URL with custom colors
  const params = new URLSearchParams({
    seed: avatarSeed,
    size: size.toString(),
    backgroundColor: '000000', // Black background
    backgroundType: 'solid',
  });
  
  // Add color arrays for red and white theme
  const colorParams = [
    `clothesColor=${primaryRed},${secondaryRed}`,
    `skinColor=${primaryWhite},${secondaryWhite}`,
    `hairColor=${primaryRed},${secondaryRed}`,
    `facialHairColor=${primaryRed}`,
    `accessoriesColor=${primaryRed}`
  ];
  
  return `https://api.dicebear.com/7.x/${avatarStyle}/svg?${params.toString()}&${colorParams.join('&')}`;
}

// ✅ UPDATED: Get Avatar URL from User Object (matches Navbar logic)
function getAvatarUrl(user, size = 64) {
  if (!user) {
    // Default avatar with red/white/black theme
    return generateAvatarUrl('default', 0, 'default', 'avataaars', size);
  }
  
  // Priority 1: Custom uploaded image (user.img)
  if (user.img) {
    return user.img;
  }
  
  // Priority 2: Primary avatar from avatars table
  const primaryAvatar = user.avatars?.find(a => a.isPrimary) || user.avatars?.[0];
  
  if (primaryAvatar) {
    // Priority 2a: Custom upload in avatar
    if (primaryAvatar.isCustomUpload && primaryAvatar.customImageUrl) {
      return primaryAvatar.customImageUrl;
    }
    
    // Priority 2b: Generated avatar with custom colors
    return generateAvatarUrl(
      user.id,
      primaryAvatar.avatarIndex,
      primaryAvatar.avatarSeed,
      primaryAvatar.avatarStyle || 'avataaars',
      size
    );
  }
  
  // Fallback: Generate default avatar with username/id seed
  const seed = user.username || user.id || 'default';
  return generateAvatarUrl(user.id || 'default', 0, seed, 'avataaars', size);
}

// Test Prisma connection on startup
async function testPrismaConnection() {
  try {
    await prisma.$connect();
    console.log('✅ Prisma connected successfully');
    
    const count = await prisma.student.count();
    console.log(`Found ${count} students in database`);
    return true;
  } catch (error) {
    console.error('❌ Prisma connection failed:', error.message);
    return false;
  }
}

// ✅ IMPROVED: More flexible origin validation
const wss = new WebSocket.Server({ 
  server,
  verifyClient: (info, callback) => {
    const origin = info.origin;
    
    // ✅ Allow connections without origin (mobile apps, Postman, etc.)
    if (!origin) {
      callback(true);
      return;
    }
    
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://localhost:3000',
      'https://localhost:3001',
      process.env.FRONTEND_URL,
      process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null,
    ].filter(Boolean);
    
    // ✅ Allow all Vercel preview deployments
    const isVercel = origin?.includes('.vercel.app');
    const isAllowed = allowedOrigins.some(allowed => 
      origin === allowed || origin?.startsWith(allowed)
    );
    
    if (isAllowed || isVercel) {
      console.log('✅ Accepted connection from:', origin);
      callback(true);
    } else {
      console.log('❌ Rejected connection from:', origin);
      callback(false, 403, 'Forbidden');
    }
  }
});

// Helper: Parse cookies and authenticate
// ✅ FIXED: Accept token from query string OR cookies
async function authenticateUser(request) {
  try {
    console.log('🔐 [AUTH] Starting authentication...');
    console.log('🔐 [AUTH] Request URL:', request.url);
    console.log('🔐 [AUTH] Request Headers:', {
      host: request.headers.host,
      origin: request.headers.origin,
      cookie: request.headers.cookie ? 'Present' : 'Not present'
    });
    
    if (!prisma || !prisma.student) {
      console.error('❌ [AUTH] Database connection not available');
      throw new Error('Database connection not available');
    }

    // ✅ TRY 1: Get token from query string
    const url = new URL(request.url, `http://${request.headers.host}`);
    let token = url.searchParams.get('token');
    
    console.log('🔐 [AUTH] Token from query:', token ? `Yes (${token.length} chars)` : 'No');
    
    // ✅ TRY 2: Fallback to cookies
    if (!token) {
      const cookies = cookie.parse(request.headers.cookie || '');
      token = cookies['auth-token'];
      console.log('🔐 [AUTH] Token from cookie:', token ? `Yes (${token.length} chars)` : 'No');
    }
    
    if (!token) {
      console.error('❌ [AUTH] No token found in query or cookies');
      throw new Error('No auth token');
    }

    // ✅ Log JWT_SECRET (first 10 chars only for security)
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error('❌ [AUTH] JWT_SECRET not set in environment!');
      throw new Error('Server configuration error');
    }
    console.log('🔐 [AUTH] JWT_SECRET exists:', jwtSecret.substring(0, 10) + '...');

    // ✅ Decode without verification first to check payload
    let decoded;
    try {
      const decodedNoVerify = jwt.decode(token);
      console.log('🔐 [AUTH] Token payload (no verification):', {
        userId: decodedNoVerify?.userId,
        exp: decodedNoVerify?.exp ? new Date(decodedNoVerify.exp * 1000).toISOString() : 'No expiry',
        iat: decodedNoVerify?.iat ? new Date(decodedNoVerify.iat * 1000).toISOString() : 'No issued at'
      });
      
      // Now verify
      decoded = jwt.verify(token, jwtSecret);
      console.log('✅ [AUTH] Token verified successfully');
      
    } catch (verifyError) {
      console.error('❌ [AUTH] Token verification failed:', verifyError.message);
      if (verifyError.name === 'TokenExpiredError') {
        throw new Error('Token expired. Please log in again.');
      }
      if (verifyError.name === 'JsonWebTokenError') {
        throw new Error('Invalid token. Please log in again.');
      }
      throw verifyError;
    }
    
    if (!decoded || !decoded.userId) {
      console.error('❌ [AUTH] Invalid token payload:', decoded);
      throw new Error('Invalid token payload');
    }

    console.log('🔐 [AUTH] Looking up user:', decoded.userId);
    
    const user = await prisma.student.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        username: true,
        name: true,
        img: true,
        avatars: {
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            avatarIndex: true,
            avatarSeed: true,
            avatarStyle: true,
            isPrimary: true,
            isCustomUpload: true,
            customImageUrl: true,
          }
        }
      }
    });

    if (!user) {
      console.error('❌ [AUTH] User not found in database:', decoded.userId);
      throw new Error('User not found');
    }

    console.log('✅ [AUTH] User authenticated successfully:', {
      id: user.id,
      username: user.username,
      name: user.name
    });
    
    return user;
    
  } catch (error) {
    console.error('❌ [AUTH] Authentication failed:', {
      message: error.message,
      name: error.name,
      stack: error.stack?.split('\n')[0]
    });
    return null;
  }
}

// Helper: Broadcast to room
function broadcastToRoom(roomId, event, data, excludeClientId = null) {
  const roomConnections = connections.get(roomId);
  if (!roomConnections) return;

  const message = JSON.stringify({ event, data });

  roomConnections.forEach(client => {
    if (client.readyState === WebSocket.OPEN && client.clientId !== excludeClientId) {
      client.send(message);
    }
  });
}

// WebSocket connection handler
wss.on('connection', async (ws, request) => {
  console.log('🔌 New WebSocket connection attempt');
  console.log('📍 Origin:', request.headers.origin);
  console.log('🌐 Host:', request.headers.host);
  console.log('🔗 URL:', request.url);

  let user = null;
  let roomId = null;
  let participantId = null;
  const clientId = Math.random().toString(36).substr(2, 9);
  ws.clientId = clientId;

  // Authenticate user
  user = await authenticateUser(request);

  if (!user) {
    console.log('❌ WS: Authentication failed');
    ws.send(JSON.stringify({
      event: 'error',
      data: { 
        message: 'Authentication failed. Please log in again.', 
        code: 'AUTH_FAILED' 
      }
    }));
    ws.close(1008, 'Authentication failed'); // ✅ Use proper close code
    return;
  }

  console.log('✅ WS: User authenticated:', user.username, user.id);

  // Send authentication success
  ws.send(JSON.stringify({
    event: 'authenticated',
    data: { userId: user.id, username: user.username }
  }));

  // Handle incoming messages
  ws.on('message', async (message) => {
    try {
      const { event, data } = JSON.parse(message.toString());
      console.log('📨 WS: Received event:', event, 'from user:', user.id);

      switch (event) {
        case 'join_room':
          try {
            const requestedRoomId = data.roomId;
            
            if (!requestedRoomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Room ID is required', code: 'MISSING_ROOM_ID' }
              }));
              return;
            }

            // Verify participant access
            const participant = await prisma.chatParticipant.findUnique({
              where: {
                roomId_userId: {
                  roomId: requestedRoomId,
                  userId: user.id
                }
              }
            });

            if (!participant) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Access denied to this room', code: 'ACCESS_DENIED' }
              }));
              return;
            }

            roomId = requestedRoomId;
            participantId = participant.id;
            ws.roomId = roomId;
            ws.participantId = participantId;

            // Update online status
            await prisma.chatParticipant.update({
              where: { id: participantId },
              data: { isOnline: true, lastSeen: new Date() }
            });

            // Add to room connections
            if (!connections.has(roomId)) {
              connections.set(roomId, new Set());
            }
            connections.get(roomId).add(ws);

            console.log('✅ WS: User joined room:', roomId);

            // Send confirmation
            ws.send(JSON.stringify({
              event: 'room_joined',
              data: { roomId, userId: user.id }
            }));

            // Broadcast user online to room with avatar
            broadcastToRoom(roomId, 'user:online', {
              userId: user.id,
              username: user.username,
              avatar: getAvatarUrl(user, 64),
              timestamp: new Date().toISOString()
            }, clientId);

          } catch (error) {
            console.error('❌ WS: Join room error:', error);
            ws.send(JSON.stringify({
              event: 'error',
              data: { 
                message: `Failed to join room: ${error.message}`,
                code: 'JOIN_FAILED'
              }
            }));
          }
          break;

        case 'send_message':
          try {
            if (!roomId || !participantId) {
              const errorMsg = !roomId 
                ? 'Not in a room. Please rejoin.' 
                : 'Session expired. Please reload.';
              
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: errorMsg, code: 'NOT_IN_ROOM' }
              }));
              return;
            }

            const { content, replyToId, messageType = 'text' } = data;

            if (!content || content.trim().length === 0) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Message content is required', code: 'EMPTY_MESSAGE' }
              }));
              return;
            }

            // ✅ Encrypt message
            const { encryptedContent, contentHash } = encryptMessage(content);

            const wordCount = content.trim().split(/\s+/).length;
            const characterCount = content.length;

            // ✅ Create message with full user data including avatars
            const message = await prisma.chatMessage.create({
              data: {
                roomId,
                userId: user.id,
                encryptedContent,
                contentHash,
                messageType,
                replyToId,
                wordCount,
                characterCount
              },
              include: {
                user: {
                  select: {
                    id: true,
                    username: true,
                    name: true,
                    surname: true,
                    img: true,
                    avatars: {
                      orderBy: { createdAt: 'desc' },
                      select: {
                        id: true,
                        avatarIndex: true,
                        avatarSeed: true,
                        avatarStyle: true,
                        isPrimary: true,
                        isCustomUpload: true,
                        customImageUrl: true,
                      }
                    },
                    userXP: {
                      select: {
                        totalXP: true,
                        contributorTitle: true
                      }
                    },
                    badges: {
                      where: { isEarned: true, isDisplayed: true },
                      orderBy: { displayOrder: 'asc' },
                      take: 3,
                      select: {
                        id: true,
                        title: true,
                        icon: true,
                        color: true
                      }
                    },
                    _count: {
                      select: {
                        followers: true,
                        following: true,
                        courses: true
                      }
                    },
                    UserGoals: {
                      select: { purpose: true },
                      take: 1
                    }
                  }
                },
                replyTo: {
                  include: {
                    user: {
                      select: {
                        id: true,
                        username: true,
                        name: true,
                        img: true,
                        avatars: {
                          where: { isPrimary: true },
                          take: 1,
                          select: {
                            id: true,
                            avatarIndex: true,
                            avatarSeed: true,
                            avatarStyle: true,
                            isPrimary: true,
                            isCustomUpload: true,
                            customImageUrl: true,
                          }
                        }
                      }
                    }
                  }
                },
                reactions: true
              }
            });

            // Update participant stats
            Promise.all([
              prisma.chatParticipant.update({
                where: { id: participantId },
                data: {
                  messagesCount: { increment: 1 },
                  lastSeen: new Date()
                }
              }),
              prisma.chatRoomAnalytics.upsert({
                where: { roomId },
                create: {
                  roomId,
                  totalMessages: 1,
                  totalWords: wordCount
                },
                update: {
                  totalMessages: { increment: 1 },
                  totalWords: { increment: wordCount },
                  lastCalculated: new Date()
                }
              })
            ]).catch(err => console.error('Failed to update stats:', err));

            // ✅ BUILD COMPLETE USER METADATA WITH PROPER AVATAR
            const avatarUrl = getAvatarUrl(message.user, 64);
            const primaryAvatar = message.user.avatars?.find(a => a.isPrimary) || message.user.avatars?.[0] || null;
            
            const userGoal = message.user.UserGoals?.[0];
            let userType = 'learner';
            if (userGoal) {
              if (userGoal.purpose === 'teach') userType = 'tutor';
              else if (userGoal.purpose === 'both') userType = 'both';
            }

            const userMetadata = {
              id: message.user.id,
              username: message.user.username,
              name: message.user.name || 'User',
              surname: message.user.surname,
              avatar: avatarUrl,
              avatarObject: primaryAvatar,
              img: avatarUrl,
              isOnline: true,
              type: userType,
              role: userType === 'tutor' ? 'mentor' : 'student',
              xp: message.user.userXP?.totalXP || 0,
              seekers: message.user._count.followers || 0,
              seeking: message.user._count.following || 0,
              coursesMade: message.user._count.courses || 0,
              coursesLearning: 0,
              badges: (message.user.badges || []).map(badge => ({
                id: badge.id,
                name: badge.title,
                icon: badge.icon,
                color: badge.color
              })),
              bio: '',
              isPrivate: false
            };

            // ✅ BROADCAST WITH COMPLETE AVATAR DATA
            const messageData = {
              id: message.id,
              userId: message.userId,
              roomId: message.roomId,
              content: content,
              messageType: message.messageType,
              createdAt: message.createdAt.toISOString(),
              timestamp: message.createdAt.toISOString(), // ✅ ADD THIS
              isEdited: message.isEdited,
              
              // User info with proper avatar
              user: {
                ...message.user,
                avatar: avatarUrl,
                avatarObject: primaryAvatar,
              },
              
              // Complete user metadata
              userMetadata: userMetadata,
              userName: message.user.name || 'User',
              userAvatar: avatarUrl,
              userRole: userType === 'tutor' ? 'mentor' : 'student',
              
              replyTo: message.replyTo ? {
    ...message.replyTo,
    createdAt: message.replyTo.createdAt.toISOString(), // ✅ Add this
    user: {
      ...message.replyTo.user,
      avatar: getAvatarUrlFromUser(message.replyTo.user, 48),
      avatarObject: message.replyTo.user.avatars?.[0] || null
    }
  } : undefined,
              
              reactions: []
            };

            // Broadcast to room
            const roomConnections = connections.get(roomId);
            if (roomConnections) {
              roomConnections.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                  client.send(JSON.stringify({
                    event: 'message:new',
                    data: messageData
                  }));
                }
              });
            }

            console.log('✅ WS: Message sent with avatar:', avatarUrl);

          } catch (error) {
            console.error('❌ WS: Send message error:', error);
            ws.send(JSON.stringify({
              event: 'error',
              data: { 
                message: 'Failed to send message',
                details: error.message,
                code: 'SEND_FAILED'
              }
            }));
          }
          break;

        case 'typing':
          try {
            if (!roomId) return;

            const { isTyping } = data;

            if (isTyping) {
              await prisma.chatTypingIndicator.upsert({
                where: {
                  roomId_userId: {
                    roomId,
                    userId: user.id
                  }
                },
                create: {
                  roomId,
                  userId: user.id,
                  isTyping: true,
                  expiresAt: new Date(Date.now() + 5000)
                },
                update: {
                  isTyping: true,
                  expiresAt: new Date(Date.now() + 5000)
                }
              });
            } else {
              await prisma.chatTypingIndicator.deleteMany({
                where: { 
                  roomId, 
                  userId: user.id 
                }
              });
            }

            broadcastToRoom(roomId, 'user:typing', {
              userId: user.id,
              username: user.username,
              name: user.name,
              avatar: getAvatarUrl(user, 48),
              isTyping
            }, clientId);

          } catch (error) {
            console.error('❌ WS: Typing indicator error:', error);
          }
          break;

        case 'toggle_reaction':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Must join a room first', code: 'NOT_IN_ROOM' }
              }));
              return;
            }

            const { messageId, emoji } = data;

            const existing = await prisma.chatReaction.findUnique({
              where: {
                messageId_userId_emoji: {
                  messageId,
                  userId: user.id,
                  emoji
                }
              }
            });

            let added = false;

            if (existing) {
              await prisma.chatReaction.delete({
                where: { id: existing.id }
              });
              added = false;
            } else {
              await prisma.chatReaction.create({
                data: {
                  messageId,
                  userId: user.id,
                  emoji
                }
              });
              added = true;
            }

            broadcastToRoom(roomId, 'reaction:toggle', {
              messageId,
              userId: user.id,
              emoji,
              added
            });

            console.log('✅ WS: Reaction toggled:', messageId, emoji);

          } catch (error) {
            console.error('❌ WS: Toggle reaction error:', error);
            ws.send(JSON.stringify({
              event: 'error',
              data: { message: 'Failed to toggle reaction', code: 'REACTION_FAILED' }
            }));
          }
          break;

        case 'edit_message':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Must join a room first', code: 'NOT_IN_ROOM' }
              }));
              return;
            }

            const { messageId, content } = data;

            const message = await prisma.chatMessage.findUnique({
              where: { id: messageId }
            });

            if (!message || message.userId !== user.id) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Access denied', code: 'ACCESS_DENIED' }
              }));
              return;
            }

            const { encryptedContent, contentHash } = encryptMessage(content);

            const wordCount = content.trim().split(/\s+/).length;
            const characterCount = content.length;

            await prisma.chatMessage.update({
              where: { id: messageId },
              data: {
                encryptedContent,
                contentHash,
                wordCount,
                characterCount,
                isEdited: true,
                editedAt: new Date()
              }
            });

            const updatedMessage = await prisma.chatMessage.findUnique({
              where: { id: messageId },
              include: {
                user: {
                  select: {
                    id: true,
                    username: true,
                    name: true,
                    img: true,
                    avatars: {
                      orderBy: { createdAt: 'desc' },
                      take: 1,
                      select: {
                        id: true,
                        avatarIndex: true,
                        avatarSeed: true,
                        avatarStyle: true,
                        isPrimary: true,
                        isCustomUpload: true,
                        customImageUrl: true,
                      }
                    }
                  }
                }
              }
            });

            broadcastToRoom(roomId, 'message:edited', {
              messageId,
              content,
              editedAt: new Date().toISOString(),
              user: updatedMessage?.user ? {
                ...updatedMessage.user,
                avatar: getAvatarUrl(updatedMessage.user, 64)
              } : undefined
            });

            console.log('✅ WS: Message edited:', messageId);

          } catch (error) {
            console.error('❌ WS: Edit message error:', error);
            ws.send(JSON.stringify({
              event: 'error',
              data: { message: 'Failed to edit message', code: 'EDIT_FAILED' }
            }));
          }
          break;

        case 'delete_message':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Must join a room first', code: 'NOT_IN_ROOM' }
              }));
              return;
            }

            const { messageId } = data;

            const message = await prisma.chatMessage.findUnique({
              where: { id: messageId }
            });

            if (!message || message.userId !== user.id) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Access denied', code: 'ACCESS_DENIED' }
              }));
              return;
            }

            await prisma.chatMessage.update({
              where: { id: messageId },
              data: {
                isDeleted: true,
                deletedAt: new Date()
              }
            });

            broadcastToRoom(roomId, 'message:deleted', {
              messageId,
              deletedAt: new Date().toISOString()
            });

            console.log('✅ WS: Message deleted:', messageId);

          } catch (error) {
            console.error('❌ WS: Delete message error:', error);
            ws.send(JSON.stringify({
              event: 'error',
              data: { message: 'Failed to delete message', code: 'DELETE_FAILED' }
            }));
          }
          break;

        case 'question:new':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Not in room', code: 'NOT_IN_ROOM' }
              }));
              return;
            }
            
            broadcastToRoom(roomId, 'question:new', {
              question: data.question
            }, clientId);
            
            console.log('✅ WS: Broadcasted new question');
          } catch (error) {
            console.error('❌ WS: Question broadcast error:', error);
            ws.send(JSON.stringify({
              event: 'error',
              data: { message: 'Failed to broadcast question' }
            }));
          }
          break;

        case 'question:upvote':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Not in room', code: 'NOT_IN_ROOM' }
              }));
              return;
            }
            
            broadcastToRoom(roomId, 'question:upvote', {
              questionId: data.questionId,
              userId: data.userId,
              upvoted: data.upvoted,
              upvoteCount: data.upvoteCount,
              hasUpvoted: data.upvoted
            }, clientId);
            
            console.log('✅ WS: Broadcasted upvote');
          } catch (error) {
            console.error('❌ WS: Upvote broadcast error:', error);
          }
          break;

        case 'question:view':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Not in room', code: 'NOT_IN_ROOM' }
              }));
              return;
            }
            broadcastToRoom(roomId, 'question:view', {
              questionId: data.questionId,
              viewCount: data.viewCount
            }, ws.clientId);
          } catch (error) {
            ws.send(JSON.stringify({
              event: 'error',
              data: { message: 'Failed to broadcast view' }
            }));
          }
          break;

        case 'question:answer':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Not in room', code: 'NOT_IN_ROOM' }
              }));
              return;
            }
            
            console.log('📨 Broadcasting answer:', data);
            
            // ✅ Broadcast with ALL data from client
            broadcastToRoom(roomId, 'question:answer', {
              roomId,  // ✅ Add roomId
              questionId: data.questionId,
              answer: data.answer,
              answerCount: data.answerCount,
              status: data.status
            }, clientId);
            
            console.log('✅ WS: Broadcasted answer');
          } catch (error) {
            console.error('❌ WS: Answer broadcast error:', error);
          }
          break;

        case 'answer:thanked':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Not in room', code: 'NOT_IN_ROOM' }
              }));
              return;
            }
            
            console.log('📨 Broadcasting thanks:', data);
            
            // ✅ Broadcast with ALL data
            broadcastToRoom(roomId, 'answer:thanked', {
              roomId,  // ✅ Add roomId
              questionId: data.questionId,
              answerId: data.answerId,
              isThanked: data.isThanked,
              thanksGivenCount: data.thanksGivenCount
            }, clientId);
            
            console.log('✅ WS: Broadcasted thanks badge update');
          } catch (error) {
            console.error('❌ WS: Thanks broadcast error:', error);
          }
          break;

        case 'answer:upvote':
          try {
            if (!roomId) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Not in room', code: 'NOT_IN_ROOM' }
              }));
              return;
            }
            
            console.log('📨 Broadcasting answer upvote:', data);
            
            broadcastToRoom(roomId, 'answer:upvote', {
              roomId,  // ✅ Add roomId
              questionId: data.questionId,
              answerId: data.answerId,
              userId: data.userId,
              upvoted: data.upvoted,
              upvoteCount: data.upvoteCount,
              hasUpvoted: data.hasUpvoted
            }, clientId);
            
            console.log('✅ WS: Broadcasted answer upvote');
          } catch (error) {
            console.error('❌ WS: Answer upvote broadcast error:', error);
          }
          break;

        case 'post:new':
          try {
            if (!user) return;
            
            const followers = await prisma.follow.findMany({
              where: {
                followingId: user.id,
                isAccepted: true
              },
              select: { followerId: true }
            });
            
            followers.forEach(({ followerId }) => {
              const followerConnections = Array.from(connections.values())
                .flatMap(set => Array.from(set))
                .filter(client => client.userId === followerId);
              
              followerConnections.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                  client.send(JSON.stringify({
                    event: 'post:new',
                    data: data.post
                  }));
                }
              });
            });
            
            console.log('✅ WS: Broadcasted new post');
          } catch (error) {
            console.error('❌ WS: Post broadcast error:', error);
          }
          break;

        case 'post:like':
          try {
            broadcastToRoom(roomId, 'post:like', {
              postId: data.postId,
              userId: user.id,
              isLiked: data.isLiked,
              likesCount: data.likesCount
            }, clientId);
          } catch (error) {
            console.error('❌ WS: Like broadcast error:', error);
          }
          break;

        case 'comment:new':
          try {
            broadcastToRoom(roomId, 'comment:new', {
              postId: data.postId,
              comment: data.comment
            }, clientId);
          } catch (error) {
            console.error('❌ WS: Comment broadcast error:', error);
          }
          break;

        case 'follow:new':
          try {
            const targetConnections = Array.from(connections.values())
              .flatMap(set => Array.from(set))
              .filter(client => client.userId === data.targetUserId);
            
            targetConnections.forEach(client => {
              if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                  event: 'follow:new',
                  data: {
                    followerId: user.id,
                    followerUsername: user.username,
                    followerName: user.name,
                    followerImg: getAvatarUrl(user, 64)
                  }
                }));
              }
            });
          } catch (error) {
            console.error('❌ WS: Follow broadcast error:', error);
          }
          break;

        case 'xp:update':
          try {
            ws.send(JSON.stringify({
              event: 'xp:updated',
              data: {
                userId: user.id,
                totalXP: data.totalXP,
                xpEarned: data.xpEarned,
                contributorTitle: data.contributorTitle,
                action: data.action
              }
            }));
          } catch (error) {
            console.error('❌ WS: XP update error:', error);
          }
          break;

        case 'goals:update':
          try {
            if (!user) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Unauthorized', code: 'UNAUTHORIZED' }
              }));
              return;
            }

            const { purpose, monthlyGoal, timeCommitment } = data;

            const goals = await prisma.userGoals.upsert({
              where: { userId: user.id },
              update: {
                purpose,
                monthlyGoal,
                timeCommitment,
                lastUpdated: new Date()
              },
              create: {
                userId: user.id,
                purpose,
                monthlyGoal,
                timeCommitment
              }
            });

            ws.send(JSON.stringify({
              event: 'goals:updated',
              data: { goals }
            }));

            console.log('✅ WS: Goals updated for user:', user.id);
          } catch (error) {
            console.error('❌ WS: Goals update error:', error);
            ws.send(JSON.stringify({
              event: 'error',
              data: { message: 'Failed to update goals', code: 'UPDATE_FAILED' }
            }));
          }
          break;

        case 'preferences:update':
          try {
            if (!user) {
              ws.send(JSON.stringify({
                event: 'error',
                data: { message: 'Unauthorized', code: 'UNAUTHORIZED' }
              }));
              return;
            }

            const preferences = await prisma.userPreferences.upsert({
              where: { userId: user.id },
              update: data,
              create: {
                userId: user.id,
                ...data
              }
            });

            ws.send(JSON.stringify({
              event: 'preferences:updated',
              data: { preferences }
            }));

            console.log('✅ WS: Preferences updated for user:', user.id);
          } catch (error) {
            console.error('❌ WS: Preferences update error:', error);
            ws.send(JSON.stringify({
              event: 'error',
              data: { message: 'Failed to update preferences', code: 'UPDATE_FAILED' }
            }));
          }
          break;

        case 'ping':
          ws.send(JSON.stringify({
            event: 'pong',
            data: { timestamp: new Date().toISOString() }
          }));
          break;

        default:
          console.log('⚠️ WS: Unknown event:', event);
          ws.send(JSON.stringify({
            event: 'error',
            data: { message: 'Unknown event type', code: 'UNKNOWN_EVENT' }
          }));
      }

    } catch (error) {
      console.error('❌ WS: Message handler error:', error);
      ws.send(JSON.stringify({
        event: 'error',
        data: { message: 'Invalid message format', code: 'INVALID_FORMAT' }
      }));
    }
  });

  // Handle disconnection
  ws.on('close', async () => {
    console.log('🔌 WS: Connection closed for user:', user?.id);

    if (roomId && connections.has(roomId)) {
      connections.get(roomId).delete(ws);
      
      if (connections.get(roomId).size === 0) {
        connections.delete(roomId);
      }
    }

    if (participantId) {
      try {
        await prisma.chatParticipant.update({
          where: { id: participantId },
          data: { isOnline: false, lastSeen: new Date() }
        });

        await prisma.chatTypingIndicator.deleteMany({
          where: { 
            roomId, 
            userId: user.id 
          }
        });

        if (roomId) {
          const roomConnections = connections.get(roomId);
          if (roomConnections) {
            const offlineMessage = JSON.stringify({
              event: 'user:offline',
              data: {
                userId: user.id,
                username: user.username,
                timestamp: new Date().toISOString()
              }
            });

            roomConnections.forEach(client => {
              if (client.readyState === WebSocket.OPEN) {
                client.send(offlineMessage);
              }
            });
            
            console.log(`✅ WS: Broadcasted offline status for ${user.username}`);
          }
        }
      } catch (error) {
        console.error('Failed to update offline status:', error);
      }
    }
  });

  ws.on('error', (error) => {
    console.error('❌ WS: Connection error:', error);
  });
});

// Start server
async function startServer() {
  console.log('🚀 Starting WebSocket server...');
  
  const connected = await testPrismaConnection();
  
  if (!connected) {
    console.error('❌ Failed to connect to database. Exiting...');
    process.exit(1);
  }

  server.listen(PORT, () => {
    console.log(`✅ WebSocket server running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // Start keep-alive mechanism
    startKeepAlive();
  });
}

startServer();

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Shutting down WebSocket server...');
  
  // Stop keep-alive first
  stopKeepAlive();
  
  wss.clients.forEach(client => {
    client.close();
  });
  
  await prisma.$disconnect();
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  console.log('🛑 Received SIGINT...');
  stopKeepAlive();
  await prisma.$disconnect();
  process.exit(0);
});