import { Server, Socket } from 'socket.io';
import http from 'http';
import { Redis } from 'ioredis';

let io: Server;

const redis = new Redis(process.env.REDIS_URL!); // Ensure REDIS_URL is set

export const setupSocket = (httpServer: http.Server): void => {
  io = new Server(httpServer, {
    cors: {
      origin: process.env.NODE_ENV === 'production' ? 'https://your-mobile-app-domain.com' : '*',
      methods: ['GET', 'POST'],
      credentials: true,
    },
  });

  io.use(async (socket, next) => {
    // Optional: Attach user info to socket based on token if needed later
    // For now, just allow connection after authentication elsewhere
    next();
  });

  io.on('connection', (socket: Socket) => {
    console.log('A client connected:', socket.id);

    socket.on('disconnect', () => {
      console.log('Client disconnected:', socket.id);
    });

    // Listen for scan completion events from the queue processor
    redis.subscribe('scan_completed');
    redis.on('message', (channel, messageStr) => {
      if (channel === 'scan_completed') {
        try {
          const scanResult: Scan = JSON.parse(messageStr);
          // Emit to the specific user who initiated the scan
          // In a real scenario, you might store the socket ID against the scan ID
          // or broadcast to a room associated with the user.
          // Here, we'll broadcast to all connected sockets for that user.
          // A better approach might be to join sockets into rooms based on user ID.
          io.to(scanResult.userId).emit('scanCompleted', scanResult);
          console.log(`Emitted scanCompleted event for scan ${scanResult.id} to user ${scanResult.userId}`);
        } catch (error) {
          console.error('Error parsing scan result from Redis:', error);
        }
      }
    });
  });
};

// Function to emit events from services (e.g., when a scan completes)
export const emitScanCompletion = (userId: string, scanResult: Scan): void => {
  if (io) {
    io.to(userId).emit('scanCompleted', scanResult);
  }
  // Also publish to Redis so other instances can pick it up if scaled
  redis.publish('scan_completed', JSON.stringify(scanResult));
};