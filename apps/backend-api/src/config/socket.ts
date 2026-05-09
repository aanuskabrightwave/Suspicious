// SHIVAM WORK AREA
/**
 * apps/backend-api/src/config/socket.ts
 */
import { Server } from 'socket.io';
import { Server as HttpServer } from 'http';
import { logger } from '../utils/logger';

let io: Server;

export const initializeSocket = (server: HttpServer) => {
  io = new Server(server, {
    cors: {
      origin: process.env.MOBILE_APP_ORIGIN || '*',
      methods: ['GET', 'POST'],
    },
  });

  io.on('connection', (socket) => {
    logger.info('Client connected to Socket.IO', { socketId: socket.id });

    socket.on('join', (userId: string) => {
      socket.join(`user:${userId}`);
      logger.info('Socket joined user room', { userId, socketId: socket.id });
    });

    socket.on('disconnect', () => {
      logger.info('Client disconnected from Socket.IO', { socketId: socket.id });
    });
  });

  return io;
};

export const getIO = () => {
  if (!io) throw new Error('Socket.IO not initialized');
  return io;
};
