// ADMIN DASHBOARD - Antigravity
// TODO: Implement background heartbeat for socket health monitoring

/**
 * apps/admin-dashboard/src/services/socket.ts
 */
import { io, Socket } from 'socket.io-client';
import { store } from '../redux/store';
import { addAlert } from '../redux/slices/alertSlice';

class SocketService {
  private socket: Socket | null = null;

  connect() {
    const url = process.env.EXPO_PUBLIC_SOCKET_URL || 'http://localhost:3000';
    const token = store.getState().auth.token;

    if (this.socket?.connected) return;

    this.socket = io(url, {
      auth: { token },
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    this.socket.on('connect', () => {
      console.log('Admin connected to Threat Intelligence Stream');
    });

    this.socket.on('alert:new', (data) => {
      store.dispatch(addAlert(data));
      // Show native notification logic here
    });

    this.socket.on('scan:complete', (data) => {
      // Handle real-time scan updates
    });

    this.socket.on('threat:cluster-update', (data) => {
      // Update ThreatMap state
    });

    this.socket.on('disconnect', () => {
      console.log('Socket disconnected');
    });
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  emit(event: string, data: any) {
    this.socket?.emit(event, data);
  }
}

export const socketService = new SocketService();
