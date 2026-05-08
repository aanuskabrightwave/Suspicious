// ======================================
// ANUSKA WORK AREA
// Setup Axios instance with interceptors
// ======================================
import axios from 'axios';
export const api = axios.create({ baseURL: 'http://localhost:5000/api/v1' });