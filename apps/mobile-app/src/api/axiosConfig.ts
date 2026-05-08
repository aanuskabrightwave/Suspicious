import axios from 'axios';
// import AsyncStorage from '@react-native-async-storage/async-storage';

// ======================================
// ANUSKA WORK AREA
// Connect APIs here
// Setup base URL from environment variables
// Implement token refresh logic in interceptors
// ======================================

const api = axios.create({
  baseURL: 'http://localhost:5000/api/v1', // TODO: Use env config
  timeout: 10000,
});

api.interceptors.request.use(
  async (config) => {
    // const token = await AsyncStorage.getItem('token');
    // if (token) {
    //   config.headers.Authorization = `Bearer ${token}`;
    // }
    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // TODO: Handle 401 Unauthorized globally (logout user)
    return Promise.reject(error);
  }
);

export default api;
