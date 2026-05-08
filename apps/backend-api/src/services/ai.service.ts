import axios from 'axios';

// ======================================
// SHIVAM WORK AREA
// Communication layer with the AI Engine (Python)
// Can be replaced with Redis Pub/Sub or Celery tasks for heavy files like APKs
// ======================================

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || 'http://localhost:8000';

export const aiService = {
  analyzeUrl: async (url: string) => {
    try {
      const response = await axios.post(`${AI_ENGINE_URL}/api/v1/scan/url`, { url });
      return response.data;
    } catch (error) {
      console.error('Failed to communicate with AI Engine:', error);
      throw new Error('AI Engine is unreachable');
    }
  },
  
  // TODO: Add analyzeApk, analyzeQr methods
};
