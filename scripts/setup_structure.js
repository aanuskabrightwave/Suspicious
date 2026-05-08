const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');

const structure = {
  'README.md': '# Cyber Shield App\n\nEnterprise-grade AI-powered Cyber Safety Mobile Application.',
  'turbo.json': '{\n  "$schema": "https://turbo.build/schema.json",\n  "pipeline": {\n    "build": { "dependsOn": ["^build"] }\n  }\n}',
  '.gitignore': 'node_modules/\n.env\ndist/\nbuild/',
  
  // MOBILE APP (Anuska)
  'apps/mobile-app/src/api/axios.ts': `// ======================================\n// ANUSKA WORK AREA\n// Setup Axios instance with interceptors\n// ======================================\nimport axios from 'axios';\nexport const api = axios.create({ baseURL: 'http://localhost:5000/api/v1' });`,
  'apps/mobile-app/src/api/authApi.ts': `// ANUSKA WORK AREA\nexport const loginApi = async () => {};`,
  'apps/mobile-app/src/api/scanApi.ts': `// ANUSKA WORK AREA\nexport const scanApi = async () => {};`,
  'apps/mobile-app/src/api/alertApi.ts': `// ANUSKA WORK AREA\nexport const alertApi = async () => {};`,
  'apps/mobile-app/src/api/dashboardApi.ts': `// ANUSKA WORK AREA\nexport const getDashboardStats = async () => {};`,
  
  'apps/mobile-app/src/components/common/Button.tsx': `// ANUSKA WORK AREA\nimport React from 'react';\nexport const Button = () => <button>Click</button>;`,
  'apps/mobile-app/src/components/common/Input.tsx': `// ANUSKA WORK AREA\nimport React from 'react';\nexport const Input = () => <input />;`,
  'apps/mobile-app/src/components/common/Loader.tsx': `// ANUSKA WORK AREA\nimport React from 'react';\nexport const Loader = () => <div>Loading...</div>;`,
  'apps/mobile-app/src/components/common/EmptyState.tsx': `// ANUSKA WORK AREA\nexport const EmptyState = () => <div>No Data</div>;`,
  'apps/mobile-app/src/components/common/ErrorCard.tsx': `// ANUSKA WORK AREA\nexport const ErrorCard = () => <div>Error</div>;`,
  
  'apps/mobile-app/src/components/cards/ThreatCard.tsx': `// ANUSKA WORK AREA\nexport const ThreatCard = () => <div>Threat</div>;`,
  'apps/mobile-app/src/components/cards/RiskScoreCard.tsx': `// ANUSKA WORK AREA\nexport const RiskScoreCard = () => <div>Risk Score</div>;`,
  'apps/mobile-app/src/components/cards/ScanCard.tsx': `// ANUSKA WORK AREA\nexport const ScanCard = () => <div>Scan Card</div>;`,
  'apps/mobile-app/src/components/cards/AlertCard.tsx': `// ANUSKA WORK AREA\nexport const AlertCard = () => <div>Alert Card</div>;`,
  
  'apps/mobile-app/src/components/modals/ScanResultModal.tsx': `// ANUSKA WORK AREA\nexport const ScanResultModal = () => <div>Result</div>;`,
  'apps/mobile-app/src/components/modals/AlertModal.tsx': `// ANUSKA WORK AREA\nexport const AlertModal = () => <div>Alert</div>;`,
  
  'apps/mobile-app/src/components/scanner/QRScanner.tsx': `// ANUSKA WORK AREA\nexport const QRScanner = () => <div>QR Scanner</div>;`,
  'apps/mobile-app/src/components/scanner/URLScanner.tsx': `// ANUSKA WORK AREA\nexport const URLScanner = () => <div>URL Scanner</div>;`,
  'apps/mobile-app/src/components/scanner/APKScanner.tsx': `// ANUSKA WORK AREA\nexport const APKScanner = () => <div>APK Scanner</div>;`,
  
  'apps/mobile-app/src/components/layout/Header.tsx': `// ANUSKA WORK AREA\nexport const Header = () => <header>Header</header>;`,
  'apps/mobile-app/src/components/layout/Footer.tsx': `// ANUSKA WORK AREA\nexport const Footer = () => <footer>Footer</footer>;`,
  'apps/mobile-app/src/components/layout/ScreenWrapper.tsx': `// ANUSKA WORK AREA\nexport const ScreenWrapper = ({children}: any) => <div>{children}</div>;`,

  'apps/mobile-app/src/config/env.ts': `export const ENV = { API_URL: 'localhost:5000' };`,
  'apps/mobile-app/src/config/firebase.ts': `// Firebase config stub`,
  'apps/mobile-app/src/config/appConfig.ts': `// App config stub`,

  'apps/mobile-app/src/constants/colors.ts': `export const colors = { primary: '#000' };`,
  'apps/mobile-app/src/constants/fonts.ts': `export const fonts = {};`,
  'apps/mobile-app/src/constants/routes.ts': `export const routes = {};`,
  'apps/mobile-app/src/constants/permissions.ts': `export const permissions = {};`,
  'apps/mobile-app/src/constants/riskLevels.ts': `export const riskLevels = {};`,

  'apps/mobile-app/src/hooks/useAuth.ts': `// ANUSKA WORK AREA\nexport const useAuth = () => {};`,
  'apps/mobile-app/src/hooks/useScanner.ts': `// ANUSKA WORK AREA\nexport const useScanner = () => {};`,
  'apps/mobile-app/src/hooks/usePermissions.ts': `// ANUSKA WORK AREA\nexport const usePermissions = () => {};`,
  'apps/mobile-app/src/hooks/useNotifications.ts': `// ANUSKA WORK AREA\nexport const useNotifications = () => {};`,

  'apps/mobile-app/src/navigation/RootNavigator.tsx': `// ANUSKA WORK AREA\nexport const RootNavigator = () => null;`,
  'apps/mobile-app/src/navigation/AuthNavigator.tsx': `// ANUSKA WORK AREA\nexport const AuthNavigator = () => null;`,
  'apps/mobile-app/src/navigation/MainNavigator.tsx': `// ANUSKA WORK AREA\nexport const MainNavigator = () => null;`,
  'apps/mobile-app/src/navigation/types.ts': `export type NavParams = {};`,

  'apps/mobile-app/src/redux/store.ts': `// ANUSKA WORK AREA\nimport { configureStore } from '@reduxjs/toolkit';\nexport const store = configureStore({ reducer: {} });`,
  'apps/mobile-app/src/redux/slices/authSlice.ts': `// ANUSKA WORK AREA\nexport const authSlice = {};`,
  'apps/mobile-app/src/redux/slices/scanSlice.ts': `// ANUSKA WORK AREA\nexport const scanSlice = {};`,
  'apps/mobile-app/src/redux/slices/alertSlice.ts': `// ANUSKA WORK AREA\nexport const alertSlice = {};`,
  'apps/mobile-app/src/redux/slices/dashboardSlice.ts': `// ANUSKA WORK AREA\nexport const dashboardSlice = {};`,
  'apps/mobile-app/src/redux/middleware/loggerMiddleware.ts': `// ANUSKA WORK AREA\nexport const logger = {};`,

  'apps/mobile-app/src/screens/auth/SplashScreen.tsx': `// ANUSKA WORK AREA\nexport const SplashScreen = () => null;`,
  'apps/mobile-app/src/screens/auth/LoginScreen.tsx': `// ANUSKA WORK AREA\nexport const LoginScreen = () => null;`,
  'apps/mobile-app/src/screens/auth/SignupScreen.tsx': `// ANUSKA WORK AREA\nexport const SignupScreen = () => null;`,
  'apps/mobile-app/src/screens/auth/OtpScreen.tsx': `// ANUSKA WORK AREA\nexport const OtpScreen = () => null;`,
  'apps/mobile-app/src/screens/auth/ForgotPassword.tsx': `// ANUSKA WORK AREA\nexport const ForgotPassword = () => null;`,

  'apps/mobile-app/src/screens/dashboard/DashboardScreen.tsx': `// ANUSKA WORK AREA\nexport const DashboardScreen = () => null;`,
  'apps/mobile-app/src/screens/dashboard/SecurityScore.tsx': `// ANUSKA WORK AREA\nexport const SecurityScore = () => null;`,
  'apps/mobile-app/src/screens/dashboard/RecentThreats.tsx': `// ANUSKA WORK AREA\nexport const RecentThreats = () => null;`,
  'apps/mobile-app/src/screens/dashboard/ScanHistory.tsx': `// ANUSKA WORK AREA\nexport const ScanHistory = () => null;`,

  'apps/mobile-app/src/screens/scanner/LinkScannerScreen.tsx': `// ANUSKA WORK AREA\nexport const LinkScannerScreen = () => null;`,
  'apps/mobile-app/src/screens/scanner/QRScannerScreen.tsx': `// ANUSKA WORK AREA\nexport const QRScannerScreen = () => null;`,
  'apps/mobile-app/src/screens/scanner/APKScannerScreen.tsx': `// ANUSKA WORK AREA\nexport const APKScannerScreen = () => null;`,
  'apps/mobile-app/src/screens/scanner/ScanResultScreen.tsx': `// ANUSKA WORK AREA\nexport const ScanResultScreen = () => null;`,

  'apps/mobile-app/src/screens/alerts/AlertsScreen.tsx': `// ANUSKA WORK AREA\nexport const AlertsScreen = () => null;`,
  'apps/mobile-app/src/screens/alerts/EmergencyAlerts.tsx': `// ANUSKA WORK AREA\nexport const EmergencyAlerts = () => null;`,

  'apps/mobile-app/src/screens/settings/SettingsScreen.tsx': `// ANUSKA WORK AREA\nexport const SettingsScreen = () => null;`,
  'apps/mobile-app/src/screens/settings/PermissionsScreen.tsx': `// ANUSKA WORK AREA\nexport const PermissionsScreen = () => null;`,
  'apps/mobile-app/src/screens/settings/PrivacyScreen.tsx': `// ANUSKA WORK AREA\nexport const PrivacyScreen = () => null;`,

  'apps/mobile-app/src/screens/education/ScamAwareness.tsx': `// ANUSKA WORK AREA\nexport const ScamAwareness = () => null;`,
  'apps/mobile-app/src/screens/education/BankingFraud.tsx': `// ANUSKA WORK AREA\nexport const BankingFraud = () => null;`,
  'apps/mobile-app/src/screens/education/CyberTips.tsx': `// ANUSKA WORK AREA\nexport const CyberTips = () => null;`,

  'apps/mobile-app/src/services/secureStorage.ts': `// ANUSKA WORK AREA\nexport const storage = {};`,
  'apps/mobile-app/src/services/notificationService.ts': `// ANUSKA WORK AREA\nexport const notify = {};`,
  'apps/mobile-app/src/services/scannerService.ts': `// ANUSKA WORK AREA\nexport const scanSvc = {};`,
  'apps/mobile-app/src/services/cameraService.ts': `// ANUSKA WORK AREA\nexport const cameraSvc = {};`,
  'apps/mobile-app/src/services/analyticsService.ts': `// ANUSKA WORK AREA\nexport const analyticsSvc = {};`,

  'apps/mobile-app/src/theme/colors.ts': `export const colors = {};`,
  'apps/mobile-app/src/theme/typography.ts': `export const typo = {};`,
  'apps/mobile-app/src/theme/spacing.ts': `export const space = {};`,
  'apps/mobile-app/src/theme/index.ts': `export const theme = {};`,

  'apps/mobile-app/src/types/auth.ts': `export type Auth = {};`,
  'apps/mobile-app/src/types/scan.ts': `export type Scan = {};`,
  'apps/mobile-app/src/types/alert.ts': `export type Alert = {};`,
  'apps/mobile-app/src/types/user.ts': `export type User = {};`,

  'apps/mobile-app/src/utils/validators.ts': `export const validate = {};`,
  'apps/mobile-app/src/utils/formatters.ts': `export const format = {};`,
  'apps/mobile-app/src/utils/helpers.ts': `export const help = {};`,
  'apps/mobile-app/src/utils/permissions.ts': `export const perms = {};`,

  // BACKEND API (Shivam)
  'apps/backend-api/prisma/migrations/.keep': '',
  'apps/backend-api/prisma/seed.ts': `// SHIVAM WORK AREA\n// Prisma seed script`,
  
  'apps/backend-api/src/config/database.ts': `// SHIVAM WORK AREA\nexport const dbConfig = {};`,
  'apps/backend-api/src/config/redis.ts': `// SHIVAM WORK AREA\nexport const redisConfig = {};`,
  'apps/backend-api/src/config/env.ts': `export const envConfig = {};`,
  'apps/backend-api/src/config/firebase.ts': `export const firebaseConfig = {};`,

  'apps/backend-api/src/controllers/authController.ts': `// SHIVAM WORK AREA\nexport const login = () => {};`,
  'apps/backend-api/src/controllers/scanController.ts': `// SHIVAM WORK AREA\nexport const scanUrl = () => {};`,
  'apps/backend-api/src/controllers/alertController.ts': `// SHIVAM WORK AREA\nexport const getAlerts = () => {};`,
  'apps/backend-api/src/controllers/dashboardController.ts': `// SHIVAM WORK AREA\nexport const getStats = () => {};`,

  'apps/backend-api/src/middleware/authMiddleware.ts': `// SHIVAM WORK AREA\nexport const protect = () => {};`,
  'apps/backend-api/src/middleware/errorMiddleware.ts': `// SHIVAM WORK AREA\nexport const errorHandler = () => {};`,
  'apps/backend-api/src/middleware/rateLimiter.ts': `// SHIVAM WORK AREA\nexport const rateLimit = () => {};`,
  'apps/backend-api/src/middleware/loggerMiddleware.ts': `// SHIVAM WORK AREA\nexport const logger = () => {};`,
  'apps/backend-api/src/middleware/validationMiddleware.ts': `// SHIVAM WORK AREA\nexport const validate = () => {};`,

  'apps/backend-api/src/routes/authRoutes.ts': `// SHIVAM WORK AREA\nimport { Router } from 'express';\nexport const router = Router();`,
  'apps/backend-api/src/routes/scanRoutes.ts': `// SHIVAM WORK AREA\nimport { Router } from 'express';\nexport const router = Router();`,
  'apps/backend-api/src/routes/alertRoutes.ts': `// SHIVAM WORK AREA\nimport { Router } from 'express';\nexport const router = Router();`,
  'apps/backend-api/src/routes/dashboardRoutes.ts': `// SHIVAM WORK AREA\nimport { Router } from 'express';\nexport const router = Router();`,

  'apps/backend-api/src/services/authService.ts': `// SHIVAM WORK AREA\nexport const authService = {};`,
  'apps/backend-api/src/services/scanService.ts': `// SHIVAM WORK AREA\nexport const scanService = {};`,
  'apps/backend-api/src/services/aiService.ts': `// SHIVAM WORK AREA\nexport const aiService = {};`,
  'apps/backend-api/src/services/alertService.ts': `// SHIVAM WORK AREA\nexport const alertService = {};`,
  'apps/backend-api/src/services/notificationService.ts': `// SHIVAM WORK AREA\nexport const notificationService = {};`,

  'apps/backend-api/src/repositories/userRepository.ts': `// SHIVAM WORK AREA\nexport const userRepo = {};`,
  'apps/backend-api/src/repositories/scanRepository.ts': `// SHIVAM WORK AREA\nexport const scanRepo = {};`,
  'apps/backend-api/src/repositories/alertRepository.ts': `// SHIVAM WORK AREA\nexport const alertRepo = {};`,

  'apps/backend-api/src/validators/authValidator.ts': `// SHIVAM WORK AREA\nexport const authValid = {};`,
  'apps/backend-api/src/validators/scanValidator.ts': `// SHIVAM WORK AREA\nexport const scanValid = {};`,
  'apps/backend-api/src/validators/alertValidator.ts': `// SHIVAM WORK AREA\nexport const alertValid = {};`,

  'apps/backend-api/src/sockets/socketServer.ts': `// SHIVAM WORK AREA\nexport const initSockets = () => {};`,

  'apps/backend-api/src/queues/scanQueue.ts': `// SHIVAM WORK AREA\nexport const scanQueue = {};`,
  'apps/backend-api/src/queues/notificationQueue.ts': `// SHIVAM WORK AREA\nexport const notificationQueue = {};`,

  'apps/backend-api/src/jobs/cleanupJob.ts': `// SHIVAM WORK AREA\nexport const cleanup = () => {};`,
  'apps/backend-api/src/jobs/alertJob.ts': `// SHIVAM WORK AREA\nexport const runAlerts = () => {};`,

  'apps/backend-api/src/utils/logger.ts': `// SHIVAM WORK AREA\nexport const logger = {};`,
  'apps/backend-api/src/utils/jwt.ts': `// SHIVAM WORK AREA\nexport const jwtUtils = {};`,
  'apps/backend-api/src/utils/response.ts': `// SHIVAM WORK AREA\nexport const responseUtils = {};`,
  'apps/backend-api/src/utils/helpers.ts': `export const helpers = {};`,

  'apps/backend-api/src/types/auth.ts': `export type AuthType = {};`,
  'apps/backend-api/src/types/scan.ts': `export type ScanType = {};`,
  'apps/backend-api/src/types/alert.ts': `export type AlertType = {};`,

  'apps/backend-api/src/app.ts': `// SHIVAM WORK AREA\nimport express from 'express';\nconst app = express();\nexport default app;`,

  // AI ENGINE (Ayush)
  'apps/ai-engine/app/api/routes/url_scan.py': `# AYUSH WORK AREA\nfrom fastapi import APIRouter\nrouter = APIRouter()`,
  'apps/ai-engine/app/api/routes/qr_scan.py': `# AYUSH WORK AREA\nfrom fastapi import APIRouter\nrouter = APIRouter()`,
  'apps/ai-engine/app/api/routes/apk_scan.py': `# AYUSH WORK AREA\nfrom fastapi import APIRouter\nrouter = APIRouter()`,
  'apps/ai-engine/app/api/routes/ocr_scan.py': `# AYUSH WORK AREA\nfrom fastapi import APIRouter\nrouter = APIRouter()`,

  'apps/ai-engine/app/scanners/url_scanner.py': `# AYUSH WORK AREA\ndef scan_url(): pass`,
  'apps/ai-engine/app/scanners/qr_scanner.py': `# AYUSH WORK AREA\ndef scan_qr(): pass`,
  'apps/ai-engine/app/scanners/apk_scanner.py': `# AYUSH WORK AREA\ndef scan_apk(): pass`,
  'apps/ai-engine/app/scanners/media_scanner.py': `# AYUSH WORK AREA\ndef scan_media(): pass`,

  'apps/ai-engine/app/classifiers/phishing_classifier.py': `# AYUSH WORK AREA\ndef classify_phishing(): pass`,
  'apps/ai-engine/app/classifiers/scam_classifier.py': `# AYUSH WORK AREA\ndef classify_scam(): pass`,
  'apps/ai-engine/app/classifiers/fraud_classifier.py': `# AYUSH WORK AREA\ndef classify_fraud(): pass`,
  'apps/ai-engine/app/classifiers/risk_classifier.py': `# AYUSH WORK AREA\ndef classify_risk(): pass`,

  'apps/ai-engine/app/heuristics/domain_checks.py': `# AYUSH WORK AREA\ndef check_domain(): pass`,
  'apps/ai-engine/app/heuristics/ssl_checks.py': `# AYUSH WORK AREA\ndef check_ssl(): pass`,
  'apps/ai-engine/app/heuristics/redirect_checks.py': `# AYUSH WORK AREA\ndef check_redirect(): pass`,
  'apps/ai-engine/app/heuristics/keyword_checks.py': `# AYUSH WORK AREA\ndef check_keyword(): pass`,

  'apps/ai-engine/app/ocr/image_text.py': `# AYUSH WORK AREA\ndef extract_text(): pass`,
  'apps/ai-engine/app/ocr/scam_text_detector.py': `# AYUSH WORK AREA\ndef detect_scam(): pass`,
  'apps/ai-engine/app/ocr/text_cleaner.py': `# AYUSH WORK AREA\ndef clean_text(): pass`,

  'apps/ai-engine/app/models/phishing_model.pkl': ``,
  'apps/ai-engine/app/models/risk_model.pkl': ``,
  'apps/ai-engine/app/models/scam_model.pkl': ``,

  'apps/ai-engine/app/services/scoring_service.py': `# AYUSH WORK AREA\ndef get_score(): pass`,
  'apps/ai-engine/app/services/threat_service.py': `# AYUSH WORK AREA\ndef get_threat(): pass`,
  'apps/ai-engine/app/services/ai_pipeline.py': `# AYUSH WORK AREA\ndef run_pipeline(): pass`,

  'apps/ai-engine/app/utils/logger.py': `# AYUSH WORK AREA\nimport logging`,
  'apps/ai-engine/app/utils/helpers.py': `def help(): pass`,
  'apps/ai-engine/app/utils/constants.py': `CONST = 1`,

  // ADMIN DASHBOARD
  'apps/admin-dashboard/src/layouts/MainLayout.tsx': `// GENERAL FRONTEND\nexport const MainLayout = () => null;`,
  'apps/admin-dashboard/src/routes/AppRoutes.tsx': `// GENERAL FRONTEND\nexport const AppRoutes = () => null;`,
  'apps/admin-dashboard/src/charts/ThreatChart.tsx': `// GENERAL FRONTEND\nexport const ThreatChart = () => null;`,

  // PACKAGES
  'packages/shared-types/auth.ts': `export interface AuthUser { id: string; }`,
  'packages/shared-types/scan.ts': `export interface ScanResult { risk: string; }`,
  'packages/shared-types/alert.ts': `export interface AlertMsg { title: string; }`,
  
  'packages/shared-utils/validators.ts': `export const isEmail = () => true;`,
  'packages/shared-utils/formatters.ts': `export const formatDate = () => '';`,
  'packages/shared-utils/helpers.ts': `export const capitalize = () => '';`,

  'packages/ui-kit/buttons/PrimaryButton.tsx': `export const PrimaryButton = () => null;`,
  'packages/ui-kit/cards/StatCard.tsx': `export const StatCard = () => null;`,
  'packages/ui-kit/modals/ConfirmModal.tsx': `export const ConfirmModal = () => null;`,

  // INFRASTRUCTURE
  'infrastructure/docker/mobile.Dockerfile': `# Dockerfile for Mobile CI`,
  'infrastructure/docker/backend.Dockerfile': `# Dockerfile for Backend API\nFROM node:20`,
  'infrastructure/docker/ai-engine.Dockerfile': `# Dockerfile for AI Engine\nFROM python:3.11`,

  'infrastructure/kubernetes/backend-deployment.yml': `apiVersion: apps/v1\nkind: Deployment`,
  'infrastructure/kubernetes/ai-deployment.yml': `apiVersion: apps/v1\nkind: Deployment`,
  'infrastructure/kubernetes/redis-deployment.yml': `apiVersion: apps/v1\nkind: Deployment`,

  'infrastructure/terraform/main.tf': `# Terraform Main`,
  'infrastructure/terraform/variables.tf': `# Terraform Variables`,
  'infrastructure/terraform/outputs.tf': `# Terraform Outputs`,

  // SCRIPTS & DOCS
  'docs/api-docs/openapi.yaml': `openapi: 3.0.0\ninfo:\n  title: Cyber Shield API\n  version: 1.0.0`,
  'docs/architecture/system-design.md': `# System Design`,
  'docs/database/schema.md': `# Database Schema`,
  'docs/deployment/guide.md': `# Deployment Guide`,

  'scripts/setup.sh': `#!/bin/bash\necho "Setting up..."`,
  'scripts/deploy.sh': `#!/bin/bash\necho "Deploying..."`,
  'scripts/backup.sh': `#!/bin/bash\necho "Backing up..."`
};

// Create files
for (const [filePath, content] of Object.entries(structure)) {
  const fullPath = path.join(root, filePath);
  const dir = path.dirname(fullPath);
  
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  // Only write if file doesn't exist to not overwrite previous work completely,
  // or overwrite with boilerplate if required. 
  // Since user asked to "build it with the refrence code", we overwrite or create.
  fs.writeFileSync(fullPath, content);
}

console.log("Structure generated successfully!");
