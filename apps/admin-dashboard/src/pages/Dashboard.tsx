import React from 'react';
import ThreatTable from '../components/ThreatTable';

// ======================================
// GENERAL FRONTEND WORK AREA
// Build the main analytical dashboard
// Fetch summary stats from the backend API
// ======================================

const Dashboard: React.FC = () => {
  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold mb-8 text-gray-800">Cyber Shield Security Center</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* KPI Cards */}
        <div className="bg-white p-6 rounded-lg shadow border-l-4 border-blue-500">
          <h3 className="text-gray-500 text-sm">Total Scans (24h)</h3>
          <p className="text-2xl font-bold">14,203</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow border-l-4 border-red-500">
          <h3 className="text-gray-500 text-sm">Threats Blocked</h3>
          <p className="text-2xl font-bold text-red-600">892</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow border-l-4 border-green-500">
          <h3 className="text-gray-500 text-sm">Active Devices</h3>
          <p className="text-2xl font-bold">5,430</p>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-xl font-bold">Recent Threat Incidents</h2>
        </div>
        <div className="p-0">
          <ThreatTable />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
