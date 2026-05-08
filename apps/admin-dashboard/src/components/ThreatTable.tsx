import React from 'react';

// ======================================
// GENERAL FRONTEND WORK AREA
// Connect this table to the backend API (`/api/v1/threats`)
// Add pagination, sorting, and filtering
// ======================================

const ThreatTable: React.FC = () => {
  // Mock data
  const threats = [
    { id: 'TR-1029', user: 'user_123', type: 'PHISHING', level: 'CRITICAL', date: '2026-05-08 14:30', target: 'http://fake-bank.com' },
    { id: 'TR-1028', user: 'user_456', type: 'MALWARE_APK', level: 'HIGH', date: '2026-05-08 13:15', target: 'whatsapp-mod.apk' },
  ];

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Target</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {threats.map((threat) => (
            <tr key={threat.id}>
              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{threat.id}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{threat.type}</td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${threat.level === 'CRITICAL' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}`}>
                  {threat.level}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{threat.target}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{threat.date}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ThreatTable;
