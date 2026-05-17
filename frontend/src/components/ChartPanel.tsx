import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { FC } from 'react';

const ChartPanel: FC<{
  osChartData: Array<{ name: string; value: number; color: string }>;
  statusChartData: Array<{ status: string; count: number; fill: string }>;
}> = ({ osChartData, statusChartData }) => {
  return (
    <article className="panel panel-chart">
      <div className="panel-header">
        <div>
          <h2>Distribución OS / Vendor</h2>
          <p>Uso como mapa rápido de plataformas y fabricantes detectados.</p>
        </div>
      </div>

      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={osChartData}
              dataKey="value"
              innerRadius={62}
              outerRadius={88}
              paddingAngle={4}
            >
              {osChartData.map((entry) => (
                <Cell key={entry.name} fill={entry.color} stroke="none" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(15, 23, 42, 0.92)',
                border: '1px solid rgba(125, 211, 252, 0.2)',
                borderRadius: '12px',
                color: '#f8fafc',
              }}
              itemStyle={{ color: '#f8fafc' }}
              labelStyle={{ color: '#bae6fd' }}
              wrapperStyle={{ outline: 'none' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="panel-divider" />

      <div className="mini-bars">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={statusChartData} barSize={24}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="rgba(148, 163, 184, 0.2)"
              vertical={false}
            />
            <XAxis
              dataKey="status"
              tick={{ fill: '#cbd5e1', fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: '#cbd5e1', fontSize: 12 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(15, 23, 42, 0.92)',
                border: '1px solid rgba(125, 211, 252, 0.2)',
                borderRadius: '12px',
                color: '#f8fafc',
              }}
              cursor={{ fill: 'rgba(96, 165, 250, 0.12)' }}
              itemStyle={{ color: '#f8fafc' }}
              labelStyle={{ color: '#bae6fd' }}
              wrapperStyle={{ outline: 'none' }}
            />
            <Legend />
            <Bar dataKey="count" radius={[12, 12, 0, 0]}>
              {statusChartData.map((entry) => (
                <Cell key={entry.status} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </article>
  );
};

export default ChartPanel;
