import { useState, type FormEvent } from 'react';
import type { Asset } from '../types';

export type AssetFormState = {
  hostname: string;
  ip: string;
  mac: string;
  os: string;
  criticality: number;
  status: Asset['status'];
};

interface AssetFormProps {
  onSubmit: (data: AssetFormState) => void;
}

export default function AssetForm({ onSubmit }: AssetFormProps) {
  const [form, setForm] = useState<AssetFormState>({
    hostname: '',
    ip: '',
    mac: '',
    os: 'Desconocido',
    criticality: 5,
    status: 'Active',
  });

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    onSubmit(form);
    setForm({
      hostname: '',
      ip: '',
      mac: '',
      os: 'Desconocido',
      criticality: 5,
      status: 'Active',
    });
  };

  return (
    <article className="panel panel-form">
      <div className="panel-header pb-4">
        <h2>Registrar Activo Manualmente</h2>
        <p className="m-0 text-sm text-slate-400">
          Registra detalles de un dispositivo estático en la red actual.
        </p>
      </div>

      <form className="space-y-4" onSubmit={handleSubmit}>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-1">
            <label htmlFor="asset-hostname" className="text-sm font-medium text-slate-300">
              Hostname
            </label>
            <input
              id="asset-hostname"
              type="text"
              value={form.hostname}
              onChange={(e) => setForm((prev) => ({ ...prev, hostname: e.target.value }))}
              className="field-input"
              placeholder="Ej. Servidor-BD"
              required
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="asset-ip" className="text-sm font-medium text-slate-300">
              Dirección IP
            </label>
            <input
              id="asset-ip"
              type="text"
              value={form.ip}
              onChange={(e) => setForm((prev) => ({ ...prev, ip: e.target.value }))}
              className="field-input"
              placeholder="Ej. 192.168.1.50"
              required
            />
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-1">
            <label htmlFor="asset-mac" className="text-sm font-medium text-slate-300">
              Dirección MAC
            </label>
            <input
              id="asset-mac"
              type="text"
              value={form.mac}
              onChange={(e) => setForm((prev) => ({ ...prev, mac: e.target.value }))}
              className="field-input"
              placeholder="Opcional. Ej. AA:BB:CC:DD:EE:FF"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="asset-os" className="text-sm font-medium text-slate-300">
              Tipo de Sistema / OS
            </label>
            <select
              id="asset-os"
              value={form.os}
              onChange={(e) => setForm((prev) => ({ ...prev, os: e.target.value }))}
              className="field-input"
            >
              <option value="Desconocido">Desconocido</option>
              <option value="Windows">Windows</option>
              <option value="Linux / Unix">Linux / Unix</option>
              <option value="Android">Android</option>
              <option value="iOS / Apple">iOS / Apple</option>
              <option value="Network Device (Router/Switch)">
                Dispositivo de Red (Router/Switch)
              </option>
              <option value="IoT / Camera">Dispositivo IoT</option>
            </select>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-1">
            <label htmlFor="asset-criticality" className="text-sm font-medium text-slate-300">
              Nivel de Criticidad ({form.criticality})
            </label>
            <input
              id="asset-criticality"
              type="range"
              min={1}
              max={10}
              value={form.criticality}
              onChange={(e) =>
                setForm((prev) => ({ ...prev, criticality: Number(e.target.value) }))
              }
              className="range-input"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="asset-status" className="text-sm font-medium text-slate-300">
              Estado
            </label>
            <select
              id="asset-status"
              value={form.status}
              onChange={(e) =>
                setForm((prev) => ({ ...prev, status: e.target.value as typeof form.status }))
              }
              className="field-input"
            >
              <option value="Active">Operativo / Activo</option>
              <option value="Down">Caído / Fuera de línea</option>
              <option value="Compromised">Comprometido / Riesgo</option>
            </select>
          </div>
        </div>

        <button type="submit" className="button">
          Añadir Activo al Inventario
        </button>
      </form>
    </article>
  );
}
