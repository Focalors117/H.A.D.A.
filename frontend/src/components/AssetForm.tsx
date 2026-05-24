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
    <article className="panel panel-form panel-form-compact">
      <div className="panel-header panel-header-compact">
        <div>
          <h2>Registro rápido</h2>
          <p>Agrega manualmente un activo a tu inventario para monitoreo y análisis.</p>
        </div>
      </div>

      <div className="asset-form-summary" aria-label="Resumen del formulario">
        <div className="summary-chip">
          <span>Perfil</span>
          <strong>{form.os}</strong>
        </div>
        <div className="summary-chip">
          <span>IP</span>
          <strong>{form.ip || 'pendiente'}</strong>
        </div>
        <div className="summary-chip">
          <span>Riesgo</span>
          <strong>Nivel {form.criticality}</strong>
        </div>
      </div>

      <form className="asset-form-grid" onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="asset-hostname" className="field-label">
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

        <div className="field">
          <label htmlFor="asset-ip" className="field-label">
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

        <div className="field">
          <label htmlFor="asset-mac" className="field-label">
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

        <div className="field">
          <label htmlFor="asset-os" className="field-label">
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

        <div className="field field-span-2">
          <label htmlFor="asset-criticality" className="field-label">
            Nivel de Criticidad <span className="field-hint">({form.criticality})</span>
          </label>
          <input
            id="asset-criticality"
            type="range"
            min={1}
            max={10}
            value={form.criticality}
            onChange={(e) => setForm((prev) => ({ ...prev, criticality: Number(e.target.value) }))}
            className="range-input"
          />
        </div>

        <div className="field field-span-2">
          <label htmlFor="asset-status" className="field-label">
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

        <div className="asset-form-actions field-span-2">
          <button type="submit" className="primary-button form-submit">
            Añadir al inventario
          </button>
        </div>
      </form>

      <div className="asset-form-footer">
        <span>Tip</span>
        <p>Usa el selector de sistema y el nivel de criticidad para dejar el activo listo en segundos.</p>
      </div>
    </article>
  );
}
