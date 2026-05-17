import { useState } from 'react';

export default function ImportModal({
  onClose,
  onImport,
}: {
  onClose: () => void;
  onImport: (items: any[] | any[]) => Promise<void>;
}) {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);

  const handleFile = (file?: File) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setText(String(reader.result ?? ''));
    };
    reader.readAsText(file);
  };

  const submit = async () => {
    try {
      setLoading(true);
      const parsed = JSON.parse(text);
      const items = Array.isArray(parsed) ? parsed : [parsed];
      await onImport(items);
      onClose();
    } catch (err) {
      // eslint-disable-next-line no-alert
      alert('Error al parsear JSON');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card max-w-2xl">
        <div className="modal-header">
          <div>
            <p className="modal-kicker">Importar activos</p>
            <h3 className="modal-title">Importación masiva (JSON)</h3>
          </div>
          <div className="modal-actions">
            <button type="button" className="secondary-button" onClick={onClose}>
              Cerrar
            </button>
          </div>
        </div>

        <div className="p-4">
          <p className="mb-2">Pega un array JSON de objetos de activos o sube un archivo .json</p>
          <textarea
            className="w-full h-48 p-2 bg-slate-900 text-sm"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <div className="flex items-center gap-3 mt-3">
            <input
              id="import-file"
              type="file"
              accept="application/json"
              onChange={(e) => handleFile(e.target.files?.[0])}
            />
            <button type="button" className="primary-button" onClick={submit} disabled={loading}>
              {loading ? 'Importando…' : 'Importar'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
