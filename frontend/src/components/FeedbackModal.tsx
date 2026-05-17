import { useState } from 'react';

export default function FeedbackModal({ onClose }: { onClose: () => void }) {
  const [message, setMessage] = useState('');
  const [email, setEmail] = useState('');

  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <div>
            <p className="modal-kicker">Enviar feedback</p>
            <h3 className="modal-title">Queremos saber tu opinión</h3>
          </div>
          <div className="modal-actions">
            <button type="button" className="secondary-button small" onClick={onClose}>
              Cerrar
            </button>
          </div>
        </div>

        <div className="modal-grid">
          <label className="block">
            <span className="label">Correo (opcional)</span>
            <input value={email} onChange={(e) => setEmail(e.target.value)} className="input mt-1" />
          </label>
          <label className="block mt-2">
            <span className="label">Mensaje</span>
            <textarea value={message} onChange={(e) => setMessage(e.target.value)} className="textarea mt-1" />
          </label>
        </div>

        <div className="modal-actions mt-4">
          <button
            type="button"
            className="primary-button"
            onClick={async () => {
              try {
                await fetch('/api/feedback', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ email, message }),
                });
                alert('Gracias por tu feedback');
                onClose();
              } catch (e) {
                alert('Error al enviar feedback');
              }
            }}
          >
            Enviar
          </button>
        </div>
      </div>
    </div>
  );
}
