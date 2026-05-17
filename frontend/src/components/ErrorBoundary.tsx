import React from 'react';

type Props = { children: React.ReactNode };

type State = { hasError: boolean; error?: Error };

export default class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(_error: Error, _info: unknown) {
    // Enviar a telemetría si está activada (implementación opcional)
  }

  render() {
    if (this.state.hasError) {
      const message = this.state.error?.message ?? 'Error desconocido';
      const details = String(this.state.error?.stack ?? message);
      return (
        <div className="error-boundary p-6 bg-red-50 rounded">
          <h2 className="text-lg font-semibold mb-2">Se produjo un error inesperado</h2>
          <p className="mb-4">Puedes recargar la página o enviar un informe al equipo.</p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="primary-button"
            >
              Recargar
            </button>
            <button
              type="button"
              onClick={() => navigator.clipboard?.writeText(details)}
              className="secondary-button"
            >
              Copiar detalles
            </button>
            <a
              href={`mailto:devteam@example.com?subject=H.A.D.A%20Error%20Report&body=${encodeURIComponent(
                `Mensaje: ${message}\n\nStack:\n${details}`
              )}`}
              className="secondary-button"
            >
              Enviar informe
            </a>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
