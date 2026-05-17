// Minimal i18n scaffolding file. Install `i18next` and `react-i18next` to enable.

export const locales = {
  en: {
    welcome: 'Welcome to H.A.D.A',
  },
  es: {
    welcome: 'Bienvenido a H.A.D.A',
  },
};

export function translate(key: string, lang = 'es') {
  return (locales as any)[lang]?.[key] ?? key;
}
