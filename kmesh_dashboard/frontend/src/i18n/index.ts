import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import zh from './locales/zh'
import en from './locales/en'

const LANG_KEY = 'kmesh_dashboard_lang'

export const defaultLang = 'zh'
export const supportedLangs = ['zh', 'en'] as const
export type Lang = (typeof supportedLangs)[number]

export function getStoredLang(): Lang {
  try {
    const stored = localStorage.getItem(LANG_KEY)
    if (stored && supportedLangs.includes(stored as Lang)) return stored as Lang
  } catch {}
  return defaultLang
}

export function setStoredLang(lang: Lang) {
  try {
    localStorage.setItem(LANG_KEY, lang)
  } catch {}
}

i18n.use(initReactI18next).init({
  resources: { zh: { translation: zh }, en: { translation: en } },
  lng: getStoredLang(),
  fallbackLng: defaultLang,
  interpolation: { escapeValue: false },
})

i18n.on('languageChanged', (lng) => setStoredLang(lng as Lang))

export default i18n
