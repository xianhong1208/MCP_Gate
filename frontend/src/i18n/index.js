import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

import en from './locales/en.json'
import zhTW from './locales/zh-TW.json'

// English is the project default. The browser locale is deliberately not consulted: only an explicit
// choice made with the language switcher (persisted in localStorage) changes the UI language.
i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      'zh-TW': { translation: zhTW },
    },
    fallbackLng: 'en',
    supportedLngs: ['en', 'zh-TW'],
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage'],
      lookupLocalStorage: 'language',
      caches: ['localStorage'],
    },
  })

export default i18n
