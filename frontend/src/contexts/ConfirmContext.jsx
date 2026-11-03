import { createContext, useContext, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import ConfirmDialog from '../components/ConfirmDialog'
import { oauthApi } from '../services/api'
import { formatDateTime } from '../utils/format'
import { revocationNote } from '../utils/revocation'

const ConfirmContext = createContext()

export function useConfirm() {
  const context = useContext(ConfirmContext)
  if (!context) {
    throw new Error('useConfirm must be used within a ConfirmProvider')
  }
  return context
}

export function ConfirmProvider({ children }) {
  const { t } = useTranslation()
  const [state, setState] = useState({
    isOpen: false,
    title: '',
    message: '',
    confirmText: '',
    cancelText: '',
    type: 'danger',
    isLoading: false,
    onConfirm: null,
    onCancel: null,
  })

  const confirm = useCallback(({
    title,
    message,
    confirmText,
    cancelText,
    type = 'danger',
  }) => {
    return new Promise((resolve) => {
      setState({
        isOpen: true,
        title: title || t('confirm.defaultTitle'),
        message,
        confirmText: confirmText || t('confirm.defaultConfirm'),
        cancelText: cancelText || t('confirm.cancel'),
        type,
        isLoading: false,
        onConfirm: () => {
          setState(prev => ({ ...prev, isOpen: false }))
          resolve(true)
        },
        onCancel: () => {
          setState(prev => ({ ...prev, isOpen: false }))
          resolve(false)
        },
      })
    })
  }, [t])

  // itemName is now expected pre-translated by caller (e.g., t('tokens.common.tokenLabel'))
  // If the caller gives none, fall back to "this item" (itemDefault)
  const confirmDelete = useCallback((itemName) => {
    const item = itemName || t('confirm.itemDefault')
    return confirm({
      title: t('confirm.deleteTitle'),
      message: t('confirm.deleteMessage', { item }),
      confirmText: t('confirm.delete'),
      cancelText: t('confirm.cancel'),
      type: 'delete',
    })
  }, [confirm, t])

  const confirmRevoke = useCallback((itemName, note = null) => {
    const item = itemName || t('confirm.tokenDefault')
    const message = t('confirm.revokeMessage', { item })
    return confirm({
      title: t('confirm.revokeTitle'),
      message: note ? `${message}\n\n${note}` : message,
      confirmText: t('confirm.revoke'),
      cancelText: t('confirm.cancel'),
      type: 'revoke',
    })
  }, [confirm, t])

  // Revoking an issued token: the dialog also says whether the token's server hears about it before the token
  // expires (it only does when it polls the revocation feed). A status that cannot be loaded adds nothing.
  const confirmTokenRevoke = useCallback(async (tk) => {
    let status = null
    if (tk.audience && tk.kind !== 'refresh') {
      status = await oauthApi.revocationFeed.forAudience(tk.audience).catch(() => null)
    }
    const label = tk.label ? `"${tk.label}"` : `${tk.kind} ${tk.jti.slice(0, 8)}…`
    return confirmRevoke(label, revocationNote(t, status, tk, (v) => (v ? formatDateTime(v) : '—')))
  }, [confirmRevoke, t])

  // itemType may be an i18n key path passed by the caller (e.g. 'tokens.common.tokenLabel')
  // or an already-translated string (like "Token" or "Service")
  const confirmBatchDelete = useCallback((count, itemTypeLabel) => {
    const label = itemTypeLabel || t('confirm.itemDefault')
    return confirm({
      title: t('confirm.batchDeleteTitle'),
      message: t('confirm.batchDeleteMessage', { count, item: label }),
      confirmText: t('confirm.batchDeleteButton', { count, item: label }),
      cancelText: t('confirm.cancel'),
      type: 'delete',
    })
  }, [confirm, t])

  const confirmDeleteJWT = useCallback(() => {
    return confirm({
      title: t('confirm.deleteJwtTitle'),
      message: t('confirm.deleteJwtMessage'),
      confirmText: t('confirm.deleteJwtButton'),
      cancelText: t('confirm.cancel'),
      type: 'delete',
    })
  }, [confirm, t])

  const handleClose = useCallback(() => {
    if (state.onCancel) {
      state.onCancel()
    }
  }, [state])

  const handleConfirm = useCallback(() => {
    if (state.onConfirm) {
      state.onConfirm()
    }
  }, [state])

  return (
    <ConfirmContext.Provider value={{ confirm, confirmDelete, confirmRevoke, confirmTokenRevoke, confirmBatchDelete, confirmDeleteJWT }}>
      {children}
      <ConfirmDialog
        isOpen={state.isOpen}
        onClose={handleClose}
        onConfirm={handleConfirm}
        title={state.title}
        message={state.message}
        confirmText={state.confirmText}
        cancelText={state.cancelText}
        type={state.type}
        isLoading={state.isLoading}
      />
    </ConfirmContext.Provider>
  )
}
