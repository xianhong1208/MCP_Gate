import { useEffect, useRef } from 'react'

/**
 * Runs fn every intervalMs while the tab is visible; runs once immediately when the user returns to the tab.
 * enabled=false disables it entirely (no timer is held).
 *
 * Why check visibilityState: a background tab hammering the API only wastes server time and battery,
 * and the user may still see stale data on return -- "refresh on return" is what they actually want.
 */
export default function useVisiblePolling(fn, intervalMs, enabled = true) {
  const fnRef = useRef(fn)
  fnRef.current = fn

  useEffect(() => {
    if (!enabled || !intervalMs) return
    const run = () => {
      if (document.visibilityState === 'visible') fnRef.current()
    }
    const id = setInterval(run, intervalMs)
    document.addEventListener('visibilitychange', run)
    return () => {
      clearInterval(id)
      document.removeEventListener('visibilitychange', run)
    }
  }, [intervalMs, enabled])
}
