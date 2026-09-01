import { useEffect, useRef, useCallback, useState } from 'react'

/**
 * WebSocket hook for real-time service updates (/ws/services, authenticated via the session cookie)
 *
 * Handles:
 *   health_update / service_added / service_removed / service_updated / pong
 *
 * Reconnect strategy:
 *   - close code 1000 (normal): no reconnect -- the user closed it
 *   - close code 4001 / 4003 (auth failure): session expired -> emit 'auth-expired' and let AuthContext handle it
 *   - others (1006 abnormal / 1011 internal): exponential backoff, capped at 30s and 5 attempts
 *
 * Cleanup hygiene:
 *   - close and null any old ws before connect() to avoid piling up zombie connections
 *   - the reconnect timeout is cleared on disconnect / re-effect
 *   - isMountedRef prevents setState after unmount
 */
export function useServiceWebSocket({ onHealthUpdate, onServiceAdded, onServiceRemoved, onServiceUpdated, enabled = true }) {
  const wsRef = useRef(null)
  const reconnectTimeoutRef = useRef(null)
  const reconnectAttemptsRef = useRef(0)
  const isMountedRef = useRef(true)
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState(null)

  const closeExistingWs = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.onerror = null
      try { wsRef.current.close(1000, 'cleanup') } catch {}
      wsRef.current = null
    }
  }, [])

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
  }, [])

  const connect = useCallback(() => {
    if (!enabled || !isMountedRef.current) return

    closeExistingWs()
    clearReconnectTimer()

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws/services`

    let ws
    try {
      ws = new WebSocket(wsUrl)
    } catch (err) {
      console.error('[WS] Failed to construct WebSocket:', err)
      return
    }
    wsRef.current = ws

    ws.onopen = () => {
      if (!isMountedRef.current) {
        try { ws.close(1000, 'unmounted') } catch {}
        return
      }
      reconnectAttemptsRef.current = 0
      setIsConnected(true)
    }

    ws.onmessage = (event) => {
      if (!isMountedRef.current) return
      try {
        const message = JSON.parse(event.data)
        setLastMessage(message)
        switch (message.type) {
          case 'health_update': onHealthUpdate?.(message); break
          case 'service_added': onServiceAdded?.(message); break
          case 'service_removed': onServiceRemoved?.(message); break
          case 'service_updated': onServiceUpdated?.(message); break
          case 'pong': break
          default: break
        }
      } catch (err) {
        console.error('[WS] Failed to parse message:', err)
      }
    }

    ws.onerror = () => {}

    ws.onclose = (event) => {
      if (!isMountedRef.current) return
      setIsConnected(false)
      if (!enabled) return
      if (event.code === 1000) return

      // Backend explicitly rejected auth: session expired, do not reconnect forever
      if (event.code === 4001 || event.code === 4003) {
        window.dispatchEvent(new CustomEvent('auth-expired', { detail: { reason: 'websocket' } }))
        return
      }

      reconnectAttemptsRef.current += 1
      if (reconnectAttemptsRef.current > 5) return
      const delay = Math.min(1000 * 2 ** (reconnectAttemptsRef.current - 1), 30000)
      reconnectTimeoutRef.current = setTimeout(connect, delay)
    }
  }, [enabled, onHealthUpdate, onServiceAdded, onServiceRemoved, onServiceUpdated, closeExistingWs, clearReconnectTimer])

  const disconnect = useCallback(() => {
    clearReconnectTimer()
    closeExistingWs()
  }, [clearReconnectTimer, closeExistingWs])

  const sendPing = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'ping' }))
    }
  }, [])

  useEffect(() => {
    isMountedRef.current = true
    if (enabled) connect()
    else disconnect()
    return () => {
      isMountedRef.current = false
      disconnect()
    }
  }, [enabled, connect, disconnect])

  // Heartbeat
  useEffect(() => {
    if (!isConnected) return
    const interval = setInterval(sendPing, 30000)
    return () => clearInterval(interval)
  }, [isConnected, sendPing])

  return { isConnected, lastMessage, reconnect: connect, disconnect }
}

export default useServiceWebSocket
