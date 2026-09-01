/**
 * Copy text to clipboard with fallback for non-secure contexts
 * @param {string} text - Text to copy
 * @returns {Promise<boolean>} - True if successful
 */
export async function copyToClipboard(text) {
  try {
    // Try modern clipboard API first (requires HTTPS or localhost)
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return true
    }

    // Fallback for HTTP or older browsers
    const textArea = document.createElement('textarea')
    textArea.value = text

    // Avoid scrolling to bottom
    textArea.style.position = 'fixed'
    textArea.style.left = '-999999px'
    textArea.style.top = '-999999px'
    textArea.style.opacity = '0'

    document.body.appendChild(textArea)
    textArea.focus()
    textArea.select()

    const successful = document.execCommand('copy')
    document.body.removeChild(textArea)

    if (!successful) {
      throw new Error('execCommand copy failed')
    }

    return true
  } catch (err) {
    console.error('Clipboard copy failed:', err)
    throw err
  }
}
