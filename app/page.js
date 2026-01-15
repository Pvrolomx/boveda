'use client'
import { useState, useEffect, useCallback, useRef } from 'react'
import { QRCodeSVG } from 'qrcode.react'

// ============================================
// SUPABASE CLIENT (opcional, mantener compatibilidad)
// ============================================
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

const supabase = supabaseUrl && supabaseAnonKey 
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null

// ============================================
// CONSTANTES CRYPTO
// ============================================
const SALT_LENGTH = 16
const IV_LENGTH = 12
const ITERATIONS = 100000
const AUTO_LOCK_MINUTES = 5

// ============================================
// FUNCIONES CRYPTO (Web Crypto API)
// ============================================

function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
}

function generateIV() {
  return crypto.getRandomValues(new Uint8Array(IV_LENGTH))
}

async function deriveKey(password, salt) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  )
  
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

async function encrypt(data, key) {
  const encoder = new TextEncoder()
  const iv = generateIV()
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(JSON.stringify(data))
  )
  
  const combined = new Uint8Array(iv.length + encrypted.byteLength)
  combined.set(iv)
  combined.set(new Uint8Array(encrypted), iv.length)
  
  return btoa(String.fromCharCode(...combined))
}

async function decrypt(encryptedBase64, key) {
  const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0))
  const iv = combined.slice(0, IV_LENGTH)
  const data = combined.slice(IV_LENGTH)
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  )
  
  const decoder = new TextDecoder()
  return JSON.parse(decoder.decode(decrypted))
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2)
}

function generatePassword(length = 16) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, b => chars[b % chars.length]).join('')
}

function getUserId() {
  let userId = localStorage.getItem('boveda_user_id')
  if (!userId) {
    userId = 'user_' + generateId()
    localStorage.setItem('boveda_user_id', userId)
  }
  return userId
}

// ============================================
// COMPONENTE PRINCIPAL
// ============================================

export default function Boveda() {
  const [isLocked, setIsLocked] = useState(true)
  const [hasVault, setHasVault] = useState(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [entries, setEntries] = useState([])
  const [cryptoKey, setCryptoKey] = useState(null)
  const [salt, setSalt] = useState(null)
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [lastActivity, setLastActivity] = useState(Date.now())
  const [copiedId, setCopiedId] = useState(null)
  const [qrEntry, setQrEntry] = useState(null)
  const [showChangePassword, setShowChangePassword] = useState(false)
  const [currentPwd, setCurrentPwd] = useState("")
  const [newPwd, setNewPwd] = useState("")
  const [confirmNewPwd, setConfirmNewPwd] = useState("")
  const [changePwdError, setChangePwdError] = useState("")
  const [syncing, setSyncing] = useState(false)
  const [syncStatus, setSyncStatus] = useState('')
  
  // Estados para Export/Import
  const [showTransfer, setShowTransfer] = useState(false)
  const [transferMode, setTransferMode] = useState('export') // 'export' | 'import'
  const [exportData, setExportData] = useState('')
  const [importCode, setImportCode] = useState('')
  const [showScanner, setShowScanner] = useState(false)
  const [transferStatus, setTransferStatus] = useState('')
  
  // Estados para mostrar/ocultar passwords
  const [showMasterPassword, setShowMasterPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [showFormPassword, setShowFormPassword] = useState(false)
  const [visiblePasswords, setVisiblePasswords] = useState({})
  
  // PWA Install
  const [deferredPrompt, setDeferredPrompt] = useState(null)
  const [showInstall, setShowInstall] = useState(false)
  
  const [formData, setFormData] = useState({
    name: '', username: '', password: '', url: '', notes: ''
  })

  const html5QrCodeRef = useRef(null)

  // ============================================
  // EFFECTS
  // ============================================

  useEffect(() => {
    if (typeof window !== "undefined" && "serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch(() => {})
    }
    
    const handler = (e) => {
      e.preventDefault()
      setDeferredPrompt(e)
      setShowInstall(true)
    }
    window.addEventListener('beforeinstallprompt', handler)
    return () => window.removeEventListener('beforeinstallprompt', handler)
  }, [])

  const installApp = async () => {
    if (!deferredPrompt) return
    deferredPrompt.prompt()
    const { outcome } = await deferredPrompt.userChoice
    if (outcome === 'accepted') {
      setShowInstall(false)
    }
    setDeferredPrompt(null)
  }

  useEffect(() => {
    const vaultExists = localStorage.getItem('boveda_vault')
    setHasVault(!!vaultExists)
  }, [])

  useEffect(() => {
    if (!isLocked) {
      const interval = setInterval(() => {
        if (Date.now() - lastActivity > AUTO_LOCK_MINUTES * 60 * 1000) {
          handleLock()
        }
      }, 10000)
      return () => clearInterval(interval)
    }
  }, [isLocked, lastActivity])

  useEffect(() => {
    const handleActivity = () => setLastActivity(Date.now())
    window.addEventListener('click', handleActivity)
    window.addEventListener('keydown', handleActivity)
    return () => {
      window.removeEventListener('click', handleActivity)
      window.removeEventListener('keydown', handleActivity)
    }
  }, [])

  // ============================================
  // EXPORT/IMPORT FUNCTIONS
  // ============================================

  const handleExport = () => {
    const vaultData = localStorage.getItem('boveda_vault')
    if (!vaultData) {
      setTransferStatus('❌ No hay datos para exportar')
      return
    }
    
    try {
      const vault = JSON.parse(vaultData)
      // Crear paquete con salt + datos encriptados
      const exportPackage = {
        v: 1, // versión del formato
        s: vault.salt,
        d: vault.encrypted,
        t: new Date().toISOString()
      }
      
      // Convertir a string compacto
      const exportString = btoa(JSON.stringify(exportPackage))
      setExportData(exportString)
      setTransferStatus(`✅ QR listo (${Math.round(exportString.length/1024*10)/10}KB)`)
    } catch (err) {
      setTransferStatus('❌ Error al exportar')
      console.error(err)
    }
  }

  const handleImport = async () => {
    if (!importCode.trim()) {
      setTransferStatus('❌ Escanea o pega un código')
      return
    }
    
    try {
      const importPackage = JSON.parse(atob(importCode.trim()))
      
      if (!importPackage.s || !importPackage.d) {
        throw new Error('Formato inválido')
      }
      
      // Guardar en localStorage con el formato correcto
      const vaultData = {
        salt: importPackage.s,
        encrypted: importPackage.d,
        updated_at: importPackage.t || new Date().toISOString()
      }
      
      localStorage.setItem('boveda_vault', JSON.stringify(vaultData))
      setHasVault(true)
      setShowTransfer(false)
      setImportCode('')
      stopScanner()
      
      alert('✅ Datos importados. Ahora desbloquea con tu contraseña maestra.')
    } catch (err) {
      setTransferStatus('❌ Código inválido')
      console.error(err)
    }
  }

  // ============================================
  // SCANNER FUNCTIONS
  // ============================================

  const startScanner = async () => {
    try {
      const { Html5Qrcode } = await import("html5-qrcode")
      if (html5QrCodeRef.current) {
        try { await html5QrCodeRef.current.stop() } catch(e) {}
      }
      const html5QrCode = new Html5Qrcode("qr-reader-transfer")
      html5QrCodeRef.current = html5QrCode
      await html5QrCode.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 250, height: 250 } },
        (decodedText) => {
          setImportCode(decodedText)
          stopScanner()
          setShowScanner(false)
          setTransferStatus('✅ QR escaneado')
        },
        () => {}
      )
    } catch (err) {
      console.error("Scanner error:", err)
      alert("No se pudo acceder a la cámara")
      setShowScanner(false)
    }
  }

  const stopScanner = async () => {
    if (html5QrCodeRef.current) {
      try {
        await html5QrCodeRef.current.stop()
        html5QrCodeRef.current = null
      } catch (err) {}
    }
  }

  useEffect(() => {
    if (showScanner && transferMode === 'import') {
      const timer = setTimeout(() => {
        const el = document.getElementById("qr-reader-transfer")
        if (el) startScanner()
      }, 500)
      return () => clearTimeout(timer)
    } else {
      stopScanner()
    }
  }, [showScanner, transferMode])

  // ============================================
  // VAULT FUNCTIONS
  // ============================================

  const handleSetup = async (e) => {
    e.preventDefault()
    setError('')
    
    if (masterPassword.length < 4) {
      setError('Mínimo 4 caracteres')
      return
    }
    
    if (masterPassword !== confirmPassword) {
      setError('Las contraseñas no coinciden')
      return
    }

    try {
      const newSalt = generateSalt()
      const key = await deriveKey(masterPassword, newSalt)
      
      const vaultData = {
        salt: btoa(String.fromCharCode(...newSalt)),
        encrypted: await encrypt([], key),
        updated_at: new Date().toISOString()
      }
      
      localStorage.setItem('boveda_vault', JSON.stringify(vaultData))
      
      setSalt(newSalt)
      setCryptoKey(key)
      setEntries([])
      setHasVault(true)
      setIsLocked(false)
      setMasterPassword('')
      setConfirmPassword('')
    } catch (err) {
      setError('Error al crear bóveda')
      console.error(err)
    }
  }

  const handleUnlock = async (e) => {
    e.preventDefault()
    setError('')

    try {
      const vaultData = JSON.parse(localStorage.getItem('boveda_vault'))
      const saltBytes = Uint8Array.from(atob(vaultData.salt), c => c.charCodeAt(0))
      const key = await deriveKey(masterPassword, saltBytes)
      
      const decryptedEntries = await decrypt(vaultData.encrypted, key)
      
      setSalt(saltBytes)
      setCryptoKey(key)
      setEntries(decryptedEntries)
      setIsLocked(false)
      setMasterPassword('')
      setLastActivity(Date.now())
      setSyncStatus('✓ Desbloqueado')
      setTimeout(() => setSyncStatus(''), 2000)
    } catch (err) {
      setError('Contraseña incorrecta')
    }
  }

  const handleLock = () => {
    setIsLocked(true)
    setCryptoKey(null)
    setEntries([])
    setSearchTerm('')
    setShowForm(false)
    setEditingId(null)
    setVisiblePasswords({})
  }

  const saveEntries = async (newEntries) => {
    if (!cryptoKey || !salt) return
    
    try {
      const encrypted = await encrypt(newEntries, cryptoKey)
      const vaultData = {
        salt: btoa(String.fromCharCode(...salt)),
        encrypted: encrypted,
        updated_at: new Date().toISOString()
      }
      localStorage.setItem('boveda_vault', JSON.stringify(vaultData))
      setEntries(newEntries)
    } catch (err) {
      console.error('Error saving:', err)
    }
  }

  const handleAddEntry = async (e) => {
    e.preventDefault()
    
    if (!formData.name || !formData.password) return
    
    const newEntry = {
      id: editingId || generateId(),
      ...formData,
      createdAt: editingId ? entries.find(e => e.id === editingId)?.createdAt : new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
    
    let newEntries
    if (editingId) {
      newEntries = entries.map(e => e.id === editingId ? newEntry : e)
    } else {
      newEntries = [...entries, newEntry]
    }
    
    await saveEntries(newEntries)
    
    setFormData({ name: '', username: '', password: '', url: '', notes: '' })
    setShowForm(false)
    setEditingId(null)
  }

  const handleEdit = (entry) => {
    setFormData({
      name: entry.name,
      username: entry.username || '',
      password: entry.password,
      url: entry.url || '',
      notes: entry.notes || ''
    })
    setEditingId(entry.id)
    setShowForm(true)
  }

  const handleDelete = async (id) => {
    if (!confirm('¿Eliminar esta contraseña?')) return
    const newEntries = entries.filter(e => e.id !== id)
    await saveEntries(newEntries)
  }

  const handleCopy = async (text, id) => {
    await navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const togglePasswordVisibility = (id) => {
    setVisiblePasswords(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const handleChangePassword = async (e) => {
    e.preventDefault()
    setChangePwdError("")
    
    if (newPwd.length < 4) {
      setChangePwdError("Mínimo 4 caracteres")
      return
    }
    
    if (newPwd !== confirmNewPwd) {
      setChangePwdError("Las contraseñas no coinciden")
      return
    }
    
    try {
      const vaultData = JSON.parse(localStorage.getItem('boveda_vault'))
      const oldSaltBytes = Uint8Array.from(atob(vaultData.salt), c => c.charCodeAt(0))
      const oldKey = await deriveKey(currentPwd, oldSaltBytes)
      await decrypt(vaultData.encrypted, oldKey)
      
      const newSalt = generateSalt()
      const newKey = await deriveKey(newPwd, newSalt)
      const newEncrypted = await encrypt(entries, newKey)
      
      const newVaultData = {
        salt: btoa(String.fromCharCode(...newSalt)),
        encrypted: newEncrypted,
        updated_at: new Date().toISOString()
      }
      localStorage.setItem('boveda_vault', JSON.stringify(newVaultData))
      
      setSalt(newSalt)
      setCryptoKey(newKey)
      setShowChangePassword(false)
      setCurrentPwd("")
      setNewPwd("")
      setConfirmNewPwd("")
      alert("✅ Contraseña cambiada")
    } catch (err) {
      setChangePwdError("Contraseña actual incorrecta")
    }
  }

  const handleDeleteVault = () => {
    if (!confirm('⚠️ ¿Eliminar TODA la bóveda? Esta acción no se puede deshacer.')) return
    if (!confirm('¿Estás seguro? Se perderán todas las contraseñas.')) return
    
    localStorage.removeItem('boveda_vault')
    localStorage.removeItem('boveda_user_id')
    setHasVault(false)
    setIsLocked(true)
    setEntries([])
    setCryptoKey(null)
    setSalt(null)
  }

  const filteredEntries = entries.filter(entry =>
    entry.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (entry.username && entry.username.toLowerCase().includes(searchTerm.toLowerCase()))
  )

  // ============================================
  // RENDER - LOCKED STATE
  // ============================================

  if (isLocked) {
    return (
      <main className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white p-4 flex flex-col items-center justify-center">
        <div className="w-full max-w-sm">
          <div className="text-center mb-8">
            <div className="text-6xl mb-4">🔐</div>
            <h1 className="text-3xl font-bold">Bóveda</h1>
            <p className="text-gray-400 mt-1">Gestor de contraseñas seguro</p>
          </div>

          {!hasVault ? (
            <form onSubmit={handleSetup} className="space-y-4">
              <p className="text-center text-gray-400 text-sm mb-4">
                Crea tu contraseña maestra
              </p>
              
              <div className="relative">
                <input
                  type={showMasterPassword ? "text" : "password"}
                  placeholder="Contraseña maestra"
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  className="w-full bg-gray-800 rounded-xl px-4 py-3 pr-12 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  autoFocus
                />
                <button
                  type="button"
                  onClick={() => setShowMasterPassword(!showMasterPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showMasterPassword ? '🙈' : '👁️'}
                </button>
              </div>
              
              <div className="relative">
                <input
                  type={showConfirmPassword ? "text" : "password"}
                  placeholder="Confirmar contraseña"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-gray-800 rounded-xl px-4 py-3 pr-12 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showConfirmPassword ? '🙈' : '👁️'}
                </button>
              </div>
              
              {error && <p className="text-red-400 text-sm text-center">{error}</p>}
              
              <button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700 rounded-xl py-3 font-medium transition-colors"
              >
                Crear Bóveda
              </button>
              
              <button
                type="button"
                onClick={() => { setShowTransfer(true); setTransferMode('import'); }}
                className="w-full bg-gray-700 hover:bg-gray-600 rounded-xl py-3 font-medium transition-colors flex items-center justify-center gap-2"
              >
                📥 Importar desde otro dispositivo
              </button>
            </form>
          ) : (
            <form onSubmit={handleUnlock} className="space-y-4">
              <div className="relative">
                <input
                  type={showMasterPassword ? "text" : "password"}
                  placeholder="Contraseña maestra"
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  className="w-full bg-gray-800 rounded-xl px-4 py-3 pr-12 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  autoFocus
                />
                <button
                  type="button"
                  onClick={() => setShowMasterPassword(!showMasterPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showMasterPassword ? '🙈' : '👁️'}
                </button>
              </div>
              
              {error && <p className="text-red-400 text-sm text-center">{error}</p>}
              
              <button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700 rounded-xl py-3 font-medium transition-colors"
              >
                🔓 Desbloquear
              </button>
            </form>
          )}

          {/* Install App Button */}
          {showInstall && (
            <button
              onClick={installApp}
              className="w-full mt-4 bg-green-600 hover:bg-green-700 rounded-xl py-3 font-medium transition-colors flex items-center justify-center gap-2"
            >
              <span>📲</span>
              <span className="font-semibold">Instalar App</span>
            </button>
          )}

          <div className="text-center text-gray-600 text-xs mt-8">
            <p>Creado por C19 Sage | Colmena 2026</p>
          </div>
        </div>

        {/* Transfer Modal (Import mode from locked state) */}
        {showTransfer && (
          <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
            <div className="bg-gray-900 rounded-2xl p-6 w-full max-w-sm">
              <h2 className="text-xl font-bold mb-4 text-center">📥 Importar Bóveda</h2>
              
              <p className="text-gray-400 text-sm text-center mb-4">
                Escanea el QR del dispositivo que tiene tus contraseñas
              </p>
              
              {!showScanner ? (
                <button
                  onClick={() => setShowScanner(true)}
                  className="w-full bg-blue-600 hover:bg-blue-700 rounded-xl py-3 font-medium transition-colors flex items-center justify-center gap-2 mb-4"
                >
                  📷 Escanear QR
                </button>
              ) : (
                <div className="mb-4">
                  <div id="qr-reader-transfer" className="w-full bg-gray-800 rounded-xl overflow-hidden" style={{ minHeight: "280px" }}></div>
                  <button
                    onClick={startScanner}
                    className="w-full mt-2 bg-green-600 hover:bg-green-500 rounded-lg py-2 text-sm"
                  >
                    🔄 Reiniciar cámara
                  </button>
                </div>
              )}
              
              <div className="border-t border-gray-700 pt-4 mt-4">
                <p className="text-xs text-gray-400 mb-2">O pega el código:</p>
                <textarea
                  placeholder="Pega aquí el código exportado..."
                  value={importCode}
                  onChange={(e) => setImportCode(e.target.value)}
                  className="w-full bg-gray-800 rounded-lg px-4 py-2 mb-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 h-20 resize-none"
                />
                <button
                  onClick={handleImport}
                  disabled={!importCode.trim()}
                  className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-700 disabled:opacity-50 rounded-lg py-2 font-medium"
                >
                  Importar
                </button>
              </div>
              
              {transferStatus && (
                <p className="text-center text-sm mt-3">{transferStatus}</p>
              )}
              
              <button
                onClick={() => { setShowTransfer(false); setImportCode(''); setShowScanner(false); stopScanner(); setTransferStatus(''); }}
                className="w-full mt-4 bg-gray-700 hover:bg-gray-600 rounded-lg py-2"
              >
                Cancelar
              </button>
            </div>
          </div>
        )}
      </main>
    )
  }

  // ============================================
  // RENDER - UNLOCKED STATE
  // ============================================

  return (
    <main className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white p-4 pb-24">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">🔐 Bóveda</h1>
          {syncStatus && <p className="text-xs text-green-400">{syncStatus}</p>}
        </div>
        <div className="flex gap-2">
          {/* Install App Button (unlocked) */}
          {showInstall && (
            <button
              onClick={installApp}
              className="bg-green-600 hover:bg-green-700 rounded-lg p-2 transition-colors"
              title="Instalar App"
            >
              📲
            </button>
          )}
          <button
            onClick={() => { setShowTransfer(true); setTransferMode('export'); handleExport(); }}
            className="bg-purple-600 hover:bg-purple-700 rounded-lg p-2 transition-colors"
            title="Exportar/Importar"
          >
            🔄
          </button>
          <button
            onClick={() => setShowChangePassword(true)}
            className="bg-gray-700 hover:bg-gray-600 rounded-lg p-2 transition-colors"
            title="Cambiar contraseña"
          >
            ⚙️
          </button>
          <button
            onClick={handleLock}
            className="bg-red-600 hover:bg-red-700 rounded-lg p-2 transition-colors"
            title="Bloquear"
          >
            🔒
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="relative mb-4">
        <input
          type="text"
          placeholder="🔍 Buscar..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-gray-800 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      {/* Add Button */}
      <button
        onClick={() => { setShowForm(true); setEditingId(null); setFormData({ name: '', username: '', password: '', url: '', notes: '' }); }}
        className="w-full bg-blue-600 hover:bg-blue-700 rounded-xl py-3 font-medium mb-4 transition-colors"
      >
        + Agregar Contraseña
      </button>

      {/* Add/Edit Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 rounded-2xl p-6 w-full max-w-sm">
            <h2 className="text-xl font-bold mb-4">
              {editingId ? '✏️ Editar' : '➕ Nueva Contraseña'}
            </h2>
            <form onSubmit={handleAddEntry} className="space-y-3">
              <input
                type="text"
                placeholder="Nombre (ej: Gmail, Netflix)"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
              <input
                type="text"
                placeholder="Usuario o email"
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <div className="relative">
                <input
                  type={showFormPassword ? "text" : "password"}
                  placeholder="Contraseña"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  className="w-full bg-gray-800 rounded-lg px-4 py-2 pr-20 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                  <button
                    type="button"
                    onClick={() => setShowFormPassword(!showFormPassword)}
                    className="text-gray-400 hover:text-white p-1"
                  >
                    {showFormPassword ? '🙈' : '👁️'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormData({ ...formData, password: generatePassword() })}
                    className="text-gray-400 hover:text-white p-1"
                    title="Generar"
                  >
                    🎲
                  </button>
                </div>
              </div>
              <input
                type="url"
                placeholder="URL (opcional)"
                value={formData.url}
                onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <textarea
                placeholder="Notas (opcional)"
                value={formData.notes}
                onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none h-20"
              />
              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => { setShowForm(false); setEditingId(null); }}
                  className="flex-1 bg-gray-700 hover:bg-gray-600 rounded-lg py-2 transition-colors"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 rounded-lg py-2 font-medium transition-colors"
                >
                  {editingId ? 'Guardar' : 'Agregar'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Change Password Modal */}
      {showChangePassword && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 rounded-2xl p-6 w-full max-w-sm">
            <h2 className="text-xl font-bold mb-4">🔑 Cambiar Contraseña</h2>
            <form onSubmit={handleChangePassword} className="space-y-3">
              <input
                type="password"
                placeholder="Contraseña actual"
                value={currentPwd}
                onChange={(e) => setCurrentPwd(e.target.value)}
                className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
              <input
                type="password"
                placeholder="Nueva contraseña"
                value={newPwd}
                onChange={(e) => setNewPwd(e.target.value)}
                className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
              <input
                type="password"
                placeholder="Confirmar nueva"
                value={confirmNewPwd}
                onChange={(e) => setConfirmNewPwd(e.target.value)}
                className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
              {changePwdError && <p className="text-red-400 text-sm">{changePwdError}</p>}
              
              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => { setShowChangePassword(false); setCurrentPwd(''); setNewPwd(''); setConfirmNewPwd(''); setChangePwdError(''); }}
                  className="flex-1 bg-gray-700 hover:bg-gray-600 rounded-lg py-2 transition-colors"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 rounded-lg py-2 font-medium transition-colors"
                >
                  Cambiar
                </button>
              </div>
              
              <button
                type="button"
                onClick={handleDeleteVault}
                className="w-full mt-4 bg-red-900/50 hover:bg-red-900 text-red-400 rounded-lg py-2 text-sm transition-colors"
              >
                🗑️ Eliminar toda la bóveda
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Transfer Modal (Export/Import) */}
      {showTransfer && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 rounded-2xl p-6 w-full max-w-sm">
            <h2 className="text-xl font-bold mb-4 text-center">🔄 Transferir Bóveda</h2>
            
            {/* Toggle */}
            <div className="flex gap-2 mb-4">
              <button
                onClick={() => { setTransferMode('export'); handleExport(); }}
                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${transferMode === 'export' ? 'bg-purple-600' : 'bg-gray-700'}`}
              >
                📤 Exportar
              </button>
              <button
                onClick={() => { setTransferMode('import'); setShowScanner(false); }}
                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${transferMode === 'import' ? 'bg-purple-600' : 'bg-gray-700'}`}
              >
                📥 Importar
              </button>
            </div>
            
            {transferMode === 'export' ? (
              <div>
                <p className="text-gray-400 text-sm text-center mb-4">
                  Escanea este QR desde el otro dispositivo
                </p>
                {exportData ? (
                  <div className="flex flex-col items-center">
                    <div className="bg-white p-4 rounded-xl mb-4">
                      <QRCodeSVG value={exportData} size={220} level="L" />
                    </div>
                    <p className="text-xs text-gray-500 mb-2">
                      {entries.length} contraseña(s) · {Math.round(exportData.length/1024*10)/10}KB
                    </p>
                    <button
                      onClick={() => { navigator.clipboard.writeText(exportData); setTransferStatus('✅ Código copiado'); }}
                      className="text-sm text-blue-400 hover:text-blue-300"
                    >
                      📋 Copiar código
                    </button>
                  </div>
                ) : (
                  <p className="text-center text-gray-500">Generando QR...</p>
                )}
              </div>
            ) : (
              <div>
                <p className="text-gray-400 text-sm text-center mb-4">
                  Escanea el QR del otro dispositivo
                </p>
                
                {!showScanner ? (
                  <button
                    onClick={() => setShowScanner(true)}
                    className="w-full bg-blue-600 hover:bg-blue-700 rounded-xl py-3 font-medium transition-colors flex items-center justify-center gap-2 mb-4"
                  >
                    📷 Escanear QR
                  </button>
                ) : (
                  <div className="mb-4">
                    <div id="qr-reader-transfer" className="w-full bg-gray-800 rounded-xl overflow-hidden" style={{ minHeight: "280px" }}></div>
                    <button
                      onClick={startScanner}
                      className="w-full mt-2 bg-green-600 hover:bg-green-500 rounded-lg py-2 text-sm"
                    >
                      🔄 Reiniciar cámara
                    </button>
                  </div>
                )}
                
                <div className="border-t border-gray-700 pt-4 mt-4">
                  <p className="text-xs text-gray-400 mb-2">O pega el código:</p>
                  <textarea
                    placeholder="Pega aquí..."
                    value={importCode}
                    onChange={(e) => setImportCode(e.target.value)}
                    className="w-full bg-gray-800 rounded-lg px-4 py-2 mb-2 text-sm h-20 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    onClick={handleImport}
                    disabled={!importCode.trim()}
                    className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-700 disabled:opacity-50 rounded-lg py-2 font-medium"
                  >
                    Importar (reemplaza todo)
                  </button>
                </div>
              </div>
            )}
            
            {transferStatus && (
              <p className="text-center text-sm mt-3">{transferStatus}</p>
            )}
            
            <button
              onClick={() => { setShowTransfer(false); setExportData(''); setImportCode(''); setShowScanner(false); stopScanner(); setTransferStatus(''); }}
              className="w-full mt-4 bg-gray-700 hover:bg-gray-600 rounded-lg py-2"
            >
              Cerrar
            </button>
          </div>
        </div>
      )}

      {/* QR Entry Modal */}
      {qrEntry && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 rounded-2xl p-6 w-full max-w-sm text-center">
            <h2 className="text-xl font-bold mb-2">{qrEntry.name}</h2>
            <p className="text-gray-400 text-sm mb-4">{qrEntry.username}</p>
            <div className="bg-white p-4 rounded-xl inline-block mb-4">
              <QRCodeSVG
                value={`${qrEntry.username}\n${qrEntry.password}`}
                size={200}
                level="M"
              />
            </div>
            <p className="text-gray-500 text-xs mb-4">Escanea para copiar usuario y contraseña</p>
            <button
              onClick={() => setQrEntry(null)}
              className="w-full bg-gray-700 hover:bg-gray-600 rounded-lg py-2 transition-colors"
            >
              Cerrar
            </button>
          </div>
        </div>
      )}

      {/* Entries List */}
      <div className="space-y-2">
        {filteredEntries.length === 0 ? (
          <div className="text-center text-gray-500 py-12">
            {entries.length === 0 
              ? 'No hay contraseñas guardadas. ¡Agrega una!'
              : 'No se encontraron resultados'}
          </div>
        ) : (
          filteredEntries.map(entry => (
            <div
              key={entry.id}
              className="bg-gray-900 rounded-xl p-4 hover:bg-gray-800 transition-colors"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <h3 className="font-medium truncate">{entry.name}</h3>
                  <p className="text-gray-400 text-sm truncate">{entry.username}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <p className="text-gray-500 text-sm font-mono">
                      {visiblePasswords[entry.id] ? entry.password : '••••••••'}
                    </p>
                    <button
                      onClick={() => togglePasswordVisibility(entry.id)}
                      className="text-gray-400 hover:text-white transition-colors text-xs"
                    >
                      {visiblePasswords[entry.id] ? '🙈' : '👁️'}
                    </button>
                  </div>
                </div>
                <div className="flex gap-1 ml-2">
                  <button
                    onClick={() => handleCopy(entry.password, entry.id)}
                    className={`p-2 rounded-lg transition-colors ${
                      copiedId === entry.id 
                        ? 'bg-green-600' 
                        : 'bg-gray-700 hover:bg-gray-600'
                    }`}
                    title="Copiar"
                  >
                    {copiedId === entry.id ? '✓' : '📋'}
                  </button>
                  <button
                    onClick={() => setQrEntry(entry)}
                    className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                    title="QR"
                  >
                    📱
                  </button>
                  <button
                    onClick={() => handleEdit(entry)}
                    className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                    title="Editar"
                  >
                    ✏️
                  </button>
                  <button
                    onClick={() => handleDelete(entry.id)}
                    className="p-2 bg-gray-700 hover:bg-red-600 rounded-lg transition-colors"
                    title="Eliminar"
                  >
                    🗑️
                  </button>
                </div>
              </div>
              {entry.url && (
                <a
                  href={entry.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 text-xs mt-2 block truncate hover:underline"
                >
                  {entry.url}
                </a>
              )}
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      <div className="text-center text-gray-600 text-xs mt-8">
        <p>Auto-bloqueo en {AUTO_LOCK_MINUTES} min</p>
        <p className="mt-1">Creado por C19 Sage | Colmena 2026</p>
      </div>
    </main>
  )
}
