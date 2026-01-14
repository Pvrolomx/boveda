'use client'
import { useState, useEffect, useCallback, useRef } from 'react'
import { QRCodeSVG } from 'qrcode.react'

// ============================================
// SUPABASE CLIENT
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

// Obtener o crear user ID único para este usuario
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
  const [showLinkDevice, setShowLinkDevice] = useState(false)
  const [linkCode, setLinkCode] = useState("")
  const [showScanner, setShowScanner] = useState(false)
  const [deviceId, setDeviceId] = useState("")
  const [showChangePassword, setShowChangePassword] = useState(false)
  const [currentPwd, setCurrentPwd] = useState("")
  const [newPwd, setNewPwd] = useState("")
  const [confirmNewPwd, setConfirmNewPwd] = useState("")
  const [changePwdError, setChangePwdError] = useState("")
  const [syncing, setSyncing] = useState(false)
  const [syncStatus, setSyncStatus] = useState('')
  
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

  // ============================================
  // PWA INSTALL PROMPT
  // ============================================

  useEffect(() => {
    // Registrar Service Worker
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

  // ============================================
  // SYNC FUNCTIONS
  // ============================================

  const syncToCloud = async (entriesToSave, saltBytes) => {
    if (!supabase) return
    
    try {
      setSyncing(true)
      const userId = getUserId()
      const encryptedData = await encrypt(entriesToSave, cryptoKey)
      const saltBase64 = btoa(String.fromCharCode(...saltBytes))
      
      const { error } = await supabase
        .from('vaults')
        .upsert({
          user_id: userId,
          encrypted_data: encryptedData,
          salt: saltBase64,
          updated_at: new Date().toISOString()
        }, {
          onConflict: 'user_id'
        })
      
      if (error) throw error
      setSyncStatus('✓ Sincronizado')
      setTimeout(() => setSyncStatus(''), 2000)
    } catch (err) {
      console.error('Sync error:', err)
      setSyncStatus('⚠ Error sync')
    } finally {
      setSyncing(false)
    }
  }

  const loadFromCloud = async (key, saltBytes) => {
    if (!supabase) return null
    
    try {
      const userId = getUserId()
      const { data, error } = await supabase
        .from('vaults')
        .select('encrypted_data, salt, updated_at')
        .eq('user_id', userId)
        .single()
      
      if (error || !data) return null
      
      // Comparar con local para ver cuál es más reciente
      const localData = localStorage.getItem('boveda_vault')
      if (localData) {
        const local = JSON.parse(localData)
        const localTime = new Date(local.updated_at || 0).getTime()
        const cloudTime = new Date(data.updated_at).getTime()
        
        if (localTime > cloudTime) {
          // Local es más reciente, sincronizar a la nube
          return null
        }
      }
      
      const decrypted = await decrypt(data.encrypted_data, key)
      return decrypted
    } catch (err) {
      console.error('Load from cloud error:', err)
      return null
    }
  }

  // ============================================
  // PERSISTENCIA
  // ============================================

  const saveData = useCallback(async (entriesToSave, key, saltBytes) => {
    try {
      const encryptedData = await encrypt(entriesToSave, key)
      const vaultData = {
        data: encryptedData,
        salt: btoa(String.fromCharCode(...saltBytes)),
        updated_at: new Date().toISOString()
      }
      localStorage.setItem('boveda_vault', JSON.stringify(vaultData))
      
      // Sync to cloud
      if (supabase && key) {
        await syncToCloud(entriesToSave, saltBytes)
      }
    } catch (err) {
      console.error('Error saving:', err)
      setError('Error al guardar')
    }
  }, [cryptoKey])

  // ============================================
  // SETUP Y UNLOCK
  // ============================================

  const handleSetup = async (e) => {
    e.preventDefault()
    setError('')
    
    if (masterPassword.length < 8) {
      setError('La contraseña debe tener al menos 8 caracteres')
      return
    }
    
    if (masterPassword !== confirmPassword) {
      setError('Las contraseñas no coinciden')
      return
    }
    
    try {
      const newSalt = generateSalt()
      const key = await deriveKey(masterPassword, newSalt)
      
      setSalt(newSalt)
      setCryptoKey(key)
      setEntries([])
      setIsLocked(false)
      setHasVault(true)
      setMasterPassword('')
      setConfirmPassword('')
      setShowMasterPassword(false)
      setShowConfirmPassword(false)
      
      await saveData([], key, newSalt)
    } catch (err) {
      setError('Error al crear la bóveda')
      console.error(err)
    }
  }

  const handleUnlock = async (e) => {
    e.preventDefault()
    setError('')
    
    try {
      const stored = localStorage.getItem('boveda_vault')
      if (!stored) {
        setError('No hay bóveda guardada')
        return
      }
      
      const vaultData = JSON.parse(stored)
      const saltBytes = Uint8Array.from(atob(vaultData.salt), c => c.charCodeAt(0))
      const key = await deriveKey(masterPassword, saltBytes)
      
      // Primero intentar descifrar local para validar password
      let decryptedEntries = await decrypt(vaultData.data, key)
      
      // Luego intentar cargar de la nube si hay datos más recientes
      const cloudEntries = await loadFromCloud(key, saltBytes)
      if (cloudEntries) {
        decryptedEntries = cloudEntries
        // Actualizar local con datos de la nube
        const encryptedData = await encrypt(cloudEntries, key)
        const newVaultData = {
          data: encryptedData,
          salt: vaultData.salt,
          updated_at: new Date().toISOString()
        }
        localStorage.setItem('boveda_vault', JSON.stringify(newVaultData))
        setSyncStatus('✓ Sincronizado desde nube')
        setTimeout(() => setSyncStatus(''), 2000)
      }
      
      setSalt(saltBytes)
      setCryptoKey(key)
      setEntries(decryptedEntries)
      setIsLocked(false)
      setMasterPassword('')
      setShowMasterPassword(false)
      setLastActivity(Date.now())
      setDeviceId(getUserId())
    } catch (err) {
      setError('Contraseña incorrecta')
      console.error(err)
    }
  }

  const handleLock = () => {
    setIsLocked(true)
    setCryptoKey(null)
    setEntries([])
    setShowForm(false)
    setEditingId(null)
    setVisiblePasswords({})
  }

  const handleLinkDevice = async (newUserId) => {
    if (!newUserId || newUserId.trim() === "") return
    
    // Guardar el nuevo user_id
    localStorage.setItem("boveda_user_id", newUserId.trim())
    
    // Recargar la app para que tome el nuevo ID
    setShowLinkDevice(false)
    setLinkCode("")
    handleLock()
    alert("Dispositivo vinculado. Desbloquea con tu contraseña maestra para sincronizar.")
  }
  const html5QrCodeRef = useRef(null)

  const startScanner = async () => {
    try {
      const { Html5Qrcode } = await import("html5-qrcode")
      if (html5QrCodeRef.current) {
        try { await html5QrCodeRef.current.stop() } catch(e) {}
      }
      const html5QrCode = new Html5Qrcode("qr-reader")
      html5QrCodeRef.current = html5QrCode
      await html5QrCode.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 200, height: 200 } },
        (decodedText) => {
          setLinkCode(decodedText)
          stopScanner()
          setShowScanner(false)
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
    if (showScanner) {
      const timer = setTimeout(() => startScanner(), 100)
      return () => clearTimeout(timer)
    } else {
      stopScanner()
    }
  }, [showScanner])



  const handleChangePassword = async (e) => {
    e.preventDefault()
    setChangePwdError("")
    
    // Validaciones
    if (newPwd.length < 8) {
      setChangePwdError("La nueva contraseña debe tener al menos 8 caracteres")
      return
    }
    if (newPwd !== confirmNewPwd) {
      setChangePwdError("Las contraseñas no coinciden")
      return
    }
    
    try {
      // Verificar contraseña actual
      const stored = localStorage.getItem("boveda_vault")
      const vaultData = JSON.parse(stored)
      const currentSalt = Uint8Array.from(atob(vaultData.salt), c => c.charCodeAt(0))
      const currentKey = await deriveKey(currentPwd, currentSalt)
      
      // Intentar descifrar para verificar
      await decrypt(vaultData.data, currentKey)
      
      // Generar nuevo salt y key
      const newSalt = generateSalt()
      const newKey = await deriveKey(newPwd, newSalt)
      
      // Re-encriptar con la nueva key
      const encryptedData = await encrypt(entries, newKey)
      const newVaultData = {
        data: encryptedData,
        salt: btoa(String.fromCharCode(...newSalt)),
        updated_at: new Date().toISOString()
      }
      localStorage.setItem("boveda_vault", JSON.stringify(newVaultData))
      
      // Actualizar estados
      setSalt(newSalt)
      setCryptoKey(newKey)
      
      // Sync a la nube
      if (supabase) {
        await syncToCloud(entries, newSalt)
      }
      
      // Limpiar y cerrar
      setCurrentPwd("")
      setNewPwd("")
      setConfirmNewPwd("")
      setShowChangePassword(false)
      alert("Contraseña cambiada exitosamente!")
    } catch (err) {
      setChangePwdError("Contraseña actual incorrecta")
      console.error(err)
    }
  }

  // ============================================
  // AUTO-LOCK
  // ============================================

  useEffect(() => {
    if (isLocked) return
    
    const resetActivity = () => setLastActivity(Date.now())
    
    window.addEventListener('mousemove', resetActivity)
    window.addEventListener('keydown', resetActivity)
    window.addEventListener('click', resetActivity)
    
    const interval = setInterval(() => {
      if (Date.now() - lastActivity > AUTO_LOCK_MINUTES * 60 * 1000) {
        handleLock()
      }
    }, 10000)
    
    return () => {
      window.removeEventListener('mousemove', resetActivity)
      window.removeEventListener('keydown', resetActivity)
      window.removeEventListener('click', resetActivity)
      clearInterval(interval)
    }
  }, [isLocked, lastActivity])

  useEffect(() => {
    const stored = localStorage.getItem('boveda_vault')
    setHasVault(!!stored)
    setDeviceId(localStorage.getItem("boveda_user_id") || "")
  }, [])

  // ============================================
  // CRUD ENTRIES
  // ============================================

  const handleSaveEntry = async (e) => {
    e.preventDefault()
    
    let newEntries
    const now = new Date().toISOString()
    
    if (editingId) {
      newEntries = entries.map(entry => 
        entry.id === editingId 
          ? { ...entry, ...formData, updatedAt: now }
          : entry
      )
    } else {
      const newEntry = {
        id: generateId(),
        ...formData,
        createdAt: now,
        updatedAt: now
      }
      newEntries = [...entries, newEntry]
    }
    
    setEntries(newEntries)
    await saveData(newEntries, cryptoKey, salt)
    
    setShowForm(false)
    setEditingId(null)
    setShowFormPassword(false)
    setFormData({ name: '', username: '', password: '', url: '', notes: '' })
  }

  const handleEdit = (entry) => {
    setFormData({
      name: entry.name,
      username: entry.username,
      password: entry.password,
      url: entry.url || '',
      notes: entry.notes || ''
    })
    setEditingId(entry.id)
    setShowFormPassword(false)
    setShowForm(true)
  }

  const handleDelete = async (id) => {
    if (!confirm('¿Eliminar esta entrada?')) return
    
    const newEntries = entries.filter(e => e.id !== id)
    setEntries(newEntries)
    await saveData(newEntries, cryptoKey, salt)
  }

  const handleCopy = async (text, id) => {
    await navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleGeneratePassword = () => {
    setFormData({ ...formData, password: generatePassword() })
    setShowFormPassword(true)
  }

  const togglePasswordVisibility = (id) => {
    setVisiblePasswords(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const filteredEntries = entries.filter(entry =>
    entry.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    entry.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (entry.url && entry.url.toLowerCase().includes(searchTerm.toLowerCase()))
  )

  // ============================================
  // RENDER: LOCKED / SETUP
  // ============================================

  if (isLocked) {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <div className="text-6xl mb-4">🔐</div>
            <h1 className="text-3xl font-bold">Bóveda</h1>
            <p className="text-gray-400 mt-2">Contraseñas seguras con sync ☁️</p>
          </div>

          {/* Install App Button */}
          {showInstall && (
            <button
              onClick={installApp}
              className="w-full bg-green-600 hover:bg-green-500 rounded-xl p-4 mb-4 flex items-center justify-center gap-2 transition-colors"
            >
              <span className="text-xl">📲</span>
              <span className="font-semibold">Instalar App</span>
            </button>
          )}
          
          <div className="bg-gray-900 rounded-2xl p-6">
            {hasVault ? (
              <form onSubmit={handleUnlock}>
                <label className="block text-sm text-gray-400 mb-2">
                  Contraseña maestra
                </label>
                <div className="relative mb-4">
                  <input
                    type={showMasterPassword ? 'text' : 'password'}
                    value={masterPassword}
                    onChange={(e) => setMasterPassword(e.target.value)}
                    className="w-full bg-gray-800 rounded-lg px-4 py-3 pr-12 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="••••••••"
                    autoFocus
                  />
                  <button
                    type="button"
                    onClick={() => setShowMasterPassword(!showMasterPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                  >
                    {showMasterPassword ? '🙈' : '👁️'}
                  </button>
                </div>
                {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                <button
                  type="submit"
                  className="w-full bg-blue-600 hover:bg-blue-700 rounded-lg py-3 font-medium transition-colors"
                >
                  Desbloquear
                </button>
              </form>
            ) : (
              <form onSubmit={handleSetup}>
                <p className="text-gray-400 text-sm mb-4">
                  Crea tu contraseña maestra. Esta será la única contraseña que necesitarás recordar.
                </p>
                <label className="block text-sm text-gray-400 mb-2">
                  Contraseña maestra
                </label>
                <div className="relative mb-4">
                  <input
                    type={showMasterPassword ? 'text' : 'password'}
                    value={masterPassword}
                    onChange={(e) => setMasterPassword(e.target.value)}
                    className="w-full bg-gray-800 rounded-lg px-4 py-3 pr-12 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Mínimo 8 caracteres"
                    autoFocus
                  />
                  <button
                    type="button"
                    onClick={() => setShowMasterPassword(!showMasterPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                  >
                    {showMasterPassword ? '🙈' : '👁️'}
                  </button>
                </div>
                <label className="block text-sm text-gray-400 mb-2">
                  Confirmar contraseña
                </label>
                <div className="relative mb-4">
                  <input
                    type={showConfirmPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full bg-gray-800 rounded-lg px-4 py-3 pr-12 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Repite la contraseña"
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                  >
                    {showConfirmPassword ? '🙈' : '👁️'}
                  </button>
                </div>
                {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                <button
                  type="submit"
                  className="w-full bg-green-600 hover:bg-green-700 rounded-lg py-3 font-medium transition-colors"
                >
                  Crear Bóveda
                </button>
              </form>
            )}
          </div>
          
          <p className="text-center text-gray-600 text-xs mt-6">
            Encriptación local + sync seguro en la nube
          </p>
        </div>
      </main>
    )
  }

  // ============================================
  // RENDER: UNLOCKED
  // ============================================

  return (
    <main className="min-h-screen p-4 max-w-2xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🔓</span>
          <h1 className="text-xl font-bold">Bóveda</h1>
          {syncStatus && (
            <span className="text-xs text-green-400">{syncStatus}</span>
          )}
          {syncing && (
            <span className="text-xs text-gray-400">☁️ Sincronizando...</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {showInstall && (
            <button
              onClick={installApp}
              className="text-gray-400 hover:text-white transition-colors"
              title="Instalar App"
            >
              📲
            </button>
          )}
          <button
            onClick={() => setShowChangePassword(true)}
            className="text-gray-400 hover:text-white transition-colors"
            title="Cambiar contraseña"
          >
            🔑
          </button>
          <button
            onClick={() => setShowLinkDevice(true)}
            className="text-gray-400 hover:text-white transition-colors"
            title="Vincular dispositivo"
          >
            🔗
          </button>
          <button
            onClick={handleLock}
            className="text-gray-400 hover:text-white transition-colors"
          >
            🔒 Bloquear
          </button>
        </div>
      </div>

      {/* Search + Add */}
      <div className="flex gap-2 mb-4">
        <input
          type="text"
          placeholder="Buscar..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="flex-1 bg-gray-900 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={() => {
            setFormData({ name: '', username: '', password: '', url: '', notes: '' })
            setEditingId(null)
            setShowFormPassword(false)
            setShowForm(true)
          }}
          className="bg-blue-600 hover:bg-blue-700 rounded-lg px-4 py-2 font-medium transition-colors"
        >
          + Agregar
        </button>
      </div>

      {/* Entry Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 rounded-2xl p-6 w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">
              {editingId ? 'Editar' : 'Nueva entrada'}
            </h2>
            <form onSubmit={handleSaveEntry}>
              <div className="space-y-3">
                <input
                  type="text"
                  placeholder="Nombre (ej: Gmail)"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
                <input
                  type="text"
                  placeholder="Usuario / Email"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <input
                      type={showFormPassword ? 'text' : 'password'}
                      placeholder="Contraseña"
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      className="w-full bg-gray-800 rounded-lg px-4 py-2 pr-10 focus:outline-none focus:ring-2 focus:ring-blue-500"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowFormPassword(!showFormPassword)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                    >
                      {showFormPassword ? '🙈' : '👁️'}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={handleGeneratePassword}
                    className="bg-gray-700 hover:bg-gray-600 rounded-lg px-3 transition-colors"
                    title="Generar contraseña"
                  >
                    🎲
                  </button>
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
                  className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                  rows={2}
                />
              </div>
              <div className="flex gap-2 mt-4">
                <button
                  type="button"
                  onClick={() => {
                    setShowForm(false)
                    setEditingId(null)
                    setShowFormPassword(false)
                  }}
                  className="flex-1 bg-gray-700 hover:bg-gray-600 rounded-lg py-2 transition-colors"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 rounded-lg py-2 font-medium transition-colors"
                >
                  Guardar
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
            <h2 className="text-xl font-bold mb-4 text-center">🔑 Cambiar Contraseña</h2>
            <form onSubmit={handleChangePassword}>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Contraseña actual</label>
                  <input
                    type="password"
                    value={currentPwd}
                    onChange={(e) => setCurrentPwd(e.target.value)}
                    className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="••••••••"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Nueva contraseña</label>
                  <input
                    type="password"
                    value={newPwd}
                    onChange={(e) => setNewPwd(e.target.value)}
                    className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Mínimo 8 caracteres"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Confirmar nueva contraseña</label>
                  <input
                    type="password"
                    value={confirmNewPwd}
                    onChange={(e) => setConfirmNewPwd(e.target.value)}
                    className="w-full bg-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Repite la nueva contraseña"
                    required
                  />
                </div>
              </div>
              {changePwdError && <p className="text-red-400 text-sm mt-3">{changePwdError}</p>}
              <div className="flex gap-2 mt-4">
                <button
                  type="button"
                  onClick={() => { setShowChangePassword(false); setCurrentPwd(""); setNewPwd(""); setConfirmNewPwd(""); setChangePwdError(""); }}
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
            </form>
          </div>
        </div>
      )}

      {/* Link Device Modal */}
      {showLinkDevice && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 rounded-2xl p-6 w-full max-w-sm text-center">
            <h2 className="text-xl font-bold mb-4">🔗 Vincular Dispositivo</h2>
            
            {/* Toggle buttons */}
            <div className="flex gap-2 mb-4">
              <button
                onClick={() => setShowScanner(false)}
                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${!showScanner ? 'bg-blue-600' : 'bg-gray-700'}`}
              >
                Mostrar QR
              </button>
              <button
                onClick={() => setShowScanner(true)}
                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${showScanner ? 'bg-blue-600' : 'bg-gray-700'}`}
              >
                📷 Escanear
              </button>
            </div>
            
            {/* QR Display */}
            {!showScanner && deviceId && (
              <div className="mb-4">
                <p className="text-xs text-gray-400 mb-3">Escanea desde el otro dispositivo:</p>
                <div className="bg-white p-4 rounded-xl inline-block">
                  <QRCodeSVG value={deviceId} size={180} level="M" />
                </div>
              </div>
            )}
            
            {/* Scanner */}
            {showScanner && (
              <div className="mb-4">
                <p className="text-xs text-gray-400 mb-3">Apunta al QR del otro dispositivo:</p>
                <div id="qr-reader" className="w-full rounded-xl overflow-hidden"></div>
              </div>
            )}
            
            {/* Manual input */}
            <div className="border-t border-gray-700 pt-4 mt-4">
              <p className="text-xs text-gray-400 mb-2">O pega un código:</p>
              <input
                type="text"
                placeholder="Código del otro dispositivo"
                value={linkCode}
                onChange={(e) => setLinkCode(e.target.value)}
                className="w-full bg-gray-800 rounded-lg px-4 py-2 mb-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={() => { handleLinkDevice(linkCode); stopScanner(); }}
                disabled={!linkCode.trim()}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:opacity-50 rounded-lg py-2 font-medium transition-colors"
              >
                Vincular
              </button>
            </div>
            
            <button
              onClick={() => { setShowLinkDevice(false); setLinkCode(""); setShowScanner(false); stopScanner(); }}
              className="w-full mt-4 bg-gray-700 hover:bg-gray-600 rounded-lg py-2 transition-colors"
            >
              Cerrar
            </button>
          </div>
        </div>
      )}

      {/* QR Modal */}
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
                        ? 'bg-green-600 text-white' 
                        : 'bg-gray-700 hover:bg-gray-600'
                    }`}
                    title="Copiar contraseña"
                  >
                    {copiedId === entry.id ? '✓' : '📋'}
                  </button>
                  <button
                    onClick={() => setQrEntry(entry)}
                    className="p-2 bg-gray-700 hover:bg-purple-600 rounded-lg transition-colors"
                    title="Mostrar QR"
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
                  className="text-blue-400 text-xs hover:underline block mt-1 truncate"
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
        <p>Auto-bloqueo en {AUTO_LOCK_MINUTES} min · Sync ☁️ activo</p>
        <p className="mt-1">Creado por C-Cloud | Colmena 2026</p>
      </div>
    </main>
  )
}
