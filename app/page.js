'use client'
import { useState, useEffect, useCallback } from 'react'

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
  // PERSISTENCIA
  // ============================================

  const saveData = useCallback(async (entriesToSave, key, saltBytes) => {
    try {
      const encryptedData = await encrypt(entriesToSave, key)
      const vaultData = {
        data: encryptedData,
        salt: btoa(String.fromCharCode(...saltBytes))
      }
      localStorage.setItem('boveda_vault', JSON.stringify(vaultData))
    } catch (err) {
      console.error('Error saving:', err)
      setError('Error al guardar')
    }
  }, [])

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
      
      const decryptedEntries = await decrypt(vaultData.data, key)
      
      setSalt(saltBytes)
      setCryptoKey(key)
      setEntries(decryptedEntries)
      setIsLocked(false)
      setMasterPassword('')
      setShowMasterPassword(false)
      setLastActivity(Date.now())
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
            <p className="text-gray-400 mt-2">Contraseñas seguras, 100% local</p>
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
            Tus datos nunca salen de este dispositivo
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
        <p>Auto-bloqueo en {AUTO_LOCK_MINUTES} min de inactividad</p>
        <p className="mt-1">Creado por C-Cloud | Colmena 2026</p>
      </div>
    </main>
  )
}
