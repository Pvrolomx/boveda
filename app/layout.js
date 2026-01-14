import './globals.css'

export const metadata = {
  title: 'Bóveda - Password Manager Local',
  description: 'Tus contraseñas seguras, 100% local',
  manifest: '/manifest.json',
}

export default function RootLayout({ children }) {
  return (
    <html lang="es">
      <body className="bg-gray-950 text-white">{children}</body>
    </html>
  )
}
