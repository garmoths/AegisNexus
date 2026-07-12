// Hostname-based URL helper.
// Production: separate subdomains (modules.example.com, example.com).
// Local/Docker (localhost, IP): single origin SPA routes (/modules, /).

const host = typeof window !== 'undefined' ? window.location.hostname.toLowerCase() : ''
const isProdMain = host === 'your-domain.com' || host === 'www.your-domain.com'
const isProdModules = host === 'modules.your-domain.com' || host.startsWith('modules.')

export const MODULES_URL = isProdMain ? 'https://modules.your-domain.com' : '/modules'
export const HOME_URL = isProdModules ? 'https://your-domain.com' : '/'
