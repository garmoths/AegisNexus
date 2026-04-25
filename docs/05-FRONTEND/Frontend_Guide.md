# AegisNexus Frontend Guide

## 🎨 Frontend Architecture

### Technology Stack
- **Framework:** React 18
- **Build Tool:** Vite 8
- **Language:** JavaScript (ES6+)
- **Styling:** Inline CSS (no external CSS framework)
- **Icons:** Lucide React (via CDN)
- **Fonts:** Inter, JetBrains Mono (Google Fonts)

### Project Structure
```
frontend-react/
├── public/              # Static assets
│   ├── favicon.svg
│   └── icons.svg
├── src/                 # Source code
│   └── ModulesApp.jsx  # Main application component
├── dist/                # Production build output
│   ├── index.html
│   ├── assets/
│   │   ├── index-*.js
│   │   └── index-*.css
│   ├── favicon.svg
│   └── icons.svg
├── index.html           # Entry HTML
├── package.json         # Dependencies
├── vite.config.js       # Vite configuration
└── README.md            # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation

1. **Navigate to frontend directory:**
```bash
cd /Users/enes/AegisNexus/frontend-react
```

2. **Install dependencies:**
```bash
npm install
```

3. **Start development server:**
```bash
npm run dev
```

4. **Build for production:**
```bash
npm run build
```

---

## 📦 Dependencies

**package.json:**
```json
{
  "name": "aegisnexus-frontend",
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.4",
    "vite": "^8.0.9"
  }
}
```

---

## 🎯 Core Components

### Main Application (ModulesApp.jsx)

**Location:** `src/ModulesApp.jsx`

**Features:**
- Tab-based navigation (AI Analyzer, Phishing Detector, Honeypot, Breach Intel)
- API integration with backend
- Real-time analysis results
- Responsive design
- Dark theme

**Key Sections:**

1. **AI Analyzer**
   - Message analysis
   - URL scanning
   - Confidence scoring
   - Threat detection

2. **Phishing Detector**
   - URL checking
   - Latest phishing data
   - Scan history
   - Pagination

3. **Honeypot/IOC**
   - IOC collection
   - Threat intelligence
   - Data visualization

4. **Breach Intelligence**
   - Data breach alerts
   - Email verification
   - Password checks

---

## 🔌 API Integration

### Base URL
```javascript
const API = import.meta.env.VITE_API_BASE_URL || '/api/v2'
```

### Environment Variables
Create `.env` file in project root:
```bash
VITE_API_BASE_URL=/api/v2
```

### API Endpoints

#### AI Analyzer
```javascript
// Analyze message
POST /api/v2/ai-analyzer/analyze
{
  "message": "text to analyze",
  "context": "email|sms|whatsapp|social_media",
  "sender": "optional sender",
  "subject": "optional subject"
}

// Quick scan
POST /api/v2/ai-analyzer/quick-scan
{
  "message": "text to scan"
}

// Check URL
POST /api/v2/ai-analyzer/check-url
{
  "url": "https://example.com"
}

// Get history
GET /api/v2/ai-analyzer/history?limit=10
```

#### Phishing Detector
```javascript
// Check URL
POST /api/v2/phishing/check-url
{
  "url": "https://example.com"
}

// Get latest phishing URLs (paged)
GET /api/v2/phishing/latest-paged?page=1&limit=20

// Get scan history
GET /api/v2/phishing/scan-history?page=1&limit=20

// Get statistics
GET /api/v2/phishing/stats
```

---

## 🎨 Styling Guide

### Theme Configuration
```javascript
const theme = {
  bg: '#080c14',              // Background
  surface: '#0f1629',         // Card background
  surface2: '#1a2342',       // Hover background
  border: '#1e2a4a',          // Border color
  primary: '#00d4ff',         // Primary accent
  accent: '#ff6b35',          // Warning accent
  success: '#22c55e',         // Success color
  warning: '#f59e0b',         // Warning color
  danger: '#ef4444',          // Danger color
  text: '#e2e8f0',            // Main text
  textMuted: '#64748b',       // Muted text
  font: "'Inter', sans-serif",
  mono: "'JetBrains Mono', monospace",
  radius: '12px',             // Border radius
}
```

### Component Styling Patterns

**Card Component:**
```javascript
function Card({ children, style, ...props }) {
  return <div style={{ 
    background: `linear-gradient(135deg, ${theme.surface}, ${theme.surface2})`,
    border: `1px solid ${theme.border}`,
    borderRadius: theme.radius,
    padding: 24,
    ...style 
  }} {...props}>{children}</div>
}
```

**Button Component:**
```javascript
function GlowButton({ children, onClick, variant='primary', ...props }) {
  const isPrimary = variant === 'primary'
  return <button 
    onClick={onClick}
    style={{
      padding: '14px 32px',
      borderRadius: '8px',
      background: isPrimary ? 'linear-gradient(135deg, #00d4ff, #0099cc)' : 'transparent',
      color: isPrimary ? '#000' : '#00d4ff',
      border: isPrimary ? 'none' : '1px solid #00d4ff44',
      ...props
    }}
  >
    {children}
  </button>
}
```

---

## 🔄 Build Process

### Development Build
```bash
npm run dev
```
- Starts Vite dev server
- Hot module replacement
- Source maps enabled
- Port: 5173

### Production Build
```bash
npm run build
```
- Optimizes and minifies code
- Generates static assets
- Output: `dist/` directory
- Ready for deployment

### Preview Production Build
```bash
npm run preview
```
- Serves production build locally
- Tests before deployment

---

## 📤 Deployment

### Local Deployment
```bash
# Build
npm run build

# Copy dist to server
scp -r dist/* root@104.248.45.198:/var/www/aegis_nexus/frontend-react/dist/
```

### Server Deployment
```bash
# SSH to server
ssh root@104.248.45.198

# Navigate to frontend
cd /var/www/aegis_nexus/frontend-react

# Pull latest changes
git pull origin main

# Install dependencies
npm install

# Build
npm run build

# Reload Nginx
sudo systemctl reload nginx
```

### Automated Deployment Script
```bash
#!/bin/bash
# deploy-frontend.sh

echo "Building frontend..."
cd /var/www/aegis_nexus/frontend-react
npm run build

echo "Reloading Nginx..."
sudo systemctl reload nginx

echo "Deployment complete!"
```

---

## 🔧 Configuration

### Vite Config (vite.config.js)
```javascript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    minify: 'terser',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom']
        }
      }
    }
  }
})
```

### Nginx Configuration
```nginx
location / {
    alias /var/www/aegis_nexus/frontend-react/dist/;
    try_files $uri $uri/ /index.html;
    add_header Cache-Control 'no-cache';
}

location /assets/ {
    alias /var/www/aegis_nexus/frontend-react/dist/assets/;
    expires 1y;
    add_header Cache-Control 'public, immutable';
}
```

---

## 🐛 Troubleshooting

### Build Fails
```bash
# Clear cache
rm -rf node_modules/.vite

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Try build again
npm run build
```

### API Connection Issues
```bash
# Check API is running
curl http://localhost:8000/health

# Check environment variable
echo $VITE_API_BASE_URL

# Check CORS settings
```

### Styling Not Loading
```bash
# Check dist directory
ls -la dist/assets/

# Verify build completed
npm run build

# Clear browser cache
```

---

## 📊 Performance Optimization

### Code Splitting
```javascript
// Lazy load components
const PhishingDetector = lazy(() => import('./PhishingDetector'))
```

### Asset Optimization
- Images: Use WebP format
- Fonts: Use font-display: swap
- CSS: Minify and purge unused styles

### Bundle Size
```bash
# Analyze bundle size
npm run build
npx vite-bundle-visualizer
```

---

## 🔒 Security Best Practices

1. **Environment Variables:** Never commit `.env` files
2. **API Keys:** Store in backend, never in frontend
3. **HTTPS:** Always use HTTPS in production
4. **CORS:** Configure properly on backend
5. **Input Validation:** Validate all user inputs
6. **XSS Prevention:** Use React's built-in escaping
7. **CSRF Protection:** Implement CSRF tokens

---

## 🧪 Testing

### Manual Testing Checklist
- [ ] All tabs navigate correctly
- [ ] API calls return data
- [ ] Forms submit successfully
- [ ] Error messages display
- [ ] Responsive design works
- [ ] Loading states show
- [ ] Dark theme applies

### Browser Testing
- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- Mobile browsers

---

## 📝 Development Workflow

### Feature Development
1. Create feature branch
2. Make changes in `src/ModulesApp.jsx`
3. Test locally with `npm run dev`
4. Build with `npm run build`
5. Commit changes
6. Push to repository
7. Deploy to server

### Code Style
- Use functional components
- Prefer hooks over class components
- Keep components small and focused
- Use descriptive variable names
- Add comments for complex logic

---

## 🎯 Customization Guide

### Changing Theme Colors
Edit `theme` object in `ModulesApp.jsx`:
```javascript
const theme = {
  primary: '#your-color',
  // ... other colors
}
```

### Adding New Module
1. Add tab to navigation array
2. Create new component function
3. Add routing logic
4. Implement API integration
5. Add styling

### Modifying API Endpoints
Update `API` constant and fetch calls:
```javascript
const API = import.meta.env.VITE_API_BASE_URL || '/api/v2'
```

---

## 📚 Resources

### Documentation
- [React Documentation](https://react.dev)
- [Vite Documentation](https://vitejs.dev)
- [MDN Web Docs](https://developer.mozilla.org)

### Tools
- [React DevTools](https://react.dev/learn/react-developer-tools)
- [Vite Plugin Inspector](https://github.com/antfu/vite-plugin-inspector)

---

## 🔄 Version History

### v0.0.0 (Current)
- Initial React SPA
- AI Analyzer module
- Phishing Detector module
- Honeypot/IOC module
- Breach Intel module
- Dark theme
- Responsive design

---

**Last Updated:** April 25, 2026
**Maintained By:** enes
