require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 10000;

// Configuration
const config = {
  nodeEnv: process.env.NODE_ENV || 'production'
};

// Path configuration
const staticPath = path.resolve(__dirname, '../');
const indexPath = path.resolve(staticPath, 'Index.html');
const footerPath = path.resolve(staticPath, 'Footer.html');

console.log('\n=== Server Initialization ===');
console.log('Environment:', config.nodeEnv);
console.log('Static files path:', staticPath);
console.log('Directory contents:', fs.readdirSync(staticPath));

// Verify critical files exist
if (!fs.existsSync(staticPath)) {
  console.error('\x1b[31mERROR: Static files directory not found\x1b[0m');
  process.exit(1);
}
if (!fs.existsSync(indexPath)) {
  console.error('\x1b[31mERROR: Index.html not found at:', indexPath, '\x1b[0m');
  process.exit(1);
}
if (!fs.existsSync(footerPath)) {
  console.error('\x1b[31mERROR: Footer.html not found at:', footerPath, '\x1b[0m');
  process.exit(1);
}

// Middleware Setup
app.set('trust proxy', 1);

// 1. FIX FOR DOMAIN REDIRECTS (403 errors)
app.use((req, res, next) => {
  const host = req.get('host').replace(/:\d+$/, '').toLowerCase();
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const url = req.originalUrl;

  // Skip static files and API routes
  if (url.includes('.') && !url.endsWith('.html')) {
    return next();
  }

  // Handle all domain variants
  if (host === 'freeontools.com' || protocol !== 'https') {
    return res.redirect(301, `https://www.freeontools.com${url}`);
  }
  next();
});

// 2. FIX FOR .html REDIRECTS
app.get('*.html', (req, res, next) => {
  if (req.path === '/Index.html' || req.path === '/Footer.html') {
    return next();
  }
  const cleanPath = req.path.replace(/\.html$/, '');
  return res.redirect(301, `https://www.freeontools.com${cleanPath}`);
});

// 3. FIX FOR DOUBLE CONTENT
app.use((req, res, next) => {
  res.locals.contentSent = false;
  next();
});

// Fix MIME types for JS files
app.use((req, res, next) => {
  if (req.path.endsWith('.js')) {
    res.type('application/javascript');
  }
  next();
});

// Static files with proper caching
app.use(express.static(staticPath, {
  setHeaders: (res, filePath) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    }
  }
}));

// 4. FIX FOR FOOTER - handle both cases
app.get(['/footer.html', '/Footer.html'], (req, res) => {
  res.sendFile(footerPath);
});

// 5. MAIN ROUTING HANDLER
app.get('*', (req, res, next) => {
  // Skip if content already sent
  if (res.locals.contentSent) {
    return next();
  }

  // Skip files with extensions
  if (req.path.includes('.')) {
    return next();
  }

  // Check if specific page exists
  const pagePath = path.join(staticPath, `${req.path}.html`);
  if (fs.existsSync(pagePath)) {
    res.locals.contentSent = true;
    return res.sendFile(pagePath);
  }

  // Only send Index.html if no specific page found
  res.locals.contentSent = true;
  res.sendFile(indexPath);
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('\x1b[31mSERVER ERROR:\x1b[0m', err.stack);
  res.status(500).send('Internal Server Error');
});

// Start server
app.listen(PORT, () => {
  console.log(`\nServer running on port ${PORT}`);
  console.log('Production URLs:');
  console.log('- https://www.freeontools.com (primary)');
  console.log('- http://freeontools.com → redirects to https://www.freeontools.com');
  console.log('- https://freeontools.com → redirects to https://www.freeontools.com');
  console.log('\nReady to handle requests');
});