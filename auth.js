/**
 * EventLens — Shared Auth Module v1.0
 * Use in ALL pages: <script src="auth.js"></script>
 * 
 * Provides:
 *   ELAuth.getToken()      — id_token or null
 *   ELAuth.isLoggedIn()    — boolean
 *   ELAuth.getUser()       — {email, name, sub, plan} or null
 *   ELAuth.logout()        — clears tokens, redirects to index.html
 *   ELAuth.requireAuth()   — redirects to login if not authenticated
 *   ELAuth.handleCallback() — processes OAuth callback tokens
 */

(function() {
  'use strict';

  const TOKEN_KEYS = {
    id_token:      'id_token',
    access_token:  'access_token',
    refresh_token: 'refresh_token',
    expiry:        'el_token_expiry',
    user:          'el_user'
  };

  const COGNITO_DOMAIN = (() => {
    // Try to read from meta tag or global config
    const meta = document.querySelector('meta[name="cognito-domain"]');
    if (meta) return meta.content;
    return window.COGNITO_DOMAIN || '';
  })();

  function _parseJWT(token) {
    try {
      const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(atob(base64));
    } catch (e) { return null; }
  }

  function _isExpired(token) {
    const payload = _parseJWT(token);
    if (!payload || !payload.exp) return true;
    return (payload.exp * 1000) < Date.now();
  }

  const ELAuth = {
    getToken() {
      const token = localStorage.getItem(TOKEN_KEYS.id_token);
      if (!token) return null;
      if (_isExpired(token)) {
        this.clearTokens();
        return null;
      }
      return token;
    },

    isLoggedIn() {
      return !!this.getToken();
    },

    getUser() {
      const token = this.getToken();
      if (!token) return null;
      try {
        const cached = localStorage.getItem(TOKEN_KEYS.user);
        if (cached) return JSON.parse(cached);
        const payload = _parseJWT(token);
        const user = {
          email: payload.email || '',
          name:  payload.name || payload['cognito:username'] || '',
          sub:   payload.sub || '',
          plan:  payload['custom:plan'] || 'free',
          studioName: payload['custom:studio_name'] || ''
        };
        localStorage.setItem(TOKEN_KEYS.user, JSON.stringify(user));
        return user;
      } catch (e) { return null; }
    },

    clearTokens() {
      Object.values(TOKEN_KEYS).forEach(k => localStorage.removeItem(k));
      sessionStorage.clear();
    },

    logout(redirectTo) {
      this.clearTokens();
      const dest = redirectTo || 'index.html';
      if (COGNITO_DOMAIN && window.CLIENT_ID) {
        const logoutUrl = `${COGNITO_DOMAIN}/logout?client_id=${window.CLIENT_ID}&logout_uri=${encodeURIComponent(location.origin + '/' + dest)}`;
        location.href = logoutUrl;
      } else {
        location.href = dest;
      }
    },

    requireAuth(redirectTo) {
      if (!this.isLoggedIn()) {
        location.href = redirectTo || 'index.html';
        return false;
      }
      return true;
    },

    handleCallback() {
      const params = new URLSearchParams(location.hash.replace('#', '?'));
      const id_token = params.get('id_token');
      const access_token = params.get('access_token');
      
      if (id_token) {
        localStorage.setItem(TOKEN_KEYS.id_token, id_token);
        if (access_token) localStorage.setItem(TOKEN_KEYS.access_token, access_token);
        
        const payload = _parseJWT(id_token);
        if (payload && payload.exp) {
          localStorage.setItem(TOKEN_KEYS.expiry, payload.exp * 1000);
        }
        // Clear hash
        history.replaceState(null, '', location.pathname + location.search);
        return true;
      }
      return false;
    },

    // Returns Authorization header object
    authHeaders() {
      const token = this.getToken();
      return token ? { 'Authorization': `Bearer ${token}` } : {};
    },

    // Plan checking
    hasFeature(feature) {
      const user = this.getUser();
      const plan = (user?.plan || 'free').toLowerCase();
      const PLAN_FEATURES = {
        free:        ['face_search', 'gallery'],
        launch:      ['face_search', 'gallery', 'branding', 'bulk_download'],
        growth:      ['face_search', 'gallery', 'branding', 'bulk_download', 'whatsapp', 'album', 'highres'],
        pro:         ['face_search', 'gallery', 'branding', 'bulk_download', 'whatsapp', 'album', 'highres', 'watermark', 'favorites'],
        studio:      ['face_search', 'gallery', 'branding', 'bulk_download', 'whatsapp', 'album', 'highres', 'watermark', 'favorites', 'analytics', 'team', 'subdomain'],
        studio_plus: ['face_search', 'gallery', 'branding', 'bulk_download', 'whatsapp', 'album', 'highres', 'watermark', 'favorites', 'analytics', 'team', 'subdomain', 'white_label'],
        premium:     ['face_search', 'gallery', 'branding', 'bulk_download', 'whatsapp', 'album', 'highres', 'watermark', 'favorites', 'analytics', 'team', 'subdomain', 'white_label', 'api', 'custom_domain']
      };
      const features = PLAN_FEATURES[plan] || PLAN_FEATURES['free'];
      return features.includes(feature);
    }
  };

  // Auto-handle OAuth callback on page load
  if (location.hash.includes('id_token=')) {
    ELAuth.handleCallback();
  }

  // Expose globally
  window.ELAuth = ELAuth;

})();
