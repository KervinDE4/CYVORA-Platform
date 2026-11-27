// frontend/assets/js/auth.js
const MANUAL_TOKEN_STORAGE_KEY = "cyvora_manual_jwt";

let supabaseClientInstance = null;

function getSupabaseClient() {
  if (supabaseClientInstance) return supabaseClientInstance;
  const { SUPABASE_URL, SUPABASE_ANON_KEY } = window.CYVORA_CONFIG || {};
  if (window.supabase && SUPABASE_URL && SUPABASE_ANON_KEY && !SUPABASE_URL.includes("YOUR-PROJECT-REF")) {
    supabaseClientInstance = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  }
  return supabaseClientInstance;
}

function setManualBearerToken(token) {
  const cleaned = (token || "").trim();
  if (cleaned) {
    sessionStorage.setItem(MANUAL_TOKEN_STORAGE_KEY, cleaned);
  } else {
    sessionStorage.removeItem(MANUAL_TOKEN_STORAGE_KEY);
  }
}

function getManualBearerToken() {
  return (sessionStorage.getItem(MANUAL_TOKEN_STORAGE_KEY) || "").trim();
}

async function getBearerToken() {
  const client = getSupabaseClient();
  if (client) {
    try {
      const { data } = await client.auth.getSession();
      const sessionToken = data?.session?.access_token;
      if (sessionToken) return sessionToken;
    } catch (_err) {
      // Fall back to manual token if session isn't active
    }
  }
  return getManualBearerToken();
}

window.CyvoraAuth = {
  getSupabaseClient,
  getBearerToken,
  setManualBearerToken,
  getManualBearerToken
};