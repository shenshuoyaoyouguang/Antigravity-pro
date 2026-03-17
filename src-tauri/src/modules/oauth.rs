use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[cfg(test)]
pub(crate) static OAUTH_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn reset_oauth_credentials_for_tests() {
    unsafe {
        let ptr = &CREDENTIALS as *const OnceLock<OAuthCredentials> as *mut OnceLock<OAuthCredentials>;
        (*ptr).take();
    }
}

// Google OAuth configuration
// Credentials are loaded from: 1) Environment variables 2) Config file
// Set environment variables: GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET
// Or create config file: ~/.antigravity/oauth.json

/// OAuth credentials container - unified loading with OnceLock
#[derive(Debug, Clone)]
pub struct OAuthCredentials {
    pub client_id: String,
    pub client_secret: String,
}

static CREDENTIALS: OnceLock<OAuthCredentials> = OnceLock::new();

/// Load credentials from env or config file using and_then style
fn try_load_from_env() -> Option<OAuthCredentials> {
    std::env::var("GOOGLE_OAUTH_CLIENT_ID")
        .ok()
        .and_then(|client_id| {
            std::env::var("GOOGLE_OAUTH_CLIENT_SECRET")
                .ok()
                .map(|client_secret| OAuthCredentials {
                    client_id,
                    client_secret,
                })
        })
}

fn try_load_from_config() -> Option<OAuthCredentials> {
    load_oauth_config()
        .and_then(|config| {
            config.client_id.and_then(|client_id| {
                config.client_secret.map(|client_secret| OAuthCredentials {
                    client_id,
                    client_secret,
                })
            })
        })
}

/// Get OAuth credentials, initializing once if not already loaded.
/// Returns error if credentials are missing or incomplete.
pub fn get_oauth_credentials() -> Result<&'static OAuthCredentials, String> {
    // Try to initialize if not already done
    if CREDENTIALS.get().is_none() {
        let creds = try_load_from_env()
            .or_else(try_load_from_config);

        match creds {
            Some(c) => {
                let _ = CREDENTIALS.set(c);
            }
            None => {
                return Err("OAuth credentials not configured. Please set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET environment variables or create ~/.antigravity/oauth.json config file".to_string());
            }
        }
    }

    // Verify credentials are actually loaded (not empty strings)
    if let Some(creds) = CREDENTIALS.get() {
        if creds.client_id.is_empty() {
            return Err("OAuth client_id is empty. Please set GOOGLE_OAUTH_CLIENT_ID environment variable or configure in ~/.antigravity/oauth.json".to_string());
        }
        if creds.client_secret.is_empty() {
            return Err("OAuth client_secret is empty. Please set GOOGLE_OAUTH_CLIENT_SECRET environment variable or configure in ~/.antigravity/oauth.json".to_string());
        }
        Ok(creds)
    } else {
        Err("OAuth credentials not configured. Please set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET environment variables or create ~/.antigravity/oauth.json config file".to_string())
    }
}

#[derive(Debug, Deserialize)]
struct OAuthConfig {
    client_id: Option<String>,
    client_secret: Option<String>,
}

fn load_oauth_config() -> Option<OAuthConfig> {
    let config_path = dirs::config_dir()
        .map(|p| p.join("antigravity").join("oauth.json"))?;

    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path).ok()?;
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub email: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
}

impl UserInfo {
    /// Get best display name
    pub fn get_display_name(&self) -> Option<String> {
        // Prefer name
        if let Some(name) = &self.name {
            if !name.trim().is_empty() {
                return Some(name.clone());
            }
        }

        // If name is empty, combine given_name and family_name
        match (&self.given_name, &self.family_name) {
            (Some(given), Some(family)) => Some(format!("{} {}", given, family)),
            (Some(given), None) => Some(given.clone()),
            (None, Some(family)) => Some(family.clone()),
            (None, None) => None,
        }
    }
}

/// Generate OAuth authorization URL
pub fn get_auth_url(redirect_uri: &str, state: &str) -> Result<String, String> {
    let creds = get_oauth_credentials()?;

    let scopes = vec![
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/cclog",
        "https://www.googleapis.com/auth/experimentsandconfigs"
    ].join(" ");

    let params = vec![
        ("client_id", creds.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", &scopes),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("include_granted_scopes", "true"),
        ("state", state),
    ];

    let url = url::Url::parse_with_params(AUTH_URL, &params).expect("Invalid Auth URL");
    Ok(url.to_string())
}

/// Exchange authorization code for token
pub async fn exchange_code(code: &str, redirect_uri: &str) -> Result<TokenResponse, String> {
    // Initialize credentials first and propagate error
    let creds = get_oauth_credentials()?;

    // [PHASE 2] 对于登录行为，尚未有 account_id，使用全局池阶梯逻辑
    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_standard_client(None, 60).await
    } else {
        crate::utils::http::get_long_standard_client()
    };

    let params = [
        ("client_id", creds.client_id.as_str()),
        ("client_secret", creds.client_secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
    ];

    tracing::debug!(
        "[OAuth] Sending exchange_code request with User-Agent: {}",
        crate::constants::NATIVE_OAUTH_USER_AGENT.as_str()
    );

    let response = client
        .post(TOKEN_URL)
        .header(rquest::header::USER_AGENT, crate::constants::NATIVE_OAUTH_USER_AGENT.as_str())
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                format!("Token exchange request failed: {}. 请检查你的网络代理设置，确保可以稳定连接 Google 服务。", e)
            } else {
                format!("Token exchange request failed: {}", e)
            }
        })?;

    if response.status().is_success() {
        let token_res = response.json::<TokenResponse>()
            .await
            .map_err(|e| format!("Token parsing failed: {}", e))?;

        // Add detailed logs
        crate::modules::logger::log_info(&format!(
            "Token exchange successful! access_token: {}..., refresh_token: {}",
            &token_res.access_token.chars().take(20).collect::<String>(),
            if token_res.refresh_token.is_some() { "✓" } else { "✗ Missing" }
        ));

        // Log warning if refresh_token is missing
        if token_res.refresh_token.is_none() {
            crate::modules::logger::log_warn(
                "Warning: Google did not return a refresh_token. Potential reasons:\n\
                 1. User has previously authorized this application\n\
                 2. Need to revoke access in Google Cloud Console and retry\n\
                 3. OAuth parameter configuration issue"
            );
        }

        Ok(token_res)
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Token exchange failed: {}", error_text))
    }
}

/// Refresh access_token using refresh_token
pub async fn refresh_access_token(refresh_token: &str, account_id: Option<&str>) -> Result<TokenResponse, String> {
    // Initialize credentials first and propagate error
    let creds = get_oauth_credentials()?;

    // [PHASE 2] 根据 account_id 使用对应的代理
    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_standard_client(account_id, 60).await
    } else {
        crate::utils::http::get_long_standard_client()
    };

    let params = [
        ("client_id", creds.client_id.as_str()),
        ("client_secret", creds.client_secret.as_str()),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ];

    // [FIX #1583] 提供更详细的日志，帮助诊断 Docker 环境下的代理问题
    if let Some(id) = account_id {
        crate::modules::logger::log_info(&format!("Refreshing Token for account: {}...", id));
    } else {
        crate::modules::logger::log_info("Refreshing Token for generic request (no account_id)...");
    }

    tracing::debug!(
        "[OAuth] Sending refresh_access_token request with User-Agent: {}",
        crate::constants::NATIVE_OAUTH_USER_AGENT.as_str()
    );

    let response = client
        .post(TOKEN_URL)
        .header(rquest::header::USER_AGENT, crate::constants::NATIVE_OAUTH_USER_AGENT.as_str())
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                format!("Refresh request failed: {}. 无法连接 Google 授权服务器，请检查代理设置。", e)
            } else {
                format!("Refresh request failed: {}", e)
            }
        })?;

    if response.status().is_success() {
        let token_data = response
            .json::<TokenResponse>()
            .await
            .map_err(|e| format!("Refresh data parsing failed: {}", e))?;

        crate::modules::logger::log_info(&format!("Token refreshed successfully! Expires in: {} seconds", token_data.expires_in));
        Ok(token_data)
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Refresh failed: {}", error_text))
    }
}

/// Get user info
pub async fn get_user_info(access_token: &str, account_id: Option<&str>) -> Result<UserInfo, String> {
    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(account_id, 15).await
    } else {
        crate::utils::http::get_client()
    };

    let response = client
        .get(USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("User info request failed: {}", e))?;

    if response.status().is_success() {
        response.json::<UserInfo>()
            .await
            .map_err(|e| format!("User info parsing failed: {}", e))
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to get user info: {}", error_text))
    }
}

/// Check and refresh Token if needed
/// Returns the latest access_token
pub async fn ensure_fresh_token(
    current_token: &crate::models::TokenData,
    account_id: Option<&str>,
) -> Result<crate::models::TokenData, String> {
    let now = chrono::Local::now().timestamp();

    // If no expiry or more than 5 minutes valid, return direct
    if current_token.expiry_timestamp > now + 300 {
        return Ok(current_token.clone());
    }

    // Need to refresh
    crate::modules::logger::log_info(&format!("Token expiring soon for account {:?}, refreshing...", account_id));
    let response = refresh_access_token(&current_token.refresh_token, account_id).await?;

    // Construct new TokenData
    Ok(crate::models::TokenData::new(
        response.access_token,
        current_token.refresh_token.clone(), // refresh_token may not be returned on refresh
        response.expires_in,
        current_token.email.clone(),
        current_token.project_id.clone(), // Keep original project_id
        None,  // session_id will be generated in token_manager
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    // Use a mutex to ensure tests don't run in parallel (affects global state)
    use crate::modules::oauth::{OAUTH_TEST_MUTEX, reset_oauth_credentials_for_tests};

    fn reset_credentials() {
        reset_oauth_credentials_for_tests();
    }

    fn create_temp_config_file(client_id: &str, client_secret: &str) -> PathBuf {
        let temp_dir = std::env::temp_dir().join(format!("oauth_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let config_path = temp_dir.join("oauth.json");

        let config = serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret
        });
        fs::write(&config_path, config.to_string()).unwrap();

        config_path
    }

    #[test]
    fn test_get_auth_url_returns_result() {
        let _guard = OAUTH_TEST_MUTEX.lock().unwrap();
        reset_credentials();

        // Without credentials, should return error
        env::remove_var("GOOGLE_OAUTH_CLIENT_ID");
        env::remove_var("GOOGLE_OAUTH_CLIENT_SECRET");

        let result = get_auth_url("http://localhost:8080/callback", "test-state");
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("client_id") || err_msg.contains("credentials not configured"));
    }

    #[test]
    fn test_get_auth_url_with_env_credentials() {
        let _guard = OAUTH_TEST_MUTEX.lock().unwrap();
        reset_credentials();

        env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-client-id-from-env");
        env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-client-secret-from-env");

        let result = get_auth_url("http://localhost:8080/callback", "test-state-123456");
        assert!(result.is_ok());

        let url = result.unwrap();
        assert!(url.contains("state=test-state-123456"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=test-client-id-from-env"));

        env::remove_var("GOOGLE_OAUTH_CLIENT_ID");
        env::remove_var("GOOGLE_OAUTH_CLIENT_SECRET");
    }

    #[test]
    fn test_env_takes_precedence_over_config() {
        let _guard = OAUTH_TEST_MUTEX.lock().unwrap();
        reset_credentials();

        // Set env vars
        env::set_var("GOOGLE_OAUTH_CLIENT_ID", "env-client-id");
        env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "env-client-secret");

        let result = get_oauth_credentials();
        assert!(result.is_ok());

        let creds = result.unwrap();
        assert_eq!(creds.client_id, "env-client-id");
        assert_eq!(creds.client_secret, "env-client-secret");

        env::remove_var("GOOGLE_OAUTH_CLIENT_ID");
        env::remove_var("GOOGLE_OAUTH_CLIENT_SECRET");
    }

    #[test]
    fn test_empty_client_id_returns_error() {
        let _guard = OAUTH_TEST_MUTEX.lock().unwrap();
        reset_credentials();

        // Manually set credentials with empty client_id
        unsafe {
            let empty_creds = OAuthCredentials {
                client_id: "".to_string(),
                client_secret: "valid-secret".to_string(),
            };
            let _ = CREDENTIALS.set(empty_creds);
        }

        let result = get_oauth_credentials();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("client_id is empty"));
    }

    #[test]
    fn test_empty_client_secret_returns_error() {
        let _guard = OAUTH_TEST_MUTEX.lock().unwrap();
        reset_credentials();

        // Manually set credentials with empty client_secret
        unsafe {
            let empty_creds = OAuthCredentials {
                client_id: "valid-id".to_string(),
                client_secret: "".to_string(),
            };
            let _ = CREDENTIALS.set(empty_creds);
        }

        let result = get_oauth_credentials();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("client_secret is empty"));
    }

    #[test]
    fn test_missing_credentials_error_message() {
        let _guard = OAUTH_TEST_MUTEX.lock().unwrap();
        reset_credentials();

        env::remove_var("GOOGLE_OAUTH_CLIENT_ID");
        env::remove_var("GOOGLE_OAUTH_CLIENT_SECRET");

        let result = get_oauth_credentials();
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.contains("OAuth credentials not configured"));
        assert!(err.contains("GOOGLE_OAUTH_CLIENT_ID"));
        assert!(err.contains("GOOGLE_OAUTH_CLIENT_SECRET"));
    }

    #[test]
    fn test_oauth_credentials_struct_clone() {
        let creds = OAuthCredentials {
            client_id: "test-id".to_string(),
            client_secret: "test-secret".to_string(),
        };

        let cloned = creds.clone();
        assert_eq!(creds.client_id, cloned.client_id);
        assert_eq!(creds.client_secret, cloned.client_secret);
    }

    #[test]
    fn test_try_load_from_env_partial() {
        let _guard = OAUTH_TEST_MUTEX.lock().unwrap();
        reset_credentials();

        // Only set client_id, not client_secret
        env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-id");
        env::remove_var("GOOGLE_OAUTH_CLIENT_SECRET");

        let result = try_load_from_env();
        assert!(result.is_none());

        env::remove_var("GOOGLE_OAUTH_CLIENT_ID");
    }

    #[test]
    fn test_try_load_from_env_complete() {
        let _guard = OAUTH_TEST_MUTEX.lock().unwrap();
        reset_credentials();

        env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-id");
        env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-secret");

        let result = try_load_from_env();
        assert!(result.is_some());

        let creds = result.unwrap();
        assert_eq!(creds.client_id, "test-id");
        assert_eq!(creds.client_secret, "test-secret");

        env::remove_var("GOOGLE_OAUTH_CLIENT_ID");
        env::remove_var("GOOGLE_OAUTH_CLIENT_SECRET");
    }
}
