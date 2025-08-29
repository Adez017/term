// src-tauri/src/sudo.rs
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::io::Write;
use tauri::State;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AuthToken {
    timestamp: Instant,
    user_id: u32,
}

#[derive(Default)]
pub struct SudoCache {
    pub tokens: Arc<Mutex<HashMap<u32, AuthToken>>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SudoRequest {
    pub command: String,
    pub args: Vec<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SudoResponse {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub cached: bool,
    pub needs_password: bool,
}

impl SudoCache {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_authenticated(&self, user_id: u32, timeout_minutes: u64) -> bool {
        if let Ok(tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get(&user_id) {
                return token.timestamp.elapsed() < Duration::from_secs(timeout_minutes * 60);
            }
        }
        false
    }

    pub fn authenticate(&self, user_id: u32) {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.insert(user_id, AuthToken {
                timestamp: Instant::now(),
                user_id,
            });
        }
    }

    pub fn clear_expired(&self, timeout_minutes: u64) {
        if let Ok(mut tokens) = self.tokens.lock() {
            let timeout = Duration::from_secs(timeout_minutes * 60);
            tokens.retain(|_, token| token.timestamp.elapsed() < timeout);
        }
    }

    pub fn clear_all(&self) {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.clear();
        }
    }
}

fn get_current_user_id() -> Result<u32, Box<dyn std::error::Error>> {
    unsafe {
        Ok(libc::getuid())
    }
}

fn verify_password(password: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let mut child = Command::new("sudo")
        .args(&["-S", "-v"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        writeln!(stdin, "{}", password)?;
    }

    let output = child.wait_with_output()?;
    Ok(output.status.success())
}

async fn execute_sudo_command(
    command: &str,
    args: &[String],
    use_cached: bool,
) -> Result<SudoResponse, String> {
    let mut cmd_args = Vec::new();
    
    if use_cached {
        cmd_args.push("-n".to_string()); // Non-interactive mode for cached auth
    }
    
    cmd_args.push(command.to_string());
    cmd_args.extend_from_slice(args);

    let output = Command::new("sudo")
        .args(&cmd_args)
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(SudoResponse {
            success: true,
            output: stdout,
            error: None,
            cached: use_cached,
            needs_password: false,
        })
    } else {
        // Check if it failed because of missing authentication
        if use_cached && stderr.contains("no password entry") {
            Ok(SudoResponse {
                success: false,
                output: String::new(),
                error: Some("Authentication required".to_string()),
                cached: false,
                needs_password: true,
            })
        } else {
            Ok(SudoResponse {
                success: false,
                output: stdout,
                error: Some(stderr),
                cached: use_cached,
                needs_password: false,
            })
        }
    }
}

#[tauri::command]
pub async fn fast_sudo(
    request: SudoRequest,
    cache: State<'_, SudoCache>,
) -> Result<SudoResponse, String> {
    let user_id = get_current_user_id().map_err(|e| e.to_string())?;
    let timeout_minutes = 15; // 15 minute timeout

    // Clear expired tokens
    cache.clear_expired(timeout_minutes);

    let mut needs_auth = true;
    let mut use_cached = false;

    // Check if already authenticated
    if cache.is_authenticated(user_id, timeout_minutes) {
        use_cached = true;
        needs_auth = false;
    }

    // If we have cached auth, try to use it first
    if use_cached {
        match execute_sudo_command(&request.command, &request.args, true).await {
            Ok(response) => {
                if response.success {
                    return Ok(response);
                } else if response.needs_password {
                    // Cache expired, need to re-authenticate
                    needs_auth = true;
                    use_cached = false;
                } else {
                    return Ok(response);
                }
            }
            Err(e) => return Err(e),
        }
    }

    // If not cached and no password provided, request password
    if needs_auth && request.password.is_none() {
        return Ok(SudoResponse {
            success: false,
            output: String::new(),
            error: Some("Password required".to_string()),
            cached: false,
            needs_password: true,
        });
    }

    // Verify password if needed
    if needs_auth {
        if let Some(ref password) = request.password {
            match verify_password(password) {
                Ok(true) => {
                    cache.authenticate(user_id);
                    use_cached = false; // First time auth, not cached
                }
                Ok(false) => {
                    return Ok(SudoResponse {
                        success: false,
                        output: String::new(),
                        error: Some("Invalid password".to_string()),
                        cached: false,
                        needs_password: true,
                    });
                }
                Err(e) => {
                    return Ok(SudoResponse {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Authentication error: {}", e)),
                        cached: false,
                        needs_password: false,
                    });
                }
            }
        }
    }

    // Execute the command
    execute_sudo_command(&request.command, &request.args, false).await
}

#[tauri::command] 
pub async fn clear_sudo_cache(cache: State<'_, SudoCache>) -> Result<(), String> {
    cache.clear_all();
    
    // Also clear system sudo cache
    let _ = Command::new("sudo")
        .args(&["-k"])
        .output();
        
    Ok(())
}

#[tauri::command]
pub async fn check_sudo_privileges() -> Result<bool, String> {
    let output = Command::new("sudo")
        .args(&["-n", "true"])
        .output()
        .map_err(|e| format!("Failed to check privileges: {}", e))?;

    Ok(output.status.success())
}

#[tauri::command]
pub async fn direct_privilege_escalation(
    command: String,
    args: Vec<String>,
) -> Result<SudoResponse, String> {
    // Direct privilege escalation without sudo
    
    // For now, fall back to regular sudo
    let output = Command::new("sudo")
        .arg(&command)
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(SudoResponse {
        success: output.status.success(),
        output: stdout,
        error: if stderr.is_empty() { None } else { Some(stderr) },
        cached: false,
        needs_password: false,
    })
}

// Utility function to parse sudo commands
pub fn parse_sudo_command(input: &str) -> Option<(String, Vec<String>)> {
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    
    if parts.is_empty() || parts[0] != "sudo" {
        return None;
    }
    
    if parts.len() < 2 {
        return None;
    }
    
    let command = parts[1].to_string();
    let args = parts[2..].iter().map(|s| s.to_string()).collect();
    
    Some((command, args))
}