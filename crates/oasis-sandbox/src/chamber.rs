use anyhow::{Context, Result};
use cap_std::ambient_authority;
use wasmtime_wasi::sync::WasiCtxBuilder;
use wasmtime::{Config, Engine, Linker, Module, Store};

pub struct CodeChamber {
    engine: Engine,
}

impl CodeChamber {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true); // Enable fuel consumption (The "Halting Problem" fix)
        
        let engine = Engine::new(&config).context("Failed to create Wasmtime engine")?;
        Ok(Self { engine })
    }

    pub fn prepare_vacuum(&self, wasm_binary: &[u8]) -> Result<(Linker<wasmtime_wasi::WasiCtx>, Store<wasmtime_wasi::WasiCtx>, Module)> {
        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s).context("Failed to add WASI to linker")?;

        // Create a temporary directory for the sandbox (The "Vacuum")
        let temp_dir = tempfile::tempdir().context("Failed to create temp dir")?;
        let dir = cap_std::fs::Dir::open_ambient_dir(temp_dir.path(), ambient_authority())
            .context("Failed to open temp dir")?;

        // Configure WASI:
        // - Stdin: Empty
        // - Stdout/Stderr: Inherit (or pipe, handled in runner)
        // - Args: []
        // - Env: []
        // - Preopened dir: /workspace mapped to temp dir
        let wasi = WasiCtxBuilder::new()
            .inherit_stdio() // We will capture this in the runner if needed, or let it flow for now
            .preopened_dir(dir, "/workspace")?
            .build();

        let mut store = Store::new(&self.engine, wasi);
        
        // Add fuel: 1,000,000 units (The "Limit")
        store.set_fuel(1_000_000).context("Failed to set fuel")?;

        let module = Module::from_binary(&self.engine, wasm_binary).context("Failed to compile WASM")?;

        Ok((linker, store, module))
    }
}
