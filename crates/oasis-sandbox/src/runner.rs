use anyhow::{Context, Result};
use crate::chamber::CodeChamber;

#[derive(Debug)]
pub struct SimulationResult {
    pub success: bool,
    pub output: String,
    pub fuel_consumed: u64,
}

pub struct Runner {
    chamber: CodeChamber,
}

impl Runner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            chamber: CodeChamber::new()?,
        })
    }

    pub fn run_simulation(&self, wasm_binary: &[u8]) -> Result<SimulationResult> {
        let (linker, mut store, module) = self.chamber.prepare_vacuum(wasm_binary)?;

        let instance = linker.instantiate(&mut store, &module).context("Failed to instantiate module")?;
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start").context("Failed to get _start")?;

        // Execute
        let result = start.call(&mut store, ());
        
        let remaining_fuel = store.get_fuel().unwrap_or(0);
        let fuel_consumed = 1_000_000 - remaining_fuel;

        match result {
            Ok(_) => Ok(SimulationResult {
                success: true,
                output: "Simulation completed successfully".to_string(), // In a real implementation, we'd capture stdout
                fuel_consumed,
            }),
            Err(e) => {
                // Check if it was a fuel exhaustion
                if e.to_string().contains("fuel") {
                    Ok(SimulationResult {
                        success: false,
                        output: "Simulation terminated: Fuel exhausted (Infinite loop detected)".to_string(),
                        fuel_consumed,
                    })
                } else {
                    Ok(SimulationResult {
                        success: false,
                        output: format!("Simulation failed: {}", e),
                        fuel_consumed,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world_wat() {
        // WAT test case (No rustc required)
        let wat = r#"
        (module
            (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
            (memory 1)
            (export "memory" (memory 0))
            (func (export "_start")
                (call $proc_exit (i32.const 0))
            )
        )
        "#;
        
        // Convert WAT to WASM using the wat crate
        let binary = wat::parse_str(wat).expect("Failed to convert WAT");
        
        let runner = Runner::new().expect("Failed to create runner");
        let result = runner.run_simulation(&binary).expect("Failed to run simulation");
        
        assert!(result.success, "Simulation should succeed");
    }

    #[test]
    fn test_infinite_loop_fuel() {
        // WAT with infinite loop
        let wat = r#"
        (module
            (func (export "_start")
                (loop
                    br 0
                )
            )
        )
        "#;
        
        // Convert WAT to WASM using the wat crate
        let binary = wat::parse_str(wat).expect("Failed to convert WAT");

        let runner = Runner::new().expect("Failed to create runner");
        let result = runner.run_simulation(&binary).expect("Failed to run simulation");
        
        assert!(!result.success, "Simulation should fail due to fuel");
        assert!(result.output.contains("Fuel exhausted"), "Output should mention fuel exhaustion");
    }
}
