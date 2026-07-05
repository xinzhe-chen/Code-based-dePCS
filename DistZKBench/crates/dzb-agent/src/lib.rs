use dzb_platform::{PlatformBackend, PlatformResult, ResolvedConfig, RunId};

pub struct Agent<B> {
    backend: B,
}

impl<B: PlatformBackend> Agent<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn prepare(&self, config: &ResolvedConfig) -> PlatformResult<Vec<String>> {
        self.backend.prepare_host(config).map(|plan| plan.notes)
    }

    pub fn cleanup(&self, run_id: &RunId) -> PlatformResult<()> {
        self.backend.cleanup(run_id)
    }
}
