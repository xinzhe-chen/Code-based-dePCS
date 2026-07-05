pub trait Protocol {
    type PublicInput;
    type LocalInput;
    type Setup;
    type Proof;

    fn name(&self) -> &'static str;

    fn setup(&self) -> Result<Self::Setup, String>;

    fn generate_or_load_input(
        &self,
        rank: usize,
    ) -> Result<(Self::PublicInput, Self::LocalInput), String>;

    fn prove(
        &self,
        setup: &Self::Setup,
        public_input: &Self::PublicInput,
        local_input: Self::LocalInput,
    ) -> Result<Option<Self::Proof>, String>;

    fn verify(
        &self,
        setup: &Self::Setup,
        public_input: &Self::PublicInput,
        proof: &Self::Proof,
    ) -> Result<bool, String>;

    fn serialize_proof(&self, proof: &Self::Proof) -> Result<Vec<u8>, String>;

    fn deserialize_proof(&self, bytes: &[u8]) -> Result<Self::Proof, String>;
}
