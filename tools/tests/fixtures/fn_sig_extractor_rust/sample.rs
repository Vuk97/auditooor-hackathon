pub async fn process_message<'a, T: AccountStore>(
    ctx: &mut Context<'a>,
    msg: MsgExecute,
    signer: AccountId,
) -> Result<(), ProgramError> {
    verify_signature(&msg)?;
    execute(ctx, msg, signer)
}

impl Processor {
    pub fn apply(&mut self, ix: Instruction, signer: Pubkey) -> Result<u64, ProgramError> {
        self.inner(ix, signer)
    }

    fn helper(input: u64) {
        let _ = input;
    }
}

pub(crate) fn settle<T>(
    amount: u64,
    state: &mut State<T>,
) -> Result<(u64, u64), ProgramError>
where
    T: Codec + Clone,
{
    Ok((amount, amount))
}
